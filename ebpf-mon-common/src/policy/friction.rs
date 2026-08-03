//! Friction report: a generated, per-rule × per-backend account of exactly what
//! each enforcement target can and cannot express from the neutral IR.
//!
//! This is the machine-checkable version of the abstract's promise that "we
//! document the friction points." Nothing here fabricates agreement: every rule
//! that a backend widens (`Approximated`) or cannot represent (`Dropped`) is
//! listed with the concrete reason, sourced from the same lowering logic the real
//! backends use (`backends::apparmor::lower_to_apparmor` for AppArmor; a mirror
//! of `ebpf-mon/src/enforcement.rs::PolicyLoader` for BPF-LSM).

use crate::fs::PathPattern;
use crate::policy::{
    Action, BehaviorRule, BinaryRef, FilePattern, Object, RuleId, Verdict, PREFIX_MAX_LEN,
};

/// How faithfully a single rule survives lowering to one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Fidelity {
    /// Lowered exactly; no semantics lost.
    Expressed,
    /// Lowered, but widened / coarsened / ABI-gated (enforces something weaker
    /// than the IR states).
    Approximated,
    /// Cannot be represented; the rule is silently lost at this backend.
    Dropped,
}

impl Fidelity {
    fn marker(self) -> &'static str {
        match self {
            Fidelity::Expressed => "OK    ",
            Fidelity::Approximated => "APPROX",
            Fidelity::Dropped => "DROP  ",
        }
    }
}

/// One rule's lowering outcome at one backend.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub rule_summary: String,
    pub fidelity: Fidelity,
    /// Empty when `Expressed`; otherwise the concrete reason for the loss.
    pub detail: String,
}

/// Every rule's outcome at a single backend, plus convenience counts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackendFriction {
    pub backend: String,
    pub findings: Vec<Finding>,
}

impl BackendFriction {
    pub fn count(&self, f: Fidelity) -> usize {
        self.findings.iter().filter(|x| x.fidelity == f).count()
    }
}

/// The full report across all backends for one compiled IR.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrictionReport {
    pub total_rules: usize,
    pub backends: Vec<BackendFriction>,
}

impl FrictionReport {
    /// Compute the report for a compiled (post-pipeline, cross-linked) IR.
    pub fn compute(rules: &[BehaviorRule]) -> Self {
        FrictionReport {
            total_rules: rules.len(),
            backends: vec![bpf_lsm_friction(rules), apparmor_friction(rules)],
        }
    }

    /// Render a human-readable report. Lists counts per backend and every
    /// non-`Expressed` finding with its reason.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("=== FRICTION REPORT (IR -> each backend) ===\n");
        out.push_str(&format!("total IR rules: {}\n", self.total_rules));

        for b in &self.backends {
            out.push_str(&format!(
                "\n[{}]  expressed {} / approximated {} / dropped {}\n",
                b.backend,
                b.count(Fidelity::Expressed),
                b.count(Fidelity::Approximated),
                b.count(Fidelity::Dropped),
            ));
            let mut lossy: Vec<&Finding> = b
                .findings
                .iter()
                .filter(|f| f.fidelity != Fidelity::Expressed)
                .collect();
            lossy.sort_by_key(|f| (f.fidelity == Fidelity::Approximated, f.rule_id));
            if lossy.is_empty() {
                out.push_str("  (everything expressed exactly)\n");
            }
            for f in lossy {
                out.push_str(&format!(
                    "  [{}] rule {:<4} {}\n           {}\n",
                    f.fidelity.marker(),
                    f.rule_id,
                    f.rule_summary,
                    f.detail
                ));
            }
        }
        out
    }
}

/// AppArmor friction, derived from the real backend's per-rule warnings so it
/// can never drift from what `lower_to_apparmor` actually emits.
pub fn apparmor_friction(rules: &[BehaviorRule]) -> BackendFriction {
    use crate::policy::backends::apparmor::{lower_to_apparmor, LossKind};
    let (_text, warnings) = lower_to_apparmor(rules, "friction");
    let findings = rules
        .iter()
        .map(|r| match warnings.iter().find(|w| w.rule_id == r.id) {
            None => Finding {
                rule_id: r.id,
                rule_summary: rule_summary(r),
                fidelity: Fidelity::Expressed,
                detail: String::new(),
            },
            Some(w) => Finding {
                rule_id: r.id,
                rule_summary: rule_summary(r),
                fidelity: match w.kind {
                    LossKind::Dropped => Fidelity::Dropped,
                    LossKind::Approximated | LossKind::AbiGated => Fidelity::Approximated,
                },
                detail: w.message.clone(),
            },
        })
        .collect();
    BackendFriction { backend: "AppArmor".to_string(), findings }
}

/// BPF-LSM friction, mirroring `ebpf-mon/src/enforcement.rs::PolicyLoader` and
/// the kernel hooks it feeds. Kept in lockstep with the loader's match arms.
pub fn bpf_lsm_friction(rules: &[BehaviorRule]) -> BackendFriction {
    let findings = rules
        .iter()
        .map(|r| {
            let (fidelity, detail) = bpf_fidelity(r);
            Finding {
                rule_id: r.id,
                rule_summary: rule_summary(r),
                fidelity,
                detail,
            }
        })
        .collect();
    BackendFriction { backend: "BPF-LSM".to_string(), findings }
}

fn bpf_fidelity(r: &BehaviorRule) -> (Fidelity, String) {
    match (&r.object, r.action) {
        (Object::File(f), Action::FileOpen | Action::FileRead | Action::FileWrite) => {
            match &f.pattern {
                FilePattern::Classified(PathPattern::Regular) => (
                    Fidelity::Dropped,
                    "Classified(Regular) has no concrete key; not enforceable".to_string(),
                ),
                FilePattern::Prefix(p) if p.len() > PREFIX_MAX_LEN => (
                    Fidelity::Dropped,
                    format!("prefix '{}' exceeds PREFIX_MAX_LEN ({}); dropped", p, PREFIX_MAX_LEN),
                ),
                // Exact paths now carry a real read/write mask: security_file_open
                // reads f_flags & O_ACCMODE and the FILE_PATH_POLICY value encodes
                // ACCESS_READ / ACCESS_WRITE, so the mode is enforced (not open-granularity).
                FilePattern::ExactPath(_) => (Fidelity::Expressed, String::new()),
                _ if matches!(r.action, Action::FileRead | Action::FileWrite) => (
                    Fidelity::Approximated,
                    "pattern/prefix tiers of security_file_open are open-granularity: read/write \
                     not distinguished there, so the open (hence both modes) is permitted"
                        .to_string(),
                ),
                _ => (Fidelity::Expressed, String::new()),
            }
        }
        (Object::Process(p), Action::ProcExec) => match &p.binary {
            BinaryRef::Path(_) => (Fidelity::Expressed, String::new()),
            BinaryRef::Comm(_) => (
                Fidelity::Dropped,
                "comm-based exec has no path hash; dropped".to_string(),
            ),
        },
        (Object::Network(n), Action::NetConnect) => {
            if n.dst_ip.is_none() {
                (
                    Fidelity::Dropped,
                    "ip-less network rule dropped by loader (key requires a concrete ip)".to_string(),
                )
            } else {
                (
                    Fidelity::Approximated,
                    "socket_connect key omits protocol; any protocol to this ip:port matches"
                        .to_string(),
                )
            }
        }
        (Object::Network(_), Action::NetBind) => (
            Fidelity::Dropped,
            "no bind-enforcement hook; dropped".to_string(),
        ),
        _ => (
            Fidelity::Dropped,
            format!("unsupported for BPF-LSM: {:?}/{:?}", r.object, r.action),
        ),
    }
}

/// Compact, human-readable one-liner for a rule.
pub fn rule_summary(r: &BehaviorRule) -> String {
    let verdict = match r.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY ",
        Verdict::Audit => "AUDIT",
    };
    let obj = match &r.object {
        Object::File(f) => match &f.pattern {
            FilePattern::ExactPath(p) => format!("file {}", p),
            FilePattern::Prefix(p) => format!("file {}**", p),
            FilePattern::Classified(c) => format!("file {}", c.as_str()),
        },
        Object::Process(p) => match &p.binary {
            BinaryRef::Path(b) => format!("exec {}", b),
            BinaryRef::Comm(_) => "exec comm=<..>".to_string(),
        },
        Object::Network(n) => {
            let ip = n
                .dst_ip
                .map(|v| {
                    let [a, b, c, d] = v.to_le_bytes();
                    format!("{a}.{b}.{c}.{d}")
                })
                .unwrap_or_else(|| "*".to_string());
            let port = n.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "*".to_string());
            let proto = match n.protocol {
                Some(6) => "tcp".to_string(),
                Some(17) => "udp".to_string(),
                Some(p) => format!("proto{p}"),
                None => "*".to_string(),
            };
            format!("net {ip}:{port}/{proto}")
        }
    };
    format!("{verdict} {:?} {obj}", r.action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        translate_all_events_json, run_pipeline, link_cross_category,
    };

    fn compile(json: &str) -> Vec<BehaviorRule> {
        let (opt, _c) = run_pipeline(translate_all_events_json(json).unwrap());
        link_cross_category(opt)
    }

    #[test]
    fn bpf_exact_path_read_write_is_expressed() {
        // An exact-path read/write is now enforced with a real access mask
        // (security_file_open reads f_flags & O_ACCMODE), so it is EXPRESSED —
        // no longer flagged as open-granularity.
        let ir = compile(r#"{"fs":[{"path":"/app/x","r_w":"read","process_ctx":{}}]}"#);
        let bpf = bpf_lsm_friction(&ir);
        assert!(
            bpf.count(Fidelity::Expressed) >= 1,
            "exact-path read/write is r/w-aware and should be EXPRESSED"
        );
        // And it must NOT be counted as an open-granularity approximation.
        let file_approx = bpf
            .findings
            .iter()
            .any(|f| f.fidelity == Fidelity::Approximated && f.detail.contains("open-granularity"));
        assert!(!file_approx, "exact-path file rule must not be open-granularity anymore");
    }

    #[test]
    fn apparmor_expresses_read_write_exactly() {
        let ir = compile(r#"{"fs":[{"path":"/app/x","r_w":"read","process_ctx":{}}]}"#);
        let aa = apparmor_friction(&ir);
        // AppArmor distinguishes r/w, so an exact read path is expressed exactly.
        assert!(aa.count(Fidelity::Expressed) >= 1);
        assert_eq!(aa.count(Fidelity::Dropped), 0);
    }

    #[test]
    fn ip_wildcard_dropped_by_bpf_not_apparmor() {
        use crate::policy::{NetworkObject, RuleMetadata, SourceModule, Subject};
        // An ip-less ("any peer") network allow: BPF-LSM drops it, AppArmor keeps it.
        let rule = BehaviorRule {
            id: 7,
            subject: Subject { container: None, binary: None, uid: None },
            object: Object::Network(NetworkObject {
                dst_ip: None,
                dst_port: Some(443),
                protocol: Some(6),
                direction: Some(1),
            }),
            action: Action::NetConnect,
            verdict: Verdict::Allow,
            metadata: RuleMetadata {
                source_module: SourceModule::Net,
                observation_count: 1,
                confidence: 1.0,
                first_seen: 0,
                last_seen: 0,
            },
        };
        let ir = vec![rule];
        assert_eq!(bpf_lsm_friction(&ir).count(Fidelity::Dropped), 1);
        assert_eq!(apparmor_friction(&ir).count(Fidelity::Dropped), 0);
    }

    #[test]
    fn report_renders_counts() {
        let ir = compile(
            r#"{"fs":[{"path":"/app/x","r_w":"read","process_ctx":{}}],
                "process":[{"exec_path":"/bin/sh","ps_type":"execve","cgroup_id":1,"process_ctx":{}}]}"#,
        );
        let report = FrictionReport::compute(&ir);
        let text = report.render();
        assert!(text.contains("FRICTION REPORT"));
        assert!(text.contains("BPF-LSM"));
        assert!(text.contains("AppArmor"));
    }
}
