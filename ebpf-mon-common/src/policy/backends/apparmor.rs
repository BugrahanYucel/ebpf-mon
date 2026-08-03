//! AppArmor backend: lower the normalized IR into an AppArmor profile.
//!
//! This is a pure function (no kernel/fs access) so it is trivially testable.
//! It demonstrates the compiler's "expressibility envelope" idea: where the IR is
//! richer than the target can *portably* express, we emit the most precise legal
//! form and record a `LoweringWarning` rather than silently dropping information.
//!
//! Format decisions are grounded in `apparmor.d(5)`; see
//! `docs/apparmor-format-reference.md`. Notably, modern AppArmor *can* mediate on
//! IP/port via `peer=(ip=..,port=..)` (ABI-gated: on older ABIs the parser silently
//! downgrades the rule to the coarse `network inet <type>` form), so destination
//! rules are emitted precisely with an ABI-dependency warning, not widened.

use crate::fs::PathPattern;
use crate::policy::{Action, BehaviorRule, BinaryRef, FilePattern, Object, RuleId, Verdict};

/// The kind of precision loss a lowering incurs (drives the friction report).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossKind {
    /// Emitted, but semantically widened or coarsened.
    Approximated,
    /// Emitted precisely, but only enforced on a capable ABI; older parsers
    /// silently downgrade it.
    AbiGated,
    /// Cannot be expressed at all; the rule is dropped.
    Dropped,
}

/// A precision loss incurred while lowering a rule to AppArmor.
#[derive(Debug, Clone)]
pub struct LoweringWarning {
    pub rule_id: RuleId,
    pub kind: LossKind,
    pub message: String,
}

/// Lower a set of behavior rules to an AppArmor profile string.
/// Returns the profile text and any precision-loss warnings.
pub fn lower_to_apparmor(rules: &[BehaviorRule], profile_name: &str) -> (String, Vec<LoweringWarning>) {
    let mut warnings = Vec::new();
    let mut exec_lines: Vec<String> = Vec::new();
    let mut file_lines: Vec<String> = Vec::new();
    let mut net_lines: Vec<String> = Vec::new();

    for rule in rules {
        let deny = if rule.verdict == Verdict::Deny { "deny " } else { "" };

        match (&rule.object, &rule.action) {
            (Object::File(f), Action::FileOpen | Action::FileRead | Action::FileWrite) => {
                let perms = if rule.action == Action::FileWrite { "w" } else { "r" };
                match file_glob(&f.pattern) {
                    GlobMap::Exact(glob) => {
                        file_lines.push(format!("  {}{} {},", deny, quote_if_needed(&glob), perms));
                    }
                    GlobMap::Approx(glob) => {
                        warnings.push(LoweringWarning {
                            rule_id: rule.id,
                            kind: LossKind::Approximated,
                            message: format!("approximate AppArmor glob for {:?}", f.pattern),
                        });
                        file_lines.push(format!("  {}{} {},", deny, quote_if_needed(&glob), perms));
                    }
                    GlobMap::Unmappable => {
                        warnings.push(LoweringWarning {
                            rule_id: rule.id,
                            kind: LossKind::Dropped,
                            message: format!(
                                "file pattern {:?} is not expressible as an AppArmor path glob; dropped",
                                f.pattern
                            ),
                        });
                    }
                }
            }

            (Object::Process(p), Action::ProcExec) => {
                if let BinaryRef::Path(path) = &p.binary {
                    exec_lines.push(format!("  {}{} ix,", deny, quote_if_needed(path)));
                } else {
                    warnings.push(LoweringWarning {
                        rule_id: rule.id,
                        kind: LossKind::Dropped,
                        message: "exec rule has no path (comm-based); cannot emit AppArmor".into(),
                    });
                }
            }

            (Object::Network(n), Action::NetConnect | Action::NetBind) => {
                let stype = match n.protocol {
                    Some(17) => "dgram",
                    _ => "stream",
                };
                // Build the ip/port conditional. For a connect the endpoint is the
                // remote peer -> `peer=(...)`; for a bind it is the local address.
                let cond = net_conditional(n, rule.action == Action::NetConnect);
                if cond.is_empty() {
                    net_lines.push(format!("  {}network inet {},", deny, stype));
                } else {
                    net_lines.push(format!("  {}network inet {} {},", deny, stype, cond));
                    warnings.push(LoweringWarning {
                        rule_id: rule.id,
                        kind: LossKind::AbiGated,
                        message: format!(
                            "emitted fine-grained '{}'; requires an AppArmor ABI with inet ip/port \
                             mediation, otherwise the parser downgrades it to 'network inet {}'",
                            cond, stype
                        ),
                    });
                }
            }

            _ => warnings.push(LoweringWarning {
                rule_id: rule.id,
                kind: LossKind::Dropped,
                message: format!(
                    "unsupported object/action for AppArmor: {:?} / {:?}",
                    rule.object, rule.action
                ),
            }),
        }
    }

    dedup_sort(&mut exec_lines);
    dedup_sort(&mut file_lines);
    dedup_sort(&mut net_lines);

    let mut out = String::new();
    out.push_str(&format!(
        "profile {} flags=(attach_disconnected,mediate_deleted) {{\n",
        profile_name
    ));
    push_section(&mut out, "# executables", &exec_lines);
    push_section(&mut out, "# files", &file_lines);
    push_section(&mut out, "# network", &net_lines);
    out.push_str("}\n");

    (out, warnings)
}

/// Result of mapping an IR file pattern to an AppArmor glob.
enum GlobMap {
    /// Exact AARE glob, no precision lost.
    Exact(String),
    /// A widened AARE glob (a `<other>`/`<global>` placeholder became `*`/`**`).
    Approx(String),
    /// Not expressible as an AppArmor path glob (e.g. the `<regular>` placeholder).
    Unmappable,
}

/// Map an IR file pattern to an AppArmor glob.
///
/// The `PathPattern::as_str()` values are already valid AARE globs
/// (`/proc/*/status`, `/tmp/**`, ...); only the internal placeholders
/// `<regular>`, `<other>`, `<global>` need translation or are unmappable.
fn file_glob(pattern: &FilePattern) -> GlobMap {
    match pattern {
        FilePattern::ExactPath(path) => GlobMap::Exact(path.clone()),
        // Prefix is canonicalized to end with '/', so "/app/" -> "/app/**".
        FilePattern::Prefix(prefix) => GlobMap::Exact(format!("{}**", prefix)),
        FilePattern::Classified(PathPattern::Regular) => GlobMap::Unmappable,
        FilePattern::Classified(pat) => {
            let s = pat.as_str();
            if s.contains('<') {
                let approx = match pat {
                    // A file directly under some /proc/<pid>/ that we don't classify.
                    PathPattern::ProcPidOther => "/proc/*/**".to_string(),
                    PathPattern::ProcGlobal => "/proc/*".to_string(),
                    _ => s.replace("<other>", "*").replace("<global>", "*"),
                };
                GlobMap::Approx(approx)
            } else {
                GlobMap::Exact(s.to_string())
            }
        }
    }
}

/// Build the AppArmor ip/port conditional for a network object, or "" if none.
/// `is_peer` selects the remote (`peer=(...)`) vs local address form.
fn net_conditional(n: &crate::policy::NetworkObject, is_peer: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ip) = n.dst_ip {
        parts.push(format!("ip={}", ipv4_dotted(ip)));
    }
    if let Some(port) = n.dst_port {
        parts.push(format!("port={}", port));
    }
    if parts.is_empty() {
        return String::new();
    }
    let inner = parts.join(" ");
    if is_peer {
        format!("peer=({})", inner)
    } else {
        inner
    }
}

/// Render the IR's `dst_ip` u32 as a dotted quad. The IR stores IPv4 in the
/// enforcement convention (`from_le_bytes(octets)`; see the AppArmor frontend's
/// `parse_ipv4`), so the octets come straight back out via `to_le_bytes`.
fn ipv4_dotted(ip: u32) -> String {
    let [a, b, c, d] = ip.to_le_bytes();
    format!("{}.{}.{}.{}", a, b, c, d)
}

fn quote_if_needed(s: &str) -> String {
    if s.chars().any(char::is_whitespace) {
        format!("\"{}\"", s)
    } else {
        s.to_string()
    }
}

fn dedup_sort(v: &mut Vec<String>) {
    v.sort();
    v.dedup();
}

fn push_section(out: &mut String, header: &str, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    out.push_str("  ");
    out.push_str(header);
    out.push('\n');
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::lower_to_apparmor;
    use crate::fs::PathPattern;
    use crate::policy::{
        Action, BehaviorRule, BinaryRef, FileObject, FilePattern, NetworkObject, Object,
        ProcessObject, RuleId, RuleMetadata, SourceModule, Subject, Verdict,
    };

    fn subj() -> Subject {
        Subject { container: None, binary: None, uid: None }
    }
    fn meta() -> RuleMetadata {
        RuleMetadata {
            source_module: SourceModule::Fs,
            observation_count: 1,
            confidence: 1.0,
            first_seen: 0,
            last_seen: 0,
        }
    }

    fn file_rule(id: RuleId, pattern: FilePattern, action: Action) -> BehaviorRule {
        BehaviorRule {
            id,
            subject: subj(),
            object: Object::File(FileObject { pattern, is_sensitive: false }),
            action,
            verdict: Verdict::Allow,
            metadata: meta(),
        }
    }

    #[test]
    fn emits_exact_pattern_and_prefix() {
        let rules = vec![
            file_rule(1, FilePattern::ExactPath("/app/config.yaml".into()), Action::FileRead),
            file_rule(2, FilePattern::Classified(PathPattern::ProcPidStatus), Action::FileRead),
            file_rule(3, FilePattern::Prefix("/app/".into()), Action::FileWrite),
        ];
        let (out, warns) = lower_to_apparmor(&rules, "test");
        assert!(out.contains("/app/config.yaml r,"), "{out}");
        assert!(out.contains("/proc/*/status r,"), "{out}");
        assert!(out.contains("/app/** w,"), "{out}");
        assert!(warns.is_empty());
    }

    #[test]
    fn network_is_lossy_and_warned() {
        let rules = vec![BehaviorRule {
            id: 7,
            subject: subj(),
            object: Object::Network(NetworkObject {
                dst_ip: Some(0x0101_0101),
                dst_port: Some(443),
                protocol: Some(6),
                direction: Some(1),
            }),
            action: Action::NetConnect,
            verdict: Verdict::Allow,
            metadata: RuleMetadata { source_module: SourceModule::Net, ..meta() },
        }];
        let (out, warns) = lower_to_apparmor(&rules, "test");
        // Destination is emitted as a peer ip/port conditional (ABI-gated), not widened.
        assert!(out.contains("network inet stream peer=(ip=1.1.1.1 port=443),"), "{out}");
        assert_eq!(warns.len(), 1);
    }

    #[test]
    fn network_without_dest_is_coarse_and_clean() {
        let rules = vec![BehaviorRule {
            id: 8,
            subject: subj(),
            object: Object::Network(NetworkObject {
                dst_ip: None,
                dst_port: None,
                protocol: Some(6),
                direction: Some(1),
            }),
            action: Action::NetConnect,
            verdict: Verdict::Allow,
            metadata: RuleMetadata { source_module: SourceModule::Net, ..meta() },
        }];
        let (out, warns) = lower_to_apparmor(&rules, "test");
        assert!(out.contains("network inet stream,"), "{out}");
        assert!(warns.is_empty());
    }

    #[test]
    fn exec_emits_ix() {
        let rules = vec![BehaviorRule {
            id: 5,
            subject: subj(),
            object: Object::Process(ProcessObject {
                binary: BinaryRef::Path("/usr/bin/python3".into()),
            }),
            action: Action::ProcExec,
            verdict: Verdict::Allow,
            metadata: RuleMetadata { source_module: SourceModule::Proc, ..meta() },
        }];
        let (out, _) = lower_to_apparmor(&rules, "test");
        assert!(out.contains("/usr/bin/python3 ix,"), "{out}");
    }
}
