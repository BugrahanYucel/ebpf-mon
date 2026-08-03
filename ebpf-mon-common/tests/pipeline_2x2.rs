//! 2x2 compiler-pipeline equivalence proof (the DEF CON demo's backbone).
//!
//! The whole thesis is "one IR in the middle". This test pins that down with two
//! independent claims, each runnable without a kernel:
//!
//!   FRONTEND CONVERGENCE  (source-independence)
//!     Two different source formats describing the *same* behavior — the eBPF
//!     monitor's JSON and a hand-written AppArmor profile — compile to the *same*
//!     normalized IR (same set of (object, action, verdict) behavioral rules).
//!
//!   BACKEND AGREEMENT     (target-independence)
//!     That one IR is lowered to two targets — our BPF-LSM policy image and an
//!     AppArmor profile — and both make identical allow/deny decisions on a
//!     battery of probe operations, matching an IR "oracle".
//!
//! Together: monitor-JSON and AppArmor are interchangeable on the way IN, and
//! BPF-LSM and AppArmor are interchangeable on the way OUT — which is exactly the
//! "M frontends + N backends, not M*N translators" claim.
//!
//! Run it (and print the convergence tables for the stage):
//!   cargo test -p ebpf-mon-common --features user --test pipeline_2x2 -- --nocapture
//!
//! NOTE on the BPF-LSM leg: there is no kernel here, so `BpfImage`/`allow_bpf`
//! model the userspace map-population + three-tier lookup that `enforcement.rs`
//! performs against real BPF maps. It is a faithful *model* of that backend's
//! decision logic, not the maps themselves.

#![cfg(feature = "user")]

use std::collections::{BTreeMap, HashSet};

use ebpf_mon_common::fs::PathPattern;
use ebpf_mon_common::policy::backends::apparmor::lower_to_apparmor;
use ebpf_mon_common::policy::frontends::apparmor::parse_apparmor;
use ebpf_mon_common::policy::{
    link_cross_category, run_pipeline, translate_all_events_json, Action, BehaviorRule, BinaryRef,
    FilePattern, Object, Verdict, ACCESS_READ, ACCESS_WRITE,
};

// --------------------------------------------------------------------------
// Scenario: the same container behavior expressed in both source formats.
// --------------------------------------------------------------------------

/// eBPF-monitor JSON frontend. The file/exec/net events below deliberately
/// include a cluster of machine-named files (WAL-like) so the generalization
/// pass collapses them into the *same* `/var/lib/app/cache/` prefix the AppArmor
/// profile writes by hand, and a raw `/proc/999/status` that classification
/// folds into the same `ProcPidStatus` pattern the AppArmor `/proc/*/status`
/// glob maps to.
const SCENARIO_JSON: &str = r#"
    {
      "fs": [
        {"path":"/app/config.yaml","r_w":"read","is_sensitive":0,"freq":5,"inode":1001,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/var/lib/app/cache/cache_00000001","r_w":"write","is_sensitive":0,"freq":1,"inode":2001,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/var/lib/app/cache/cache_00000002","r_w":"write","is_sensitive":0,"freq":1,"inode":2002,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/var/lib/app/cache/cache_00000003","r_w":"write","is_sensitive":0,"freq":1,"inode":2003,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/var/lib/app/cache/cache_00000004","r_w":"write","is_sensitive":0,"freq":1,"inode":2004,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/var/lib/app/cache/cache_00000005","r_w":"write","is_sensitive":0,"freq":1,"inode":2005,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/var/lib/app/cache/cache_00000006","r_w":"write","is_sensitive":0,"freq":1,"inode":2006,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
        {"path":"/proc/999/status","r_w":"read","is_sensitive":0,"freq":3,"inode":3001,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}}
      ],
      "process": [
        {"exec_path":"/usr/bin/python3","ps_type":"execve","cgroup_id":111,"inode":0,
         "process_ctx":{"uid":0}}
      ],
      "network": [
        {"dst_ip":"93.184.216.34","dst_port":443,"protocol":"TCP","direction":"outgoing","freq":10,
         "process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}}
      ]
    }
    "#;

fn monitor_ir() -> Vec<BehaviorRule> {
    let raw = translate_all_events_json(SCENARIO_JSON).expect("monitor JSON should translate");
    compile(raw)
}

/// AppArmor frontend: the same behavior, hand-written in AppArmor syntax.
fn apparmor_ir() -> Vec<BehaviorRule> {
    let profile = r#"
profile demo flags=(attach_disconnected) {
  /app/config.yaml r,
  /var/lib/app/cache/** w,
  /proc/*/status r,
  /usr/bin/python3 ix,
  network inet stream peer=(ip=93.184.216.34 port=443),
}
"#;
    let raw = parse_apparmor(profile).expect("AppArmor profile should parse");
    compile(raw)
}

/// The shared middle: optimization passes + cross-category linking.
fn compile(raw: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
    let (optimized, _conflicts) = run_pipeline(raw);
    link_cross_category(optimized)
}

// --------------------------------------------------------------------------
// Frontend convergence
// --------------------------------------------------------------------------

/// The behavioral core of a rule, ignoring frontend-provided context that
/// legitimately differs (rule ids, metadata, subject — an AppArmor profile has
/// no cgroup/uid subject).
fn semantic_key(r: &BehaviorRule) -> (Object, Action, Verdict) {
    (r.object.clone(), r.action, r.verdict)
}

fn semantic_set(rules: &[BehaviorRule]) -> HashSet<(Object, Action, Verdict)> {
    rules.iter().map(semantic_key).collect()
}

#[test]
fn frontends_converge_on_one_ir() {
    let monitor = monitor_ir();
    let apparmor = apparmor_ir();
    let m = semantic_set(&monitor);
    let a = semantic_set(&apparmor);

    println!("\n=== FRONTEND CONVERGENCE (monitor JSON vs AppArmor -> one IR) ===");
    println!("monitor  frontend -> {} behavioral rules", m.len());
    println!("apparmor frontend -> {} behavioral rules", a.len());
    for key in &m {
        println!("  {}", describe(key));
    }

    let only_monitor: Vec<_> = m.difference(&a).map(describe).collect();
    let only_apparmor: Vec<_> = a.difference(&m).map(describe).collect();
    assert!(
        only_monitor.is_empty() && only_apparmor.is_empty(),
        "frontends diverged.\n  only in monitor: {:?}\n  only in apparmor: {:?}",
        only_monitor,
        only_apparmor
    );
}

// --------------------------------------------------------------------------
// Backend agreement
// --------------------------------------------------------------------------

/// A single enforcement question posed to every backend.
#[derive(Clone, Copy)]
enum Probe {
    File { path: &'static str, action: Action },
    Exec { path: &'static str },
    Net { ip: u32, port: u32, proto: u8 },
}

/// Minimal classifier mirroring the enforcement path's `classify_path` for the
/// `/proc/<pid>/...` family exercised by the probes.
fn classify_probe(path: &str) -> Option<PathPattern> {
    let rem = path.strip_prefix("/proc/")?;
    let slash = rem.find('/')?;
    Some(match &rem[slash + 1..] {
        "status" => PathPattern::ProcPidStatus,
        "environ" => PathPattern::ProcPidEnviron,
        "cmdline" => PathPattern::ProcPidCmdline,
        _ => PathPattern::ProcPidOther,
    })
}

fn file_pattern_matches(pattern: &FilePattern, path: &str) -> bool {
    match pattern {
        FilePattern::ExactPath(p) => p == path,
        FilePattern::Prefix(pre) => path.starts_with(pre.as_str()),
        FilePattern::Classified(c) => classify_probe(path) == Some(*c),
    }
}

/// Reference semantics: does any Allow rule in the IR admit this probe?
fn allow_ir(rules: &[BehaviorRule], probe: &Probe) -> bool {
    rules.iter().any(|r| r.verdict == Verdict::Allow && rule_matches(r, probe))
}

fn rule_matches(r: &BehaviorRule, probe: &Probe) -> bool {
    match (probe, &r.object) {
        (Probe::File { path, action }, Object::File(f)) => {
            r.action == *action && file_pattern_matches(&f.pattern, path)
        }
        (Probe::Exec { path }, Object::Process(p)) => {
            r.action == Action::ProcExec && matches!(&p.binary, BinaryRef::Path(b) if b == path)
        }
        (Probe::Net { ip, port, proto }, Object::Network(n)) => {
            // The IR/AppArmor oracle is the *expressive* reference: it honors
            // protocol (AppArmor's stream/dgram). `None` on any field = "any".
            r.action == Action::NetConnect
                && n.dst_ip.map_or(true, |v| v == *ip)
                && n.dst_port.map_or(true, |v| v == *port)
                && n.protocol.map_or(true, |v| v == *proto)
        }
        _ => false,
    }
}

/// Open-granularity file question ("may this path be opened at all?"), ignoring
/// the read/write distinction. Used for the shared open-granularity surface; the
/// exact-path read/write distinction is proven separately in
/// `convergence_apparmor_and_bpf_enforce_rw_on_exact_paths`.
fn ir_opens(rules: &[BehaviorRule], path: &str) -> bool {
    rules.iter().any(|r| {
        r.verdict == Verdict::Allow
            && matches!(&r.object, Object::File(f) if file_pattern_matches(&f.pattern, path))
    })
}

fn aa_opens(profile_text: &str, path: &str) -> bool {
    let rules = parse_apparmor(profile_text).expect("emitted AppArmor should re-parse");
    ir_opens(&rules, path)
}

/// Model of the BPF-LSM backend's lowered maps + three-tier lookup.
///
/// Faithful to `ebpf-mon-ebpf/src/enforcement.rs`: the exact-path tier now
/// stores an access-mode MASK (ACCESS_READ / ACCESS_WRITE) — `security_file_open`
/// reads `file->f_flags & O_ACCMODE` and enforces read vs write. The
/// classification/prefix tiers remain open-granularity, and the net key omits
/// protocol.
#[derive(Default)]
struct BpfImage {
    exact: BTreeMap<String, u8>,    // tier 1: exact path hash -> access mask (r/w)
    patterns: HashSet<PathPattern>, // tier 2: classified pattern (open-granularity)
    prefixes: Vec<String>,          // tier 2.5: directory prefix (open-granularity)
    exec: HashSet<String>,          // security_bprm_check_security
    net: HashSet<(u32, u32)>,       // security_socket_connect: (ip, port); port 0 = any; no proto
}

fn lower_bpf(rules: &[BehaviorRule]) -> BpfImage {
    let mut img = BpfImage::default();
    for r in rules {
        if r.verdict != Verdict::Allow {
            continue;
        }
        match (&r.object, r.action) {
            (Object::File(f), Action::FileOpen | Action::FileRead | Action::FileWrite) => {
                // Mirror the loader: OR the permitted mode into the exact-path mask.
                let bit = if r.action == Action::FileWrite { ACCESS_WRITE } else { ACCESS_READ };
                match &f.pattern {
                    FilePattern::ExactPath(p) => {
                        *img.exact.entry(p.clone()).or_insert(0) |= bit;
                    }
                    FilePattern::Classified(c) => {
                        img.patterns.insert(*c);
                    }
                    FilePattern::Prefix(pre) => img.prefixes.push(pre.clone()),
                }
            }
            (Object::Process(p), Action::ProcExec) => {
                if let BinaryRef::Path(b) = &p.binary {
                    img.exec.insert(b.clone());
                }
            }
            (Object::Network(n), Action::NetConnect) => {
                // The loader drops ip-less rules; a missing port becomes the
                // kernel's port=0 wildcard. Protocol is not part of the key.
                if let Some(ip) = n.dst_ip {
                    img.net.insert((ip, n.dst_port.unwrap_or(0)));
                }
            }
            _ => {}
        }
    }
    img
}

/// Open-granularity file lookup ("may this path be opened at all?"): exact path
/// present with ANY mode, then classification, then prefix. Used for the shared
/// open-granularity surface; the read/write distinction is `bpf_access`.
fn bpf_opens(img: &BpfImage, path: &str) -> bool {
    if img.exact.contains_key(path) {
        return true;
    }
    if let Some(c) = classify_probe(path) {
        if img.patterns.contains(&c) {
            return true;
        }
    }
    img.prefixes.iter().any(|pre| path.starts_with(pre.as_str()))
}

/// Mode-aware file lookup: exact paths enforce the read/write mask; the
/// classification/prefix tiers stay open-granularity (any match permits any mode).
fn bpf_access(img: &BpfImage, path: &str, access: u8) -> bool {
    if let Some(mask) = img.exact.get(path) {
        return mask & access == access;
    }
    if let Some(c) = classify_probe(path) {
        if img.patterns.contains(&c) {
            return true;
        }
    }
    img.prefixes.iter().any(|pre| path.starts_with(pre.as_str()))
}

fn allow_bpf(img: &BpfImage, probe: &Probe) -> bool {
    match probe {
        Probe::File { path, action } => {
            let access = if *action == Action::FileWrite { ACCESS_WRITE } else { ACCESS_READ };
            bpf_access(img, path, access)
        }
        Probe::Exec { path } => img.exec.contains(*path),
        Probe::Net { ip, port, proto: _ } => {
            // Exact (ip, port) then the (ip, 0) wildcard-port fallback. No proto.
            img.net.contains(&(*ip, *port)) || img.net.contains(&(*ip, 0))
        }
    }
}

/// IPv4 dotted-quad -> the IR/enforcement `dst_ip` u32 (`from_le_bytes`).
fn ip_le(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_le_bytes([a, b, c, d])
}

/// Evaluate the *emitted* AppArmor profile by parsing it back and applying the
/// same oracle. Exercises the backend's text output through an independent read.
fn allow_apparmor(profile_text: &str, probe: &Probe) -> bool {
    let rules = parse_apparmor(profile_text).expect("emitted AppArmor should re-parse");
    allow_ir(&rules, probe)
}

#[test]
fn backends_agree_on_shared_granularity() {
    let ir = monitor_ir();
    let (apparmor_text, _warns) = lower_to_apparmor(&ir, "demo");
    let bpf = lower_bpf(&ir);

    // -- FILE openability (the shared granularity: "may this path be opened?").
    // BPF-LSM cannot enforce read vs write, so R/W agreement is tested as a
    // documented *divergence* below, not here. --
    let open_probes: &[(&str, bool)] = &[
        ("/app/config.yaml", true),                        // exact-path tier
        ("/var/lib/app/cache/cache_99999999", true),       // prefix tier (machine-named leaf)
        ("/var/lib/app/cache/deep/nested/x", true),        // prefix is depth-agnostic
        ("/var/lib/app/cache", false),                     // the dir node itself, no trailing slash
        ("/var/lib/app/cacheXtra/y", false),               // shares string prefix, different dir
        ("/var/lib/app/other/secret", false),              // unprofiled sibling
        ("/proc/12345/status", true),                      // classified tier
        ("/proc/12345/environ", false),                    // different classification
        ("/proc/12345/cmdline", false),                    // different classification
        ("/etc/shadow", false),                            // default-deny
        ("/usr/bin/python3", true),                        // cross-category linker: exec => readable
    ];

    println!("\n=== BACKEND AGREEMENT — files @ open granularity ===");
    println!("{:<44} {:>8} {:>8} {:>8} {:>8}", "path", "expect", "IR", "BPF", "AppArmor");
    for (path, expected) in open_probes {
        let d_ir = ir_opens(&ir, path);
        let d_bpf = bpf_opens(&bpf, path);
        let d_aa = aa_opens(&apparmor_text, path);
        println!("{:<44} {:>8} {:>8} {:>8} {:>8}", path, yn(*expected), yn(d_ir), yn(d_bpf), yn(d_aa));
        assert_eq!(d_ir, *expected, "IR disagreed on open {}", path);
        assert_eq!(d_bpf, *expected, "BPF-LSM disagreed on open {}", path);
        assert_eq!(d_aa, *expected, "AppArmor disagreed on open {}", path);
    }

    // -- EXEC + NETWORK: both backends express these at the same granularity, so
    // full agreement holds. Network probes use the profiled protocol (TCP). --
    let probes: &[(Probe, bool)] = &[
        (Probe::Exec { path: "/usr/bin/python3" }, true),
        (Probe::Exec { path: "/bin/sh" }, false),
        (Probe::Exec { path: "/app/config.yaml" }, false), // readable but not exec
        (Probe::Net { ip: ip_le(93, 184, 216, 34), port: 443, proto: 6 }, true),
        (Probe::Net { ip: ip_le(93, 184, 216, 34), port: 80, proto: 6 }, false),
        (Probe::Net { ip: ip_le(8, 8, 8, 8), port: 443, proto: 6 }, false),
    ];

    println!("\n=== BACKEND AGREEMENT — exec + network ===");
    for (probe, expected) in probes {
        let d_ir = allow_ir(&ir, probe);
        let d_bpf = allow_bpf(&bpf, probe);
        let d_aa = allow_apparmor(&apparmor_text, probe);
        println!("{:<44} {:>8} {:>8} {:>8} {:>8}", probe_label(probe), yn(*expected), yn(d_ir), yn(d_bpf), yn(d_aa));
        assert_eq!(d_ir, *expected, "IR disagreed on {}", probe_label(probe));
        assert_eq!(d_bpf, *expected, "BPF-LSM disagreed on {}", probe_label(probe));
        assert_eq!(d_aa, *expected, "AppArmor disagreed on {}", probe_label(probe));
    }
}

// --------------------------------------------------------------------------
// Documented divergences (each backend's expressibility envelope differs).
// These are the friction points the talk/report must be honest about.
// --------------------------------------------------------------------------

/// FILE read/write granularity — divergence #1, now CLOSED for exact paths.
/// `/app/config.yaml` was profiled read-only. AppArmor emits `r,` and denies a
/// write-open; BPF-LSM now reads `file->f_flags & O_ACCMODE` and its exact-path
/// map stores an ACCESS_READ/ACCESS_WRITE mask, so it ALSO denies the write —
/// matching AppArmor and the IR reference. A read of the same file is allowed by
/// all three.
#[test]
fn convergence_apparmor_and_bpf_enforce_rw_on_exact_paths() {
    let ir = monitor_ir();
    let (aa, _w) = lower_to_apparmor(&ir, "demo");
    let bpf = lower_bpf(&ir);
    let read = Probe::File { path: "/app/config.yaml", action: Action::FileRead };
    let write = Probe::File { path: "/app/config.yaml", action: Action::FileWrite };

    // Read is allowed everywhere.
    assert!(allow_ir(&ir, &read), "IR: read rule present");
    assert!(allow_apparmor(&aa, &read), "AppArmor allows read");
    assert!(allow_bpf(&bpf, &read), "BPF-LSM allows read (exact-path mask has the read bit)");

    // Write to a read-only file is denied everywhere (divergence closed).
    assert!(!allow_ir(&ir, &write), "IR reference: no write rule -> deny");
    assert!(!allow_apparmor(&aa, &write), "AppArmor enforces R/W -> deny write to read-only file");
    assert!(
        !allow_bpf(&bpf, &write),
        "BPF-LSM now enforces R/W on exact paths -> the write is DENIED (matches intent)"
    );
}

/// NETWORK protocol: the endpoint was profiled over TCP. AppArmor emits
/// `network inet stream` and denies a UDP connect; BPF-LSM's socket_connect key
/// omits protocol and therefore *permits* the UDP connect.
#[test]
fn divergence_apparmor_enforces_protocol_bpf_does_not() {
    let ir = monitor_ir();
    let (aa, _w) = lower_to_apparmor(&ir, "demo");
    let bpf = lower_bpf(&ir);
    let udp = Probe::Net { ip: ip_le(93, 184, 216, 34), port: 443, proto: 17 };

    assert!(!allow_ir(&ir, &udp), "IR reference: rule is TCP -> UDP denied");
    assert!(!allow_apparmor(&aa, &udp), "AppArmor enforces stream/dgram -> UDP denied");
    assert!(allow_bpf(&bpf, &udp), "BPF-LSM ignores protocol -> UDP ALLOWED (over-permission vs intent)");
}

/// NETWORK ip-wildcard: an ip-less allow rule means "any peer" to AppArmor, but
/// the BPF-LSM loader *drops* ip-less rules (its key requires a concrete ip),
/// turning an intended allow into a default-deny. Built by hand since neither
/// frontend emits ip-wildcards from the demo scenario.
#[test]
fn divergence_ip_wildcard_allowed_by_apparmor_dropped_by_bpf() {
    use ebpf_mon_common::policy::{NetworkObject, RuleMetadata, SourceModule, Subject};
    let rule = BehaviorRule {
        id: 1,
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
    let bpf = lower_bpf(&ir);
    let probe = Probe::Net { ip: ip_le(1, 2, 3, 4), port: 443, proto: 6 };

    assert!(allow_ir(&ir, &probe), "IR reference: ip=any -> allowed");
    assert!(bpf.net.is_empty(), "BPF-LSM loader drops ip-less rules");
    assert!(!allow_bpf(&bpf, &probe), "BPF-LSM -> default-deny (intended allow lost)");
}

/// Regression guard for the cross-frontend IPv4 encoding bug: the eBPF-monitor
/// frontend and the AppArmor frontend must produce the *same* `dst_ip` u32 for a
/// non-palindromic address (both now use the enforcement `from_le_bytes`
/// convention). If this ever regresses, an AppArmor-sourced network rule would
/// silently never match at the kernel hook.
#[test]
fn ipv4_encoding_is_consistent_across_frontends() {
    let m = translate_all_events_json(
        r#"{"network":[{"dst_ip":"93.184.216.34","dst_port":443,"protocol":"TCP","direction":"outgoing","process_ctx":{}}]}"#,
    )
    .unwrap();
    let a = parse_apparmor("network inet stream peer=(ip=93.184.216.34 port=443),\n").unwrap();
    let mip = match &m[0].object { Object::Network(n) => n.dst_ip, _ => None };
    let aip = match &a[0].object { Object::Network(n) => n.dst_ip, _ => None };
    assert_eq!(mip, aip, "frontends must agree on IPv4 encoding");
    assert_eq!(mip, Some(ip_le(93, 184, 216, 34)), "must use the enforcement (from_le_bytes) convention");
}

// --------------------------------------------------------------------------
// Compiler-property edge cases
// --------------------------------------------------------------------------

/// Re-running the optimization pipeline on already-optimized IR must be a no-op
/// (a stable fixed point) — the classic "optimizer converges" property.
#[test]
fn pipeline_is_idempotent() {
    let once = compile(
        translate_all_events_json(SCENARIO_JSON).expect("translate"),
    );
    let (twice, _c) = run_pipeline(once.clone());
    assert_eq!(
        semantic_set(&once),
        semantic_set(&twice),
        "second pipeline pass changed the IR — passes are not idempotent"
    );
}

/// Lexically messy paths from one frontend still converge with clean paths from
/// another, thanks to the canonicalization pass (`//`, `/./`).
#[test]
fn canonicalization_converges_messy_and_clean_paths() {
    let messy = compile(
        translate_all_events_json(
            r#"{"fs":[{"path":"/data/./sub//file","r_w":"read","process_ctx":{}}]}"#,
        )
        .unwrap(),
    );
    let clean = compile(parse_apparmor("/data/sub/file r,\n").unwrap());
    assert_eq!(semantic_set(&messy), semantic_set(&clean));
}

/// Deny verdicts survive the whole pipeline and lower back to an AppArmor `deny`
/// line — the substrate the (optional) conflict-detection pass needs.
#[test]
fn deny_rule_survives_pipeline_and_lowers() {
    let ir = compile(parse_apparmor("deny /etc/shadow r,\n").unwrap());
    assert!(
        ir.iter().any(|r| r.verdict == Verdict::Deny),
        "deny verdict was lost in the pipeline"
    );
    let (text, _w) = lower_to_apparmor(&ir, "demo");
    assert!(text.contains("deny"), "backend dropped the deny verdict:\n{text}");
}

/// Frontend convergence must not depend on event ordering (rules form a set).
#[test]
fn frontend_convergence_is_order_independent() {
    let forward = compile(
        translate_all_events_json(
            r#"{"fs":[
                {"path":"/a/x","r_w":"read","process_ctx":{}},
                {"path":"/b/y","r_w":"read","process_ctx":{}}
            ]}"#,
        )
        .unwrap(),
    );
    let reversed = compile(
        translate_all_events_json(
            r#"{"fs":[
                {"path":"/b/y","r_w":"read","process_ctx":{}},
                {"path":"/a/x","r_w":"read","process_ctx":{}}
            ]}"#,
        )
        .unwrap(),
    );
    assert_eq!(semantic_set(&forward), semantic_set(&reversed));
}

// --------------------------------------------------------------------------
// Small pretty-printers (stage output only)
// --------------------------------------------------------------------------

fn yn(b: bool) -> &'static str {
    if b { "ALLOW" } else { "deny" }
}

fn probe_label(p: &Probe) -> String {
    match p {
        Probe::File { path, action } => format!("file {:?} {}", action, path),
        Probe::Exec { path } => format!("exec {}", path),
        Probe::Net { ip, port, proto } => {
            let [a, b, c, d] = ip.to_le_bytes();
            format!("net {a}.{b}.{c}.{d}:{port} proto {proto}")
        }
    }
}

fn describe(key: &(Object, Action, Verdict)) -> String {
    let (obj, action, verdict) = key;
    let what = match obj {
        Object::File(f) => match &f.pattern {
            FilePattern::ExactPath(p) => format!("file exact  {}", p),
            FilePattern::Prefix(p) => format!("file prefix {}**", p),
            FilePattern::Classified(c) => format!("file glob   {}", c.as_str()),
        },
        Object::Process(p) => match &p.binary {
            BinaryRef::Path(b) => format!("exec        {}", b),
            BinaryRef::Comm(_) => "exec        <comm>".to_string(),
        },
        Object::Network(n) => format!(
            "net         ip={:?} port={:?} proto={:?}",
            n.dst_ip, n.dst_port, n.protocol
        ),
    };
    format!("{:?}/{:?}: {}", verdict, action, what)
}
