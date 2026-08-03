//! CROSS-FORMAT POLICY EQUIVALENCE — the concrete, audience-facing version of
//! the 2x2 story (`tests/pipeline_2x2.rs` is the rigorous assertion side).
//!
//! It shows, on screen, with no kernel required:
//!   1. the SAME intent expressed in TWO source formats (eBPF-monitor events and
//!      a hand-written AppArmor profile),
//!   2. both compiling to the SAME normalized IR (byte-for-byte rule set),
//!   3. that ONE IR lowered to TWO enforcement formats (AppArmor text + BPF-LSM
//!      map plan), and
//!   4. a decision table: the SAME operations, run under BOTH enforcement
//!      formats, produce identical verdicts on the shared surface — plus the
//!      two places the formats deliberately diverge.
//!
//! Run:  cargo run -q -p ebpf-mon-common --features user --example cross_format

use std::collections::{BTreeMap, HashSet};

use ebpf_mon_common::fs::PathPattern;
use ebpf_mon_common::policy::backends::apparmor::lower_to_apparmor;
use ebpf_mon_common::policy::frontends::apparmor::parse_apparmor;
use ebpf_mon_common::policy::{
    link_cross_category, run_pipeline, translate_all_events_json, Action, BehaviorRule, BinaryRef,
    FilePattern, Object, Verdict, ACCESS_READ, ACCESS_WRITE,
};

// ANSI (kept dependency-free)
const H: &str = "\x1b[1;36m"; // header
const Y: &str = "\x1b[1;33m"; // sub-header
const G: &str = "\x1b[0;32m"; // allow / agree
const R: &str = "\x1b[0;31m"; // deny / diverge
const D: &str = "\x1b[0;90m"; // dim
const NC: &str = "\x1b[0m";

// ---- the same container behavior, expressed two ways -----------------------

const MONITOR_EVENTS: &str = r#"
{
  "fs": [
    {"path":"/app/config.yaml","r_w":"read","freq":5,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/var/lib/app/cache/cache_00000001","r_w":"write","freq":1,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/var/lib/app/cache/cache_00000002","r_w":"write","freq":1,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/var/lib/app/cache/cache_00000003","r_w":"write","freq":1,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/var/lib/app/cache/cache_00000004","r_w":"write","freq":1,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/var/lib/app/cache/cache_00000005","r_w":"write","freq":1,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/var/lib/app/cache/cache_00000006","r_w":"write","freq":1,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}},
    {"path":"/proc/999/status","r_w":"read","freq":3,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}}
  ],
  "process": [
    {"exec_path":"/usr/bin/python3","ps_type":"execve","cgroup_id":111,"process_ctx":{"uid":0}}
  ],
  "network": [
    {"dst_ip":"93.184.216.34","dst_port":443,"protocol":"TCP","direction":"outgoing","freq":10,"process_ctx":{"executable":"/usr/bin/python3","uid":0,"cgroup_id":111}}
  ]
}
"#;

const APPARMOR_PROFILE: &str = r#"profile demo flags=(attach_disconnected) {
  /app/config.yaml r,
  /var/lib/app/cache/** w,
  /proc/*/status r,
  /usr/bin/python3 ix,
  network inet stream peer=(ip=93.184.216.34 port=443),
}
"#;

fn compile(raw: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
    let (optimized, _conflicts) = run_pipeline(raw);
    link_cross_category(optimized)
}

fn semantic_set(rules: &[BehaviorRule]) -> HashSet<(Object, Action, Verdict)> {
    rules
        .iter()
        .map(|r| (r.object.clone(), r.action, r.verdict))
        .collect()
}

fn main() {
    println!("{H}=== CROSS-FORMAT POLICY EQUIVALENCE ==={NC}");
    println!("{D}one policy, two source formats in, two enforcement formats out{NC}\n");

    // 1) two frontends -----------------------------------------------------
    println!("{Y}INPUT A — eBPF monitor events (frontend #1):{NC}");
    println!("{D}  file: /app/config.yaml (r), /var/lib/app/cache/cache_0000000{{1..6}} (w),{NC}");
    println!("{D}        /proc/999/status (r)   exec: /usr/bin/python3   net: 93.184.216.34:443/TCP{NC}");
    println!("\n{Y}INPUT B — AppArmor profile, hand-written (frontend #2):{NC}");
    for line in APPARMOR_PROFILE.trim().lines() {
        println!("{D}  {line}{NC}");
    }

    let ir_from_events = compile(translate_all_events_json(MONITOR_EVENTS).expect("monitor JSON"));
    let ir_from_aa = compile(parse_apparmor(APPARMOR_PROFILE).expect("apparmor profile"));

    // 2) convergence to one IR --------------------------------------------
    let set_e = semantic_set(&ir_from_events);
    let set_a = semantic_set(&ir_from_aa);
    let identical = set_e == set_a;

    println!("\n{H}--> compiled through the same pipeline (canonicalize/dedup/classify/prefix/subsume/link){NC}");
    println!(
        "    frontend A (events)   -> {} behavioral rules",
        set_e.len()
    );
    println!(
        "    frontend B (apparmor) -> {} behavioral rules",
        set_a.len()
    );
    if identical {
        println!(
            "    {G}IR MATCH: identical rule set — both formats mean the same thing{NC}"
        );
    } else {
        println!("    {R}IR DIFF:{NC}");
        for k in set_e.symmetric_difference(&set_a) {
            println!("      {R}~ {:?}/{:?}{NC}", k.2, k.1);
        }
    }

    println!("\n{Y}the shared IR (target-independent — WHO/WHAT/OP/VERDICT):{NC}");
    let mut rows: Vec<String> = ir_from_events.iter().map(describe).collect();
    rows.sort();
    rows.dedup();
    for row in &rows {
        println!("  {row}");
    }

    // 3) one IR -> two enforcement formats --------------------------------
    let ir = ir_from_events;
    let (aa_text, _warns) = lower_to_apparmor(&ir, "demo");
    let bpf = lower_bpf(&ir);

    println!("\n{H}--> that ONE IR, lowered to TWO enforcement formats:{NC}");
    println!("\n  {Y}[format 1] AppArmor profile (userspace LSM):{NC}");
    for line in aa_text.trim().lines() {
        println!("    {D}{line}{NC}");
    }
    println!("\n  {Y}[format 2] BPF-LSM map plan (in-kernel):{NC}");
    let exact_disp: Vec<String> = bpf
        .exact
        .iter()
        .map(|(p, m)| format!("{p} ({})", mode_str(*m)))
        .collect();
    println!("    {D}exact-path : {:?}{NC}", exact_disp);
    println!(
        "    {D}patterns   : {:?}{NC}",
        bpf.patterns.iter().map(|p| p.as_str()).collect::<Vec<_>>()
    );
    println!("    {D}prefixes   : {:?}{NC}", bpf.prefixes);
    println!("    {D}exec       : {:?}{NC}", sorted(&bpf.exec));
    println!(
        "    {D}net (ip,port): {:?}{NC}",
        bpf.net.iter().map(|(i, p)| (ip_str(*i), *p)).collect::<Vec<_>>()
    );

    // 4) same operations, both enforcement formats ------------------------
    println!(
        "\n{H}--> run the SAME operations under BOTH enforcement formats:{NC}"
    );
    println!(
        "    {:<40} {:>9} {:>9} {:>7}",
        "operation", "AppArmor", "BPF-LSM", "agree"
    );
    let shared: &[Probe] = &[
        Probe::File("/app/config.yaml"),
        // write to a file profiled read-only: both deny (exact-path r/w mask).
        Probe::FileWrite("/app/config.yaml"),
        Probe::File("/var/lib/app/cache/cache_99999999"),
        Probe::File("/var/lib/app/cache/deep/nested/x"),
        Probe::File("/proc/12345/status"),
        Probe::File("/proc/12345/environ"),
        Probe::File("/etc/shadow"),
        Probe::Exec("/usr/bin/python3"),
        Probe::Exec("/bin/sh"),
        Probe::Net(ip(93, 184, 216, 34), 443, 6),
        Probe::Net(ip(8, 8, 8, 8), 443, 6),
    ];
    let mut all_agree = true;
    for p in shared {
        let a = aa_decides(&aa_text, p);
        let b = bpf_decides(&bpf, p);
        let agree = a == b;
        all_agree &= agree;
        println!(
            "    {:<40} {:>17} {:>17} {:>15}",
            p.label(),
            verdict(a),
            verdict(b),
            if agree { format!("{G}yes{NC}") } else { format!("{R}NO{NC}") }
        );
    }
    println!(
        "\n    {}",
        if all_agree {
            format!("{G}==> same policy, two enforcement formats, identical decisions on the shared surface{NC}")
        } else {
            format!("{R}==> mismatch on the shared surface (unexpected){NC}")
        }
    );

    // 5) the documented divergences that remain (envelope, not bugs) ------
    println!(
        "\n{H}--> where the two formats still DIVERGE (documented envelope, from --friction-report):{NC}"
    );
    diverge_row(
        "connect 93.184.216.34:443 / UDP  (profiled TCP)",
        aa_decides(&aa_text, &Probe::Net(ip(93, 184, 216, 34), 443, 17)),
        bpf_decides(&bpf, &Probe::Net(ip(93, 184, 216, 34), 443, 17)),
        "AppArmor keeps stream/dgram; BPF-LSM socket key omits protocol",
    );
    // ip-wildcard: build a one-off "any peer" IR to show the sharp edge.
    let any_peer = any_peer_rule();
    let aa_any = {
        let (t, _w) = lower_to_apparmor(&any_peer, "demo");
        aa_decides(&t, &Probe::Net(ip(1, 2, 3, 4), 443, 6))
    };
    let bpf_any = bpf_decides(&lower_bpf(&any_peer), &Probe::Net(ip(1, 2, 3, 4), 443, 6));
    diverge_row(
        "connect <any-ip>:443  (ip-less allow rule)",
        aa_any,
        bpf_any,
        "AppArmor expresses 'any peer'; BPF-LSM loader drops ip-less rules",
    );

    println!(
        "\n{D}(rigorously asserted by the 10-case suite: cargo test -p ebpf-mon-common --features user --test pipeline_2x2){NC}"
    );
}

// ---- probes & the two backend decision models ------------------------------

enum Probe {
    File(&'static str),      // open-granularity file question
    FileWrite(&'static str), // write-specifically (for the R/W divergence)
    Exec(&'static str),
    Net(u32, u32, u8),
}

impl Probe {
    fn label(&self) -> String {
        match self {
            Probe::File(p) => format!("open {p}"),
            Probe::FileWrite(p) => format!("write {p}"),
            Probe::Exec(p) => format!("exec {p}"),
            Probe::Net(i, port, proto) => {
                format!("connect {}:{}/{}", ip_str(*i), port, if *proto == 6 { "tcp" } else { "udp" })
            }
        }
    }
}

/// AppArmor decision: parse the emitted profile back and evaluate (independent read).
fn aa_decides(profile_text: &str, p: &Probe) -> bool {
    let rules = parse_apparmor(profile_text).expect("emitted AppArmor should re-parse");
    match p {
        Probe::File(path) => ir_opens(&rules, path),
        Probe::FileWrite(path) => rules.iter().any(|r| {
            r.verdict == Verdict::Allow
                && r.action == Action::FileWrite
                && matches!(&r.object, Object::File(f) if file_pattern_matches(&f.pattern, path))
        }),
        Probe::Exec(path) => rules.iter().any(|r| {
            r.verdict == Verdict::Allow
                && r.action == Action::ProcExec
                && matches!(&r.object, Object::Process(pr) if matches!(&pr.binary, BinaryRef::Path(b) if b == path))
        }),
        Probe::Net(ipv, port, proto) => rules.iter().any(|r| {
            r.verdict == Verdict::Allow
                && r.action == Action::NetConnect
                && matches!(&r.object, Object::Network(n)
                    if n.dst_ip.map_or(true, |v| v == *ipv)
                    && n.dst_port.map_or(true, |v| v == *port)
                    && n.protocol.map_or(true, |v| v == *proto))
        }),
    }
}

fn bpf_decides(img: &BpfImage, p: &Probe) -> bool {
    match p {
        // A plain open is a read open; the exact-path tier now enforces the mode.
        Probe::File(path) => bpf_access(img, path, ACCESS_READ),
        // A write must match the write bit on an exact entry (pattern/prefix
        // tiers stay open-granularity and still permit it).
        Probe::FileWrite(path) => bpf_access(img, path, ACCESS_WRITE),
        Probe::Exec(path) => img.exec.contains(*path),
        // socket key omits protocol; (ip,0) is the wildcard-port fallback.
        Probe::Net(ipv, port, _proto) => {
            img.net.contains(&(*ipv, *port)) || img.net.contains(&(*ipv, 0))
        }
    }
}

fn ir_opens(rules: &[BehaviorRule], path: &str) -> bool {
    rules.iter().any(|r| {
        r.verdict == Verdict::Allow
            && matches!(&r.object, Object::File(f) if file_pattern_matches(&f.pattern, path))
    })
}

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

/// Faithful model of the BPF-LSM lowered maps (mirrors enforcement.rs and the
/// 2x2 test's `BpfImage`). The exact-path map now stores an access-mode MASK
/// (ACCESS_READ / ACCESS_WRITE) so `security_file_open` distinguishes read from
/// write — closing the old open-granularity divergence for exact paths. The
/// pattern/prefix tiers remain open-granularity, and the net key omits protocol.
#[derive(Default)]
struct BpfImage {
    exact: BTreeMap<String, u8>, // path -> access mask (ACCESS_READ | ACCESS_WRITE)
    patterns: HashSet<PathPattern>,
    prefixes: Vec<String>,
    exec: HashSet<String>,
    net: HashSet<(u32, u32)>,
}

fn lower_bpf(rules: &[BehaviorRule]) -> BpfImage {
    let mut img = BpfImage::default();
    for r in rules {
        if r.verdict != Verdict::Allow {
            continue;
        }
        match (&r.object, r.action) {
            (Object::File(f), Action::FileOpen | Action::FileRead | Action::FileWrite) => {
                // OR the mode this rule permits into the exact-path mask, exactly
                // like the loader (FileWrite -> write bit, otherwise read).
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
                if let Some(ipv) = n.dst_ip {
                    img.net.insert((ipv, n.dst_port.unwrap_or(0)));
                }
            }
            _ => {}
        }
    }
    img
}

/// Does the BPF-LSM image permit `access` (ACCESS_READ / ACCESS_WRITE) on `path`?
/// Exact paths carry a real r/w mask; pattern/prefix tiers are open-granularity
/// (any match permits any mode).
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

/// Render an access mask as AppArmor-style mode flags for display.
fn mode_str(mask: u8) -> &'static str {
    match (mask & ACCESS_READ != 0, mask & ACCESS_WRITE != 0) {
        (true, true) => "rw",
        (true, false) => "r",
        (false, true) => "w",
        _ => "-",
    }
}

fn any_peer_rule() -> Vec<BehaviorRule> {
    use ebpf_mon_common::policy::{NetworkObject, RuleMetadata, SourceModule, Subject};
    vec![BehaviorRule {
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
    }]
}

// ---- tiny formatting helpers ----------------------------------------------

fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_le_bytes([a, b, c, d])
}
fn ip_str(v: u32) -> String {
    let [a, b, c, d] = v.to_le_bytes();
    format!("{a}.{b}.{c}.{d}")
}
fn verdict(b: bool) -> String {
    if b {
        format!("{G}ALLOW{NC}")
    } else {
        format!("{R}deny{NC}")
    }
}
fn sorted(s: &HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = s.iter().cloned().collect();
    v.sort();
    v
}
fn diverge_row(op: &str, aa: bool, bpf: bool, why: &str) {
    println!("  {op}");
    println!(
        "     AppArmor {}   BPF-LSM {}   {D}({why}){NC}",
        verdict(aa),
        verdict(bpf)
    );
}
fn describe(r: &BehaviorRule) -> String {
    let what = match &r.object {
        Object::File(f) => match &f.pattern {
            FilePattern::ExactPath(p) => format!("file exact  {p}"),
            FilePattern::Prefix(p) => format!("file prefix {p}**"),
            FilePattern::Classified(c) => format!("file glob   {}", c.as_str()),
        },
        Object::Process(p) => match &p.binary {
            BinaryRef::Path(b) => format!("exec        {b}"),
            BinaryRef::Comm(_) => "exec        <comm>".to_string(),
        },
        Object::Network(n) => format!(
            "net         ip={} port={:?} proto={:?}",
            n.dst_ip.map_or("any".into(), ip_str),
            n.dst_port,
            n.protocol
        ),
    };
    format!("{:?} {:<10?} {what}", r.verdict, r.action)
}
