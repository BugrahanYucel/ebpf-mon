use aya::{Btf, include_bytes_aligned, maps::HashMap, programs::{BtfTracePoint, CgroupSkb, FEntry, FExit, TracePoint}};
#[rustfmt::skip]
use log::{debug, warn, info, error};
use serde_json::Value;
use tokio::{signal, sync::mpsc};
use std::process::Command;
use clap::Parser;

use ebpf_mon_common::modules::EncodedEvent;

use std::sync::atomic::Ordering;

use crate::manager::{export_events_to_json, listen_all_events, simple_event_reader};
use crate::events::{EventMap};
use crate::container::{ContainerIdentifier, TrackedContainer, ContainerWatcher, ContainerStateChange};
use std::sync::{Arc, Mutex};

mod manager;
mod program;
mod events;
mod container;
mod enforcement;

/// eBPF Security Monitoring Tool
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "eBPF-based security monitoring tool for containers and cgroups.\n\n\
                  Monitor filesystem, network, and process events with minimal overhead.\n\n\
                  Examples:\n  \
                  # Monitor default cgroup (user.slice)\n  \
                  sudo ebpf-mon\n\n  \
                  # Monitor specific Docker container by name (with restart tracking)\n  \
                  sudo ebpf-mon --name nginx-prod\n\n  \
                  # Monitor specific Docker container by ID\n  \
                  sudo ebpf-mon --container my-container\n  \
                  sudo ebpf-mon --container a1b2c3d4e5f6\n\n  \
                  # Monitor custom cgroup path (no restart tracking)\n  \
                  sudo ebpf-mon --cgroup /sys/fs/cgroup/system.slice/docker.service"
)]
struct Args {
    /// Container name to monitor (supports restart tracking)
    #[arg(long, conflicts_with_all = ["container", "cgroup"])]
    name: Option<String>,
    
    /// Docker container ID to monitor (will try to resolve name for restart tracking)
    #[arg(long, conflicts_with_all = ["name", "cgroup"])]
    container: Option<String>,
    
    /// Cgroup path to monitor directly (no restart tracking)
    #[arg(long, conflicts_with_all = ["name", "container"])]
    cgroup: Option<String>,

    /// Path to a profile JSON (e.g. final-events.json) to compile and enforce
    #[arg(long, value_name = "PROFILE")]
    enforce: Option<String>,

    /// Compile a profile JSON and report the emitted policy WITHOUT loading or
    /// enforcing anything (dry run). Needs no root/LSM. Use to A/B optimized vs
    /// --no-optimize rule counts.
    #[arg(long, value_name = "PROFILE", conflicts_with = "enforce")]
    compile: Option<String>,

    /// When used with --enforce, log policy violations without blocking
    #[arg(long, requires = "enforce")]
    audit_only: bool,

    /// Skip optimization passes (dedup/generalize/subsumption); canonicalization and
    /// cross-category linking still run. Applies wherever the pipeline runs
    /// (--enforce or --compile). Intended for benchmarking optimized vs unoptimized.
    #[arg(long)]
    no_optimize: bool,

    /// With --compile or --enforce: also emit an AppArmor profile to this path.
    #[arg(long, value_name = "FILE")]
    emit_apparmor: Option<String>,

    /// With --compile or --enforce: also emit the optimized IR as JSON to this path.
    #[arg(long, value_name = "FILE")]
    emit_json: Option<String>,

    /// Path to a JSON file overriding the optimization pass thresholds
    /// (prefix_min_cluster/min_depth/min_affix, sensitive_roots). Validated on
    /// load; missing fields fall back to conservative defaults. Lets you tune how
    /// aggressively generalization fires without recompiling.
    #[arg(long, value_name = "FILE")]
    pass_config: Option<String>,

    /// With --compile or --enforce: print a generated per-rule friction report
    /// showing what each backend (BPF-LSM, AppArmor) expresses exactly,
    /// approximates, or must drop from the IR.
    #[arg(long)]
    friction_report: bool,

    /// With --compile or --enforce: print the ACTUAL compiled rules (concrete
    /// keys grouped by target map category), not just per-category counts. The
    /// kernel maps key on a one-way path hash and can't be read back, but
    /// userspace holds the IR before hashing — so this is exactly what each map
    /// entry is built from.
    #[arg(long)]
    dump_policy: bool,
} 

// Use OUT_DIR for compilation, then manually copy for CO-RE testing
const EBPF_BYTES: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/release/ebpf-mon");

/// Run the policy pipeline on a profile JSON and return the final (linked) IR.
/// Shared by --enforce and --compile so both report identically. Logs the
/// per-pass rule-count report (the compiler-style "what optimization did").
fn compile_profile(
    profile_json: &str,
    no_optimize: bool,
    pass_config: &ebpf_mon_common::policy::PassConfig,
) -> anyhow::Result<Vec<ebpf_mon_common::policy::BehaviorRule>> {
    use ebpf_mon_common::policy::{
        translate_all_events_json, run_pipeline_reported_with, link_cross_category,
        CanonicalizationPass, ConflictDetectionPass, OptimizationPass,
    };

    let raw_rules = translate_all_events_json(profile_json)
        .map_err(|e| anyhow::anyhow!("Failed to translate profile: {}", e))?;
    info!("Translated {} raw rules from profile", raw_rules.len());

    let (optimized, conflicts) = if no_optimize {
        info!("Optimization passes SKIPPED (--no-optimize); running canonicalization only");
        let before = raw_rules.len();
        let canonical = CanonicalizationPass.run(raw_rules);
        info!("  {:<14} {:>6} -> {:>6}", "canonicalize", before, canonical.len());
        let conflicts = ConflictDetectionPass::detect(&canonical);
        (canonical, conflicts)
    } else {
        let (optimized, conflicts, stats) = run_pipeline_reported_with(raw_rules, pass_config);
        info!("Optimization pass report (rules in -> out):");
        for s in &stats {
            info!("  {:<14} {:>6} -> {:>6}  ({} removed)", s.name, s.before, s.after, s.removed());
        }
        (optimized, conflicts)
    };
    info!("Optimization complete: {} rules ({} conflicts detected)",
        optimized.len(), conflicts.len());
    for c in &conflicts {
        warn!("Policy conflict: rule {} vs rule {}", c.rule_a.id, c.rule_b.id);
    }

    let linked = link_cross_category(optimized);
    info!("Cross-category linking complete: {} rules", linked.len());
    Ok(linked)
}

/// Emit the compiled IR to optional backend outputs (AppArmor profile / IR JSON).
fn emit_outputs(
    linked: &[ebpf_mon_common::policy::BehaviorRule],
    emit_apparmor: Option<&str>,
    emit_json: Option<&str>,
    profile_name: &str,
) -> anyhow::Result<()> {
    if let Some(path) = emit_apparmor {
        let (profile, warnings) =
            ebpf_mon_common::policy::backends::apparmor::lower_to_apparmor(linked, profile_name);
        std::fs::write(path, profile)
            .map_err(|e| anyhow::anyhow!("Failed to write AppArmor profile '{}': {}", path, e))?;
        info!("Emitted AppArmor profile to {} ({} lowering warnings)", path, warnings.len());
        for w in &warnings {
            warn!("AppArmor lowering (rule {}): {}", w.rule_id, w.message);
        }
    }
    if let Some(path) = emit_json {
        let json = serde_json::to_string_pretty(linked)
            .map_err(|e| anyhow::anyhow!("Failed to serialize IR: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| anyhow::anyhow!("Failed to write JSON '{}': {}", path, e))?;
        info!("Emitted optimized IR JSON to {}", path);
    }
    Ok(())
}

/// Print the emitted-rule breakdown by target map category (compile dry-run).
fn print_rule_breakdown(rules: &[ebpf_mon_common::policy::BehaviorRule], no_optimize: bool) {
    use ebpf_mon_common::policy::{Action, FilePattern, Object};
    let (mut file_exact, mut file_pattern, mut file_prefix, mut exec, mut net) = (0, 0, 0, 0, 0);
    for r in rules {
        match (&r.object, &r.action) {
            (Object::File(f), _) => match &f.pattern {
                FilePattern::ExactPath(_) => file_exact += 1,
                FilePattern::Classified(_) => file_pattern += 1,
                FilePattern::Prefix(_) => file_prefix += 1,
            },
            (Object::Process(_), Action::ProcExec) => exec += 1,
            (Object::Network(_), _) => net += 1,
            _ => {}
        }
    }
    println!();
    println!("=== COMPILE (dry run){} ===", if no_optimize { " [--no-optimize]" } else { "" });
    println!("emitted rules: {}", rules.len());
    println!("  file (exact path): {}", file_exact);
    println!("  file (classified): {}", file_pattern);
    println!("  file (prefix):     {}", file_prefix);
    println!("  exec:              {}", exec);
    println!("  network:           {}", net);
    println!("(per-pass reduction is in the logs above; run with RUST_LOG=info)");
}

/// Print the ACTUAL compiled rules (concrete keys), grouped by the target map
/// category — the answer to "show me the BPF-LSM rules for real". The kernel
/// maps key on a one-way FNV path hash, so entries can't be read back out of the
/// kernel; but userspace holds the IR *before* hashing, so this prints exactly
/// what each map entry was built from. Reuses `friction::rule_summary` so the
/// text can never drift from the friction report.
fn dump_policy_rules(rules: &[ebpf_mon_common::policy::BehaviorRule]) {
    use ebpf_mon_common::policy::friction::rule_summary;
    use ebpf_mon_common::policy::{Action, FilePattern, Object};

    let (mut exact, mut classified, mut prefix, mut exec, mut net) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for r in rules {
        let line = format!("  {}", rule_summary(r));
        match (&r.object, r.action) {
            (Object::File(f), Action::FileOpen | Action::FileRead | Action::FileWrite) => {
                match &f.pattern {
                    FilePattern::ExactPath(_) => exact.push(line),
                    FilePattern::Classified(_) => classified.push(line),
                    FilePattern::Prefix(_) => prefix.push(line),
                }
            }
            (Object::Process(_), Action::ProcExec) => exec.push(line),
            (Object::Network(_), _) => net.push(line),
            _ => {}
        }
    }

    let section = |title: &str, lines: &[String]| {
        if lines.is_empty() {
            return;
        }
        println!("\n{} ({}):", title, lines.len());
        for l in lines {
            println!("{l}");
        }
    };
    println!("\n=== COMPILED RULES (what each map entry is built from) ===");
    section("file — exact path (FILE_PATH_POLICY, r/w-aware)", &exact);
    section("file — classified pattern (open-granularity)", &classified);
    section("file — prefix (open-granularity)", &prefix);
    section("exec (EXEC_PATH_POLICY)", &exec);
    section("network (NET_CONNECT_POLICY)", &net);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Parse command-line arguments
    let args = Args::parse();
    
    info!("eBPF Monitoring Tool starting...");

    // Flags that only make sense when the policy pipeline runs.
    if args.enforce.is_none() && args.compile.is_none() {
        if args.no_optimize {
            return Err(anyhow::anyhow!("--no-optimize requires --enforce or --compile"));
        }
        if args.emit_apparmor.is_some() || args.emit_json.is_some() {
            return Err(anyhow::anyhow!("--emit-apparmor/--emit-json require --enforce or --compile"));
        }
        if args.pass_config.is_some() {
            return Err(anyhow::anyhow!("--pass-config requires --enforce or --compile"));
        }
        if args.friction_report {
            return Err(anyhow::anyhow!("--friction-report requires --enforce or --compile"));
        }
        if args.dump_policy {
            return Err(anyhow::anyhow!("--dump-policy requires --enforce or --compile"));
        }
    }

    // Load + validate the (optional) externalized pass config once.
    let pass_config = match args.pass_config.as_deref() {
        Some(path) => {
            let cfg = ebpf_mon_common::policy::PassConfig::from_json_file(path)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            info!("Loaded pass config from {}: {:?}", path, cfg);
            cfg
        }
        None => ebpf_mon_common::policy::PassConfig::default(),
    };

    // --- Compile-only (dry run): run the policy pipeline and report the emitted
    // policy. No container, no kernel, no LSM — so this needs no root. ---
    if let Some(ref profile_path) = args.compile {
        let profile_json = std::fs::read_to_string(profile_path)
            .map_err(|e| anyhow::anyhow!("Failed to read profile '{}': {}", profile_path, e))?;
        let linked = compile_profile(&profile_json, args.no_optimize, &pass_config)?;

        let profile_name = args.name.as_deref().unwrap_or("ebpf-mon");
        emit_outputs(&linked, args.emit_apparmor.as_deref(), args.emit_json.as_deref(), profile_name)?;
        print_rule_breakdown(&linked, args.no_optimize);
        if args.dump_policy {
            dump_policy_rules(&linked);
        }
        if args.friction_report {
            println!();
            print!("{}", ebpf_mon_common::policy::FrictionReport::compute(&linked).render());
        }
        return Ok(());
    }
    
    // Determine container identifier from arguments
    let identifier = if let Some(name) = args.name {
        ContainerIdentifier::Name(name)
    } else if let Some(container_id) = args.container {
        ContainerIdentifier::ContainerId(container_id)
    } else if let Some(cgroup_path) = args.cgroup {
        ContainerIdentifier::CgroupPath(cgroup_path)
    } else {
        // Default: monitor user.slice (no container tracking)
        let default_path = "/sys/fs/cgroup/user.slice".to_string();
        info!("No container specified, using default cgroup path: {}", default_path);
        ContainerIdentifier::CgroupPath(default_path)
    };
    
    // Initialize tracked container
    let tracked_container = TrackedContainer::from_identifier(&identifier)
        .map_err(|e| anyhow::anyhow!("Failed to initialize container tracking: {}", e))?;
    
    // Log startup info
    tracked_container.log_startup_info();
    
    // Print resolved container name prominently
    if let Some(ref name) = tracked_container.name {
        println!("Container Name: {}", name);
    }
    println!("Container ID: {:.12}...", tracked_container.current_id);
    println!("Cgroup ID: {}", tracked_container.current_cgroup_id);
    println!("Restart Tracking: {}", if tracked_container.restart_tracking_enabled { "ENABLED" } else { "DISABLED" });
    
    let cgroup_path = tracked_container.current_cgroup_path.clone();
    info!("Target cgroup: {}", cgroup_path);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(EBPF_BYTES)?;

    // Use container ID from tracked container
    let c_id = if !tracked_container.current_id.is_empty() && tracked_container.current_id != "unknown" {
        Some(tracked_container.current_id.clone())
    } else {
        container::extract_container_id_from_cgroup_path(&cgroup_path)
    };
    let gateways = get_all_container_gateways(c_id.as_ref().unwrap_or(&"".to_string()).as_str()).unwrap_or_default();

    let map = ebpf.take_map("DOCKER_PROXY_IPS").unwrap();
    let mut proxy_ips: HashMap<aya::maps::MapData, u32, u8>= HashMap::try_from(map).unwrap();
    
    for gateway in &gateways {
        let ip_u32 = ipv4_to_u32(gateway);
        proxy_ips.insert(ip_u32, 1, 0)?;
        info!("Tracking docker-proxy gateway: {}", ip_u32);
    }

    let btf = Btf::from_sys_fs()?;

    println!("out_dir: {}", env!("OUT_DIR"));

    // Open the cgroup file
    let cgroup_file = std::fs::File::open(&cgroup_path)
        .map_err(|e| anyhow::anyhow!("Failed to open cgroup '{}': {}", cgroup_path, e))?;
    
    info!("Successfully opened cgroup: {}", cgroup_path);

    // Get cgroup ID from tracked container (already resolved)
    // Use take_map to get ownership, then wrap in Arc<Mutex> for shared access
    let cgroups_map = ebpf.take_map("CGROUPS").unwrap();
    let cgroups: HashMap<aya::maps::MapData, u64, u32> = HashMap::try_from(cgroups_map)?;
    let cgroups_shared = Arc::new(Mutex::new(cgroups));
    
    let cgid: u64 = tracked_container.current_cgroup_id;
    
    // Use Arc<Mutex> for shared access to the current cgroup ID
    let current_cgid = Arc::new(Mutex::new(cgid));
    let current_cgid_for_watcher = current_cgid.clone();

    // Insert initial cgroup ID
    {
        let mut cgroups_guard = cgroups_shared.lock().unwrap();
        cgroups_guard.insert(cgid, 1u32, 0)?;
    }
    info!("Initial cgroup ID: {}", cgid);

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // --- Enforcement pipeline ---
    // Retained across the enforce block so the container watcher can re-apply the
    // policy under a new cgroup id on a restart / cgroup-id change (see below).
    let mut enforce_policy: Option<Arc<Mutex<enforcement::LoadedPolicy>>> = None;
    // Whether the enforcing cgroup_skb egress twin actually loaded. If its
    // verifier check fails on a given kernel, we must NOT abort the whole
    // enforcer (egress is still enforced by the socket_connect LSM hook); we
    // fall back to the monitor-only egress program at the attach site below.
    let mut enforce_egress_loaded = false;
    if let Some(ref profile_path) = args.enforce {
        info!("Loading enforcement profile from: {}", profile_path);

        let cap = enforcement::check_lsm_support()
            .map_err(|e| anyhow::anyhow!("LSM support check failed: {}", e))?;
        if !cap.is_supported() {
            return Err(anyhow::anyhow!(
                "BPF-LSM is not supported on this kernel:\n{}", cap.report()
            ));
        }
        info!("BPF-LSM support confirmed");

        let profile_json = std::fs::read_to_string(profile_path)
            .map_err(|e| anyhow::anyhow!("Failed to read profile '{}': {}", profile_path, e))?;

        let linked = compile_profile(&profile_json, args.no_optimize, &pass_config)?;

        let profile_name = tracked_container.name.as_deref().unwrap_or("ebpf-mon");
        emit_outputs(&linked, args.emit_apparmor.as_deref(), args.emit_json.as_deref(), profile_name)?;
        if args.dump_policy {
            dump_policy_rules(&linked);
        }
        if args.friction_report {
            print!("{}", ebpf_mon_common::policy::FrictionReport::compute(&linked).render());
        }

        enforcement::PolicyLoader::attach_lsm(&mut ebpf, &btf)
            .map_err(|e| anyhow::anyhow!("Failed to attach LSM: {}", e))?;

        // Pre-LOAD the enforcing cgroup_skb egress twin NOW, while the policy
        // maps still live in `ebpf`. It is the only program that references the
        // enforcement maps (NET_CONNECT_POLICY / POLICY_CGROUPS / SKB_ENFORCE_CGID)
        // yet would otherwise load at its natural site far below. load_policy()
        // take_map()s those maps and drops the wrappers on return, CLOSING their
        // fds — so a program relocated to them afterwards is rejected by the
        // verifier ("fd N is not pointing to valid bpf_map"). Loading here commits
        // the relocation (kernel bumps the map refcounts) before that happens;
        // attach still occurs later, after the perf readers are up. The LSM
        // enforce programs are safe for the same reason: attach_lsm loaded them
        // just above. The monitor-only egress/ingress twins never touch these
        // maps, so they keep loading at the normal site.
        if args.enforce.is_some() {
            let prog: &mut CgroupSkb =
                ebpf.program_mut("cgroup_skb_egress_enforce").unwrap().try_into()?;
            // NON-FATAL: a kernel whose verifier rejects this program must not
            // sink the entire enforcer. On failure we keep going and fall back to
            // the monitor egress twin below; the socket_connect LSM hook still
            // enforces egress either way.
            match prog.load() {
                Ok(()) => enforce_egress_loaded = true,
                Err(e) => warn!(
                    "cgroup_skb_egress_enforce failed to load ({e}); packet-level egress \
                     drop disabled — egress still enforced by the socket_connect LSM hook"
                ),
            }
        }

        let loader = enforcement::PolicyLoader::new(args.audit_only);
        let loaded = loader.load_policy(&mut ebpf, &linked, cgid)
            .map_err(|e| anyhow::anyhow!("Failed to load policy: {}", e))?;

        let mode_str = if args.audit_only { "AUDIT-ONLY" } else { "ENFORCING" };
        println!("Enforcement: {} ({} path rules, {} pattern rules, {} exec rules, {} net rules)",
            mode_str, loaded.stats.path_rules, loaded.stats.pattern_rules,
            loaded.stats.exec_path_rules, loaded.stats.net_rules);

        enforce_policy = Some(Arc::new(Mutex::new(loaded)));

        if let Some(audit_map) = ebpf.take_map("AUDIT_EVENTS") {
            tokio::spawn(async move {
                listen_audit_events(audit_map).await;
            });
        }
    }

    // IMPORTANT: open the userspace perf-buffer readers BEFORE attaching any
    // probe. `bpf_perf_event_output(..., BPF_F_CURRENT_CPU)` returns -ENOENT
    // (silent drop, not a "lost" event) whenever the current CPU's slot in the
    // PERF_EVENT_ARRAY has no buffer installed yet. Probe attach can take several
    // seconds (BTF load + verifier), so any event fired in that window would be
    // lost. We spawn the readers, wait until every per-CPU buffer is open, and
    // only then start attaching probes.
    let (tx, rx) = mpsc::channel::<EncodedEvent>(100);
    let events_map = ebpf.take_map("EVENTS").unwrap();
    let export_map: Arc<Mutex<EventMap>> = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let export_map_clone = export_map.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        listen_all_events(events_map, tx, ready_tx).await;
    });
    tokio::spawn(async move {
        simple_event_reader(rx, export_map_clone).await;
    });
    // Block until all per-CPU perf buffers are installed.
    let _ = ready_rx.await;

    let program_vfs_open: &mut FExit = ebpf.program_mut("vfs_open_fexit").unwrap().try_into()?;
    program_vfs_open.load("vfs_open", &btf)?;
    program_vfs_open.attach()?;

    let program_vfs_write: &mut FEntry = ebpf.program_mut("vfs_write_fentry").unwrap().try_into()?;
    program_vfs_write.load("vfs_write", &btf)?;
    program_vfs_write.attach()?;
    
    let program_vfs_write_exit: &mut FExit = ebpf.program_mut("vfs_write_fexit").unwrap().try_into()?;
    program_vfs_write_exit.load("vfs_write", &btf)?;
    program_vfs_write_exit.attach()?;

    let program_vfs_read: &mut FEntry = ebpf.program_mut("vfs_read_fentry").unwrap().try_into()?;
    program_vfs_read.load("vfs_read", &btf)?;
    program_vfs_read.attach()?;

    let program_vfs_read_exit: &mut FExit = ebpf.program_mut("vfs_read_fexit").unwrap().try_into()?;
    program_vfs_read_exit.load("vfs_read", &btf)?;
    program_vfs_read_exit.attach()?;

    let program_security_inode_follow: &mut FEntry = ebpf.program_mut("check_symlink").unwrap().try_into()?;
    program_security_inode_follow.load("security_inode_follow_link", &btf)?;
    program_security_inode_follow.attach()?;

    let program_vfs_iter_write: &mut FEntry = ebpf.program_mut("vfs_iter_write_fentry").unwrap().try_into()?;
    program_vfs_iter_write.load("vfs_iter_write", &btf)?;
    program_vfs_iter_write.attach()?;

    let program_vfs_iter_write_exit: &mut FExit = ebpf.program_mut("vfs_iter_write_fexit").unwrap().try_into()?;
    program_vfs_iter_write_exit.load("vfs_iter_write", &btf)?;
    program_vfs_iter_write_exit.attach()?;

    let program_vfs_iter_read: &mut FEntry = ebpf.program_mut("vfs_iter_read_fentry").unwrap().try_into()?;
    program_vfs_iter_read.load("vfs_iter_read", &btf)?;
    program_vfs_iter_read.attach()?;

    let program_vfs_iter_read_exit: &mut FExit = ebpf.program_mut("vfs_iter_read_fexit").unwrap().try_into()?;
    program_vfs_iter_read_exit.load("vfs_iter_read", &btf)?;
    program_vfs_iter_read_exit.attach()?;

    // Egress: in --enforce mode attach the DROP-capable twin instead of the
    // monitor-only program. The enforcer still inspects + pipes every event
    // (so monitoring is unaffected) but returns the network verdict, dropping
    // connection-initiations to destinations outside the allowlist. In monitor
    // mode we attach the pass-only program as before.
    //
    // In --enforce mode the twin was already LOADED up in the enforcement block
    // (before load_policy took its maps), so here we only attach it. The
    // monitor-only program is loaded + attached here as usual.
    //
    // Fallback: if the enforcing twin failed to verify/load above
    // (enforce_egress_loaded == false), attach the monitor-only egress instead so
    // we keep network VISIBILITY. Egress DROP is still done by socket_connect, so
    // enforcement correctness is preserved; only packet-level egress drop is lost.
    let egress_prog_name = if args.enforce.is_some() && enforce_egress_loaded {
        "cgroup_skb_egress_enforce"
    } else {
        "cgroup_skb_egress"
    };
    let program_net_eg: &mut CgroupSkb = ebpf.program_mut(egress_prog_name).unwrap().try_into()?;
    // The enforcing twin is pre-loaded; the monitor twin (used in monitor mode OR
    // as the enforce fallback) still needs loading here.
    if egress_prog_name == "cgroup_skb_egress" {
        program_net_eg.load()?;
    }
    // Use Single (flags=0). On kernels >= 5.7 aya attaches via bpf_link_create,
    // where cgroup link attach REQUIRES link_create.flags == 0 (BPF_F_ALLOW_MULTI
    // yields EINVAL). Link-based attach already coexists with other links, so this
    // is non-displacing despite the "Single" name.
    //
    // NON-FATAL: `bpf_link_create` on a cgroup can fail with ENOENT if the
    // container's cgroup churned (e.g. the app crashed/restarted under a too-tight
    // profile) between opening `cgroup_file` and here. That must NOT tear down the
    // whole enforcer: the LSM file/exec/net hooks are already attached above, and
    // egress is independently enforced by the socket_connect LSM hook, so a failed
    // cgroup_skb attach only costs packet-level egress drop + network monitoring.
    if let Err(e) = program_net_eg.attach(&cgroup_file, aya::programs::CgroupSkbAttachType::Egress, aya::programs::CgroupAttachMode::Single) {
        warn!("cgroup_skb egress attach failed ({e}); continuing without packet-level egress \
               (LSM enforcement stays active; egress still enforced via socket_connect)");
    }

    let program_net_ig: &mut CgroupSkb = ebpf.program_mut("cgroup_skb_ingress").unwrap().try_into()?;
    program_net_ig.load()?;
    if let Err(e) = program_net_ig.attach(&cgroup_file, aya::programs::CgroupSkbAttachType::Ingress, aya::programs::CgroupAttachMode::Single) {
        warn!("cgroup_skb ingress attach failed ({e}); continuing without ingress network monitoring");
    }
    let proxy_accept_prog: &mut FExit = ebpf.program_mut("docker_proxy_accept").unwrap().try_into()?;
    proxy_accept_prog.load("inet_accept", &btf)?;
    proxy_accept_prog.attach()?;

    let proxy_connect_prog: &mut FExit = ebpf.program_mut("docker_proxy_connect").unwrap().try_into()?;
    proxy_connect_prog.load("tcp_v4_connect", &btf)?;
    proxy_connect_prog.attach()?;

    let program_execve: &mut TracePoint = ebpf.program_mut("execve_tracepoint").unwrap().try_into()?;
    program_execve.load()?;
    program_execve.attach("syscalls", "sys_enter_execve")?;

    let program_execveat: &mut TracePoint = ebpf.program_mut("execveat_tracepoint").unwrap().try_into()?;
    program_execveat.load()?;
    program_execveat.attach("syscalls", "sys_enter_execveat")?;

    let program_execve: &mut TracePoint = ebpf.program_mut("exit_execve_tracepoint").unwrap().try_into()?;
    program_execve.load()?;
    program_execve.attach("syscalls", "sys_exit_execve")?;

    let program_execveat: &mut TracePoint = ebpf.program_mut("exit_execveat_tracepoint").unwrap().try_into()?;
    program_execveat.load()?;
    program_execveat.attach("syscalls", "sys_exit_execveat")?;
    
    let program_fork: &mut BtfTracePoint = ebpf.program_mut("fork_tracepoint").unwrap().try_into()?;
    program_fork.load("sched_process_fork", &btf)?;
    program_fork.attach()?;

    // Definitive readiness sentinel: every program is now loaded and attached.
    // The demo launcher (docs/demo/lib.sh::start_enforce) waits for THIS line
    // rather than the earlier "Enforcement:" banner, which prints before the
    // attach sequence and so cannot detect a late attach failure.
    println!("READY: all eBPF programs attached; monitoring/enforcement active");

    // Start container watcher if restart tracking is enabled
    let watcher_stop_flag = if tracked_container.restart_tracking_enabled {
        if let Some(ref container_name) = tracked_container.name {
            info!("Starting container watcher for '{}'", container_name);
            
            let (state_rx, stop_flag) = ContainerWatcher::start(
                container_name.clone(),
                tracked_container.current_id.clone(),
                tracked_container.current_cgroup_id,
            );
            
            // Clone the shared cgroups map for the watcher task
            let cgroups_for_watcher = cgroups_shared.clone();
            // Enforcement maps travel with the workload too: on a cgroup-id change
            // we must re-apply the policy under the new id, or the moved container
            // runs in a cgroup POLICY_CGROUPS doesn't know and every LSM hook fails
            // open (monitoring follows via cgroups_for_watcher, enforcement would not).
            let enforce_policy_for_watcher = enforce_policy.clone();
            
            // Spawn a tokio task to handle container state changes
            let current_cgid_clone = current_cgid_for_watcher.clone();
            tokio::spawn(async move {
                loop {
                    // Check for state changes from the watcher (non-blocking)
                    match state_rx.try_recv() {
                        Ok(state_change) => {
                            match state_change {
                                ContainerStateChange::Stopped => {
                                    warn!("Container stopped - waiting for restart...");
                                }
                                ContainerStateChange::Started { container_id, cgroup_id, cgroup_path } => {
                                    let mut old_cgid = current_cgid_clone.lock().unwrap();
                                    
                                    if cgroup_id != *old_cgid {
                                        info!("=== Container Restart Detected ===");
                                        info!("  New Container ID: {:.12}...", container_id);
                                        info!("  Old Cgroup ID: {}", *old_cgid);
                                        info!("  New Cgroup ID: {}", cgroup_id);
                                        info!("  New Cgroup Path: {}", cgroup_path);
                                        
                                        // Update eBPF cgroup map
                                        let mut cgroups_guard = cgroups_for_watcher.lock().unwrap();
                                        
                                        // Remove old cgroup ID from eBPF map
                                        if let Err(e) = cgroups_guard.remove(&*old_cgid) {
                                            warn!("Failed to remove old cgroup ID {}: {:?}", *old_cgid, e);
                                        }
                                        
                                        // Insert new cgroup ID into eBPF map
                                        if let Err(e) = cgroups_guard.insert(cgroup_id, 1u32, 0) {
                                            error!("Failed to insert new cgroup ID {}: {:?}", cgroup_id, e);
                                        } else {
                                            info!("eBPF cgroup filter updated: {} -> {}", *old_cgid, cgroup_id);
                                        }
                                        
                                        drop(cgroups_guard);

                                        // Enforcement-side twin of the monitor
                                        // filter update: re-apply the policy under
                                        // the new cgroup id so the LSM hooks keep
                                        // enforcing the moved workload.
                                        if let Some(ref pol) = enforce_policy_for_watcher {
                                            match pol.lock().unwrap().rebind(*old_cgid, cgroup_id) {
                                                Ok(()) => {}
                                                Err(e) => error!(
                                                    "Failed to rebind enforcement {} -> {}: {}",
                                                    *old_cgid, cgroup_id, e
                                                ),
                                            }
                                        }

                                        *old_cgid = cgroup_id;
                                        info!("===================================");
                                    }
                                }
                                ContainerStateChange::Error(msg) => {
                                    if msg.contains("was removed") {
                                        info!("Container was removed, watcher exiting");
                                    } else {
                                        error!("Container watcher error: {}", msg);
                                    }
                                    break;
                                }
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            // No messages, continue
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            break;
                        }
                    }
                    
                    // Small sleep to avoid busy-waiting
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            });
            
            Some(stop_flag)
        } else {
            warn!("Container name not available, restart tracking disabled");
            None
        }
    } else {
        None
    };

    // Keep ebpf and cgroups map alive for the duration of the program
    let _keep_alive = (ebpf, cgroups_shared);

    // Spawn a task to periodically export events to JSON
    let export_map_summary = export_map.clone();
    let current_cgid_for_export = current_cgid.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let cgid = *current_cgid_for_export.lock().unwrap();
            if let Err(e) = export_events_to_json(&export_map_summary, "events.json", cgid) {
                eprintln!("Failed to export events to JSON: {}", e);
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    println!("Events will be exported to JSON every 5 seconds...");
    if tracked_container.restart_tracking_enabled {
        println!("Container restart tracking: ENABLED");
    }

    ctrl_c.await?;
    println!("Exiting...");
    
    // Stop the container watcher if running
    if let Some(stop_flag) = watcher_stop_flag {
        stop_flag.store(true, Ordering::Relaxed);
        info!("Container watcher stopped");
    }
    
    // Also print to console with prominent formatting
    println!("\n\n");
    println!("################################################################################");
    println!("###                          FINAL SUMMARY                                  ###");
    println!("################################################################################");
    if args.enforce.is_none() {
        let final_cgid = *current_cgid.lock().unwrap();
        if let Err(e) = export_events_to_json(&export_map, "final-events.json", final_cgid) {
            eprintln!("Failed to export final events to JSON: {}", e);
        }
        println!("### JSON events exported to final-events.json and text summary saved     ###");
    } else {
        println!("### Enforcement mode — profile not overwritten                           ###");
    }
    println!("################################################################################");

    Ok(())
}

fn ipv4_to_u32(ip: &str) -> u32 {
    let parts: Vec<u8> = ip.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    
    // Store in REVERSED order to match eBPF
    // 172.18.0.1 -> store as 1.0.18.172
    u32::from_le_bytes([parts[0], parts[1], parts[2], parts[3]])
}

pub fn get_container_gateway_ip(container_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Inspect the container
    let inspect_output = Command::new("docker")
        .args(&["inspect", container_id])
        .output()?;
    
    let json: Value = serde_json::from_slice(&inspect_output.stdout)?;
    
    // Get the network the container is connected to
    if let Some(networks) = json[0]["NetworkSettings"]["Networks"].as_object() {
        // Container can be on multiple networks, get all gateways
        for (network_name, network_info) in networks {
            if let Some(gateway) = network_info["Gateway"].as_str() {
                info!("Container {} on network '{}' with gateway: {}", 
                         container_id, network_name, gateway);
                return Ok(gateway.to_string());
            }
        }
    }
    
    Err("No gateway found for container".into())
}

// Get ALL gateways if container is on multiple networks
pub fn get_all_container_gateways(container_id: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let inspect_output = Command::new("docker")
        .args(&["inspect", container_id])
        .output()?;
    
    let json: Value = serde_json::from_slice(&inspect_output.stdout)?;
    let mut gateways = Vec::new();
    
    if let Some(networks) = json[0]["NetworkSettings"]["Networks"].as_object() {
        for (network_name, network_info) in networks {
            if let Some(gateway) = network_info["Gateway"].as_str() {
                info!("Network '{}' -> Gateway: {}", network_name, gateway);
                gateways.push(gateway.to_string());
            }
        }
    }
    
    Ok(gateways)
}

async fn listen_audit_events(audit_map: aya::maps::Map) {
    use aya::maps::AsyncPerfEventArray;
    use aya::util::online_cpus;
    use bytes::BytesMut;

    let mut perf_array = match AsyncPerfEventArray::try_from(audit_map) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to open AUDIT_EVENTS perf array: {}", e);
            return;
        }
    };

    let cpus = match online_cpus() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get online CPUs for audit reader: {:?}", e);
            return;
        }
    };

    for cpu_id in cpus {
        let buf = match perf_array.open(cpu_id, Some(64)) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to open audit perf buffer for CPU {}: {}", cpu_id, e);
                continue;
            }
        };

        tokio::spawn(async move {
            read_audit_cpu(buf).await;
        });
    }
}

async fn read_audit_cpu(mut buf: aya::maps::perf::AsyncPerfEventArrayBuffer<aya::maps::MapData>) {
    use bytes::BytesMut;

    let mut buffers: Vec<BytesMut> = (0..10)
        .map(|_| BytesMut::with_capacity(256))
        .collect();

    loop {
        match buf.read_events(&mut buffers).await {
            Ok(events) => {
                for i in 0..events.read {
                    let data = &buffers[i];
                    if data.len() >= 20 {
                        let cgroup_id = u64::from_ne_bytes(data[0..8].try_into().unwrap_or([0; 8]));
                        let path_hash = u64::from_ne_bytes(data[8..16].try_into().unwrap_or([0; 8]));
                        let pattern = data[16];
                        let action = data[17];
                        let verdict = data[18];
                        let verdict_str = match verdict {
                            0 => "DENY",
                            1 => "ALLOW",
                            2 => "AUDIT",
                            _ => "UNKNOWN",
                        };
                        let action_str = match action {
                            0 => "file_open",
                            3 => "net_connect",
                            5 => "proc_exec",
                            _ => "unknown",
                        };
                        warn!(
                            "ENFORCEMENT {}: {} path_hash={:#x} pattern={} cgroup={}",
                            verdict_str, action_str, path_hash, pattern, cgroup_id
                        );
                    }
                }
            }
            Err(e) => {
                error!("Audit perf read error: {}", e);
                break;
            }
        }
    }
}
