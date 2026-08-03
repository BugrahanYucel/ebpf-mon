use aya::maps::HashMap;
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use log::{info, warn};

use ebpf_mon_common::policy::{
    ACCESS_READ, ACCESS_WRITE, Action, BehaviorRule, BinaryRef, FilePattern,
    NetPolicyKey, NetworkObject, Object, PathPolicyKey, PatternKey,
    PolicyConfig, PrefixEntry, Verdict, PREFIX_MAX_LEN,
    fnv1a_hash_bytes,
};

pub struct PolicyLoader {
    audit_only: bool,
}

/// Build the BPF-LSM network map key for a rule.
///
/// `protocol` is forced to 0 to match the `socket_connect` hook, whose lookup key
/// hard-codes `protocol: 0` (it does not read `sk_protocol`). If this key carried
/// the IR's real protocol (e.g. 6 for TCP), every kernel lookup would miss and
/// the connection would be wrongly default-denied. Callers must ensure
/// `net_obj.dst_ip` is `Some` before calling.
fn net_policy_key(cgroup_id: u64, net_obj: &NetworkObject) -> NetPolicyKey {
    NetPolicyKey {
        cgroup_id,
        dst_ip: net_obj.dst_ip.unwrap_or(0),
        dst_port: net_obj.dst_port.unwrap_or(0),
        protocol: 0,
        _pad: [0u8; 7],
    }
}

impl PolicyLoader {
    pub fn new(audit_only: bool) -> Self {
        PolicyLoader { audit_only }
    }

    /// Take ownership of every enforcement map, apply `rules` for `cgroup_id`,
    /// and RETURN the retained handles as a `LoadedPolicy`. The handles are kept
    /// alive (not dropped) so the container watcher can re-apply the policy under
    /// a new cgroup id on a restart / cgroup-id change — otherwise enforcement
    /// silently stops for the moved workload while monitoring follows it.
    pub fn load_policy(
        &self,
        ebpf: &mut Ebpf,
        rules: &[BehaviorRule],
        cgroup_id: u64,
    ) -> Result<LoadedPolicy, Box<dyn std::error::Error>> {
        // --- Take (and retain) every enforcement map ---
        let cgroups: HashMap<aya::maps::MapData, u64, PolicyConfig> = HashMap::try_from(
            ebpf.take_map("POLICY_CGROUPS").ok_or("POLICY_CGROUPS map not found")?,
        )?;
        let skb_cgid = match ebpf.take_map("SKB_ENFORCE_CGID") {
            Some(m) => Some(aya::maps::Array::try_from(m)?),
            None => None,
        };
        let file_paths: HashMap<aya::maps::MapData, PathPolicyKey, u8> = HashMap::try_from(
            ebpf.take_map("FILE_PATH_POLICY").ok_or("FILE_PATH_POLICY map not found")?,
        )?;
        let file_patterns: HashMap<aya::maps::MapData, PatternKey, u8> = HashMap::try_from(
            ebpf.take_map("FILE_PATTERN_POLICY").ok_or("FILE_PATTERN_POLICY map not found")?,
        )?;
        let file_prefixes: HashMap<aya::maps::MapData, u64, PrefixEntry> = HashMap::try_from(
            ebpf.take_map("FILE_PREFIX_POLICY").ok_or("FILE_PREFIX_POLICY map not found")?,
        )?;
        let exec_paths: HashMap<aya::maps::MapData, PathPolicyKey, u8> = HashMap::try_from(
            ebpf.take_map("EXEC_PATH_POLICY").ok_or("EXEC_PATH_POLICY map not found")?,
        )?;
        // EXEC_PATTERN_POLICY is taken to keep it out of `ebpf` (parity with the
        // old loader) but is not populated yet.
        let _exec_patterns: HashMap<aya::maps::MapData, PatternKey, u8> = HashMap::try_from(
            ebpf.take_map("EXEC_PATTERN_POLICY").ok_or("EXEC_PATTERN_POLICY map not found")?,
        )?;
        let net_rules: HashMap<aya::maps::MapData, NetPolicyKey, u8> = HashMap::try_from(
            ebpf.take_map("NET_CONNECT_POLICY").ok_or("NET_CONNECT_POLICY map not found")?,
        )?;

        let mut loaded = LoadedPolicy {
            audit_only: self.audit_only,
            rules: rules.to_vec(),
            stats: PolicyStats::default(),
            cgroups,
            skb_cgid,
            file_paths,
            file_patterns,
            file_prefixes,
            exec_paths,
            net_rules,
        };

        let stats = loaded.bind(cgroup_id)?;
        info!(
            "Policy loaded: {} file-path, {} file-pattern, {} file-prefix, \
             {} exec-path, {} net rules, {} cgroups ({} skipped)",
            stats.path_rules, stats.pattern_rules, stats.prefix_rules,
            stats.exec_path_rules, stats.net_rules, stats.cgroups_configured,
            stats.skipped_prefix + stats.skipped_non_file,
        );
        loaded.stats = stats;
        Ok(loaded)
    }

    pub fn attach_lsm(
        ebpf: &mut Ebpf,
        btf: &Btf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // File enforcement
        info!("Loading LSM enforce_file_open...");
        let file_prog: &mut Lsm = ebpf
            .program_mut("enforce_file_open")
            .ok_or("enforce_file_open LSM program not found")?
            .try_into()?;
        file_prog.load("file_open", btf)?;
        file_prog.attach()?;
        info!("LSM enforce_file_open attached");

        // Process execution enforcement
        info!("Loading LSM enforce_bprm_check...");
        let exec_prog: &mut Lsm = ebpf
            .program_mut("enforce_bprm_check")
            .ok_or("enforce_bprm_check LSM program not found")?
            .try_into()?;
        exec_prog.load("bprm_check_security", btf)?;
        exec_prog.attach()?;
        info!("LSM enforce_bprm_check attached");

        // Network connect enforcement
        info!("Loading LSM enforce_socket_connect...");
        let net_prog: &mut Lsm = ebpf
            .program_mut("enforce_socket_connect")
            .ok_or("enforce_socket_connect LSM program not found")?
            .try_into()?;
        net_prog.load("socket_connect", btf)?;
        net_prog.attach()?;
        info!("LSM enforce_socket_connect attached");

        Ok(())
    }
}

/// Retained enforcement map handles + the compiled rules, so the policy can be
/// re-applied under a new cgroup id when the container restarts / its cgroup id
/// changes. Held alive for the process lifetime and shared with the container
/// watcher (behind a mutex). Dropping it closes the maps (ends enforcement).
pub struct LoadedPolicy {
    audit_only: bool,
    rules: Vec<BehaviorRule>,
    pub stats: PolicyStats,
    cgroups: HashMap<aya::maps::MapData, u64, PolicyConfig>,
    skb_cgid: Option<aya::maps::Array<aya::maps::MapData, u64>>,
    file_paths: HashMap<aya::maps::MapData, PathPolicyKey, u8>,
    file_patterns: HashMap<aya::maps::MapData, PatternKey, u8>,
    file_prefixes: HashMap<aya::maps::MapData, u64, PrefixEntry>,
    exec_paths: HashMap<aya::maps::MapData, PathPolicyKey, u8>,
    net_rules: HashMap<aya::maps::MapData, NetPolicyKey, u8>,
}

impl LoadedPolicy {
    /// Apply every rule for `cgroup_id` into the kernel maps. Disjoint field
    /// borrows let the rule loop read `self.rules` while writing the map fields.
    fn bind(&mut self, cgroup_id: u64) -> Result<PolicyStats, Box<dyn std::error::Error>> {
        Self::apply_rules(
            cgroup_id,
            self.audit_only,
            &self.rules,
            &mut self.cgroups,
            self.skb_cgid.as_mut(),
            &mut self.file_paths,
            &mut self.file_patterns,
            &mut self.file_prefixes,
            &mut self.exec_paths,
            &mut self.net_rules,
        )
    }

    /// Re-apply the whole policy under `new_cgroup_id` after a container restart /
    /// cgroup-id change, and drop the old cgroup from the LSM allowlist. This is
    /// the enforcement-side twin of the monitor's cgroup-filter update: without it
    /// the moved workload runs in a cgroup that `POLICY_CGROUPS` doesn't know, so
    /// every hook fails open and enforcement silently stops.
    pub fn rebind(
        &mut self,
        old_cgroup_id: u64,
        new_cgroup_id: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stats = self.bind(new_cgroup_id)?;
        // Remove the dead cgroup from the small (64-entry) allowlist so repeated
        // restarts can't fill it. The large per-path/exec/net maps are keyed by
        // (cgid, ..); their stale old-cgid entries never match again and are left
        // to be overwritten, keeping this path allocation-free.
        let _ = self.cgroups.remove(&old_cgroup_id);
        self.stats = PolicyStats { cgroups_configured: 1, ..PolicyStats::default() };
        info!(
            "Enforcement rebound {} -> {} ({} path, {} pattern, {} prefix, {} exec, {} net rules re-applied)",
            old_cgroup_id, new_cgroup_id,
            stats.path_rules, stats.pattern_rules, stats.prefix_rules,
            stats.exec_path_rules, stats.net_rules,
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_rules(
        cgroup_id: u64,
        audit_only: bool,
        rules: &[BehaviorRule],
        cgroups: &mut HashMap<aya::maps::MapData, u64, PolicyConfig>,
        skb_cgid: Option<&mut aya::maps::Array<aya::maps::MapData, u64>>,
        file_paths: &mut HashMap<aya::maps::MapData, PathPolicyKey, u8>,
        file_patterns: &mut HashMap<aya::maps::MapData, PatternKey, u8>,
        file_prefixes: &mut HashMap<aya::maps::MapData, u64, PrefixEntry>,
        exec_paths: &mut HashMap<aya::maps::MapData, PathPolicyKey, u8>,
        net_rules: &mut HashMap<aya::maps::MapData, NetPolicyKey, u8>,
    ) -> Result<PolicyStats, Box<dyn std::error::Error>> {
        let mut stats = PolicyStats::default();

        // --- Global cgroup config ---
        let config = PolicyConfig {
            default_action: 0, // default deny (allowlist model)
            audit_only: if audit_only { 1 } else { 0 },
            _pad: [0u8; 6],
        };
        cgroups.insert(cgroup_id, config, 0)?;
        stats.cgroups_configured += 1;

        // Publish the enforced cgroup id for the cgroup_skb egress enforcer,
        // which runs in softirq context and cannot reliably read it itself.
        if let Some(skb_cgid) = skb_cgid {
            skb_cgid.set(0, cgroup_id, 0)?;
        }

        let mut prefix_slot: u64 = 0;

        for rule in rules {
            let verdict_val = verdict_to_u8(&rule.verdict);

            match (&rule.object, &rule.action) {
                // File rules (FileOpen / FileRead / FileWrite)
                (Object::File(file_obj), Action::FileOpen | Action::FileRead | Action::FileWrite) => {
                    match &file_obj.pattern {
                        FilePattern::ExactPath(path) => {
                            let path_hash = fnv1a_hash_bytes(path.as_bytes());
                            let key = PathPolicyKey { cgroup_id, path_hash };
                            // The value is an access-mode MASK, not a bare
                            // verdict: OR in the mode this rule permits so a
                            // file seen both read and written ends up rw. This
                            // is what lets security_file_open deny a write to a
                            // read-only path. An explicit deny clears to 0.
                            let bit = match rule.action {
                                Action::FileWrite => ACCESS_WRITE,
                                // FileRead or a generic/exec-implied open → read
                                _ => ACCESS_READ,
                            };
                            let new_val = if rule.verdict == Verdict::Allow {
                                file_paths.get(&key, 0).unwrap_or(0) | bit
                            } else {
                                0
                            };
                            file_paths.insert(key, new_val, 0)?;
                            stats.path_rules += 1;
                        }
                        FilePattern::Classified(pattern) => {
                            // Normalize action to FileOpen (0) because
                            // security_file_open is the single LSM hook that
                            // guards all file operations. The eBPF side always
                            // looks up with action=0.
                            let key = PatternKey {
                                cgroup_id,
                                pattern: *pattern as u8,
                                action: 0, // FileOpen — matches eBPF lookup key
                                _pad: [0u8; 6],
                            };
                            file_patterns.insert(key, verdict_val, 0)?;
                            stats.pattern_rules += 1;
                        }
                        FilePattern::Prefix(prefix) => {
                            if prefix_slot < 64 {
                                let mut entry = PrefixEntry {
                                    prefix: [0u8; PREFIX_MAX_LEN],
                                    prefix_len: 0,
                                    verdict: verdict_val,
                                    _pad: [0u8; 3],
                                };
                                let bytes = prefix.as_bytes();
                                let copy_len = bytes.len().min(PREFIX_MAX_LEN);
                                entry.prefix[..copy_len].copy_from_slice(&bytes[..copy_len]);
                                entry.prefix_len = copy_len as u32;

                                let key = (cgroup_id << 8) | prefix_slot;
                                file_prefixes.insert(key, entry, 0)?;
                                prefix_slot += 1;
                                stats.prefix_rules += 1;
                            } else {
                                warn!("Prefix slot limit reached, skipping: {}", prefix);
                                stats.skipped_prefix += 1;
                            }
                        }
                    }
                }

                // Exec rules
                (Object::Process(proc_obj), Action::ProcExec) => {
                    match &proc_obj.binary {
                        BinaryRef::Path(path) => {
                            let path_hash = fnv1a_hash_bytes(path.as_bytes());
                            let key = PathPolicyKey { cgroup_id, path_hash };
                            exec_paths.insert(key, verdict_val, 0)?;
                            stats.exec_path_rules += 1;
                        }
                        BinaryRef::Comm(_) => {
                            stats.skipped_non_file += 1;
                        }
                    }
                }

                // Network rules
                (Object::Network(net_obj), Action::NetConnect) => {
                    if net_obj.dst_ip.is_some() {
                        let key = net_policy_key(cgroup_id, net_obj);
                        net_rules.insert(key, verdict_val, 0)?;
                        stats.net_rules += 1;
                    } else {
                        stats.skipped_non_file += 1;
                    }
                }

                _ => {
                    stats.skipped_non_file += 1;
                }
            }
        }

        // Expand pattern categories: if ANY variant in a virtual-fs
        // category was observed, whitelist ALL siblings. This handles
        // files opened by the container runtime (runc) that may not
        // have been exercised during profiling.
        use ebpf_mon_common::fs::PathPattern;
        let category_groups: &[&[u8]] = &[
            // /proc global: /proc/filesystems, /proc/sys/**, /proc/net/*
            &[PathPattern::ProcGlobal as u8, PathPattern::ProcGlobalSys as u8, PathPattern::ProcGlobalNet as u8],
            // /proc/PID (non-sensitive only)
            &[
                PathPattern::ProcPidCmdline as u8, PathPattern::ProcPidComm as u8,
                PathPattern::ProcPidCwd as u8, PathPattern::ProcPidExe as u8,
                PathPattern::ProcPidFd as u8, PathPattern::ProcPidMountinfo as u8,
                PathPattern::ProcPidMounts as u8, PathPattern::ProcPidNet as u8,
                PathPattern::ProcPidNs as u8, PathPattern::ProcPidStat as u8,
                PathPattern::ProcPidStatus as u8, PathPattern::ProcPidTask as u8,
                PathPattern::ProcPidCgroup as u8, PathPattern::ProcPidOther as u8,
                PathPattern::ProcSelf as u8,
            ],
            // /sys/**
            &[PathPattern::SysCgroupDocker as u8, PathPattern::SysCgroupOther as u8,
              PathPattern::SysClassNet as u8, PathPattern::SysOther as u8],
            // /run/**
            &[PathPattern::RunDocker as u8, PathPattern::RunUser as u8, PathPattern::RunOther as u8],
            // /dev/*
            &[PathPattern::DevPts as u8, PathPattern::DevShm as u8, PathPattern::DevOther as u8],
            // /tmp/**
            &[PathPattern::TmpRandom as u8, PathPattern::TmpOther as u8],
        ];

        for group in category_groups {
            let any_present = group.iter().any(|&pat| {
                let key = PatternKey { cgroup_id, pattern: pat, action: 0, _pad: [0u8; 6] };
                file_patterns.get(&key, 0).is_ok()
            });
            if any_present {
                for &pat in *group {
                    let key = PatternKey { cgroup_id, pattern: pat, action: 0, _pad: [0u8; 6] };
                    if file_patterns.get(&key, 0).is_err() {
                        file_patterns.insert(key, 1, 0)?; // allow
                        stats.pattern_rules += 1;
                    }
                }
            }
        }

        Ok(stats)
    }
}

#[derive(Debug, Default)]
pub struct PolicyStats {
    pub cgroups_configured: usize,
    pub path_rules: usize,
    pub pattern_rules: usize,
    pub prefix_rules: usize,
    pub exec_path_rules: usize,
    pub net_rules: usize,
    pub skipped_prefix: usize,
    pub skipped_non_file: usize,
}

fn verdict_to_u8(v: &Verdict) -> u8 {
    match v {
        Verdict::Deny => 0,
        Verdict::Allow => 1,
        Verdict::Audit => 2,
    }
}

fn action_to_u8(action: &ebpf_mon_common::policy::Action) -> u8 {
    action.to_policy_action() as u8
}

pub fn check_lsm_support() -> Result<LsmCapability, std::string::String> {
    let mut cap = LsmCapability {
        config_bpf_lsm: false,
        lsm_boot_param: false,
        btf_available: false,
    };

    if let Ok(config) = std::fs::read_to_string("/proc/config.gz")
        .or_else(|_| std::fs::read_to_string("/boot/config-".to_string()
            + &get_kernel_release().unwrap_or_default()))
    {
        cap.config_bpf_lsm = config.contains("CONFIG_BPF_LSM=y");
    }

    if let Ok(lsm_list) = std::fs::read_to_string("/sys/kernel/security/lsm") {
        cap.lsm_boot_param = lsm_list.contains("bpf");
    }

    cap.btf_available = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();

    Ok(cap)
}

#[derive(Debug)]
pub struct LsmCapability {
    pub config_bpf_lsm: bool,
    pub lsm_boot_param: bool,
    pub btf_available: bool,
}

impl LsmCapability {
    pub fn is_supported(&self) -> bool {
        self.lsm_boot_param && self.btf_available
    }

    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "CONFIG_BPF_LSM: {}",
            if self.config_bpf_lsm { "yes" } else { "unknown/no" }
        ));
        lines.push(format!(
            "LSM boot param (bpf): {}",
            if self.lsm_boot_param { "yes" } else { "no" }
        ));
        lines.push(format!(
            "BTF available: {}",
            if self.btf_available { "yes" } else { "no" }
        ));
        lines.push(format!(
            "Overall: {}",
            if self.is_supported() { "SUPPORTED" } else { "NOT SUPPORTED" }
        ));
        lines.join("\n")
    }
}

fn get_kernel_release() -> Option<String> {
    let output = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::net_policy_key;
    use ebpf_mon_common::policy::NetworkObject;

    /// Regression for the network-enforcement protocol bug: the loader used to
    /// write the IR's real protocol (6 for TCP) while the kernel's socket_connect
    /// hook looks up with protocol=0, so every TCP rule missed and the connection
    /// was wrongly denied. The loader's key protocol MUST be 0 to match the hook.
    #[test]
    fn net_key_protocol_is_always_zero_to_match_hook() {
        let tcp = NetworkObject {
            dst_ip: Some(0x0403_0201), // 1.2.3.4 in the enforcement (from_le_bytes) convention
            dst_port: Some(443),
            protocol: Some(6), // TCP — must NOT leak into the key
            direction: Some(1),
        };
        let key = net_policy_key(42, &tcp);
        assert_eq!(key.protocol, 0, "key protocol must be 0 or the kernel lookup misses");
        assert_eq!(key.dst_ip, 0x0403_0201, "dst_ip must pass through unchanged");
        assert_eq!(key.dst_port, 443, "dst_port must pass through unchanged");
        assert_eq!(key.cgroup_id, 42);
        assert_eq!(key._pad, [0u8; 7], "pad must be zeroed for key equality with the hook");
    }

    /// A UDP rule to the same endpoint produces an identical key (protocol is not
    /// discriminating today) — documents the known limitation, not a bug.
    #[test]
    fn net_key_is_protocol_agnostic() {
        let base = NetworkObject { dst_ip: Some(7), dst_port: Some(53), protocol: Some(6), direction: Some(1) };
        let udp = NetworkObject { protocol: Some(17), ..base.clone() };
        assert_eq!(net_policy_key(1, &base), net_policy_key(1, &udp));
    }
}
