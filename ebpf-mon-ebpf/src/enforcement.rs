use aya_ebpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};

use ebpf_mon_common::{
    alloc,
    co_re::{self, core_read_kernel, r#gen, task_struct},
    fs::{PathPattern, classify_path},
    path::MAX_PATH_DEPTH,
    policy::{InodeKey, NetPolicyKey, PathPolicyKey, PatternKey, PolicyConfig, PrefixEntry},
};

#[map]
static POLICY_CGROUPS: HashMap<u64, PolicyConfig> = HashMap::with_max_entries(64, 0);

#[map]
static FILE_PATH_POLICY: HashMap<PathPolicyKey, u8> = HashMap::with_max_entries(65536, 0);

#[map]
static FILE_PATTERN_POLICY: HashMap<PatternKey, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static AUDIT_EVENTS: aya_ebpf::maps::PerfEventByteArray = aya_ebpf::maps::PerfEventByteArray::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuditEvent {
    pub cgroup_id: u64,
    pub path_hash: u64,
    pub pattern: u8,
    pub action: u8,
    pub verdict: u8,
    pub _pad: u8,
}

// ═══════════════════════════════════════════════════════════════════
// File enforcement: security_file_open
//
// The #[lsm] macro generates a nested inner function that LLVM refuses
// to inline for large bodies, creating an empty stub in lsm/* that
// aya cannot resolve. We bypass the macro with manual link_section.
// ═══════════════════════════════════════════════════════════════════

#[no_mangle]
#[link_section = "lsm/file_open"]
pub fn enforce_file_open(ctx: *mut ::core::ffi::c_void) -> i32 {
    let ctx = LsmContext::new(ctx);

    let ts = unsafe { task_struct::current() };
    let cgid = match unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) } {
        Some(id) => id,
        None => return 0,
    };

    let config = match unsafe { POLICY_CGROUPS.get(&cgid) } {
        Some(cfg) => *cfg,
        None => return 0,
    };

    let file = unsafe { co_re::file::from_ptr(ctx.arg::<*const gen::file>(0)) };

    // Resolve path from dentry chain — single source of truth
    if alloc::init().is_err() {
        return 0;
    }
    let path_buf = match alloc::alloc_zero::<ebpf_mon_common::path::Path>() {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let _ = unsafe { path_buf.core_resolve_file(&file, MAX_PATH_DEPTH) };

    let path_hash = path_buf.hash_path();

    // Tier 1: Exact path match via hash
    let path_key = PathPolicyKey { cgroup_id: cgid, path_hash };
    if let Some(verdict) = unsafe { FILE_PATH_POLICY.get(&path_key) } {
        let v = *verdict;
        if config.audit_only != 0 && v == 0 {
            emit_audit(&ctx, cgid, path_hash, PathPattern::Regular as u8, 0, v, Some(path_buf));
            return 0;
        }
        return verdict_to_rc(v);
    }

    // Tier 2: Path classification (pattern-based)
    let classify_buf = path_buf.to_classify_buffer();
    let ns_tgid = unsafe { ts.ns_tgid() }.unwrap_or(0);
    let (pattern, _, _) = unsafe { classify_path(&classify_buf, ns_tgid) };

    if pattern != PathPattern::Regular {
        let pattern_key = PatternKey {
            cgroup_id: cgid,
            pattern: pattern as u8,
            action: 0,
            _pad: [0u8; 6],
        };
        if let Some(verdict) = unsafe { FILE_PATTERN_POLICY.get(&pattern_key) } {
            let v = *verdict;
            if config.audit_only != 0 && v == 0 {
                emit_audit(&ctx, cgid, path_hash, pattern as u8, 0, v, Some(path_buf));
                return 0;
            }
            return verdict_to_rc(v);
        }
    }

    // Tier 3: Prefix matching
    if let Some(rc) = check_prefix_match(&ctx, &config, cgid, path_hash, path_buf) {
        return rc;
    }

    // No rule matched — default deny
    if config.default_action == 0 {
        emit_audit(&ctx, cgid, path_hash, 0xFF, 0, 0, Some(path_buf));
        if config.audit_only != 0 {
            return 0;
        }
        return -1;
    }
    0
}

#[inline(always)]
fn verdict_to_rc(v: u8) -> i32 {
    match v {
        0 => -1,
        1 => 0,
        _ => 0,
    }
}

#[inline(always)]
fn default_verdict(config: &PolicyConfig) -> i32 {
    if config.default_action == 0 {
        if config.audit_only != 0 { 0 } else { -1 }
    } else {
        0
    }
}

#[inline(always)]
fn emit_audit(ctx: &LsmContext, cgroup_id: u64, path_hash: u64, pattern: u8, action: u8, verdict: u8, _path_buf: Option<&ebpf_mon_common::path::Path>) {
    let event = AuditEvent {
        cgroup_id,
        path_hash,
        pattern,
        action,
        verdict,
        _pad: 0,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &event as *const AuditEvent as *const u8,
            core::mem::size_of::<AuditEvent>(),
        )
    };
    AUDIT_EVENTS.output(ctx, bytes, 0);
}

// ═══════════════════════════════════════════════════════════════════
// Process execution enforcement: security_bprm_check_security
// ═══════════════════════════════════════════════════════════════════

#[map]
static EXEC_PATH_POLICY: HashMap<PathPolicyKey, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static EXEC_PATTERN_POLICY: HashMap<PatternKey, u8> = HashMap::with_max_entries(1024, 0);

#[no_mangle]
#[link_section = "lsm/bprm_check_security"]
pub fn enforce_bprm_check(ctx: *mut ::core::ffi::c_void) -> i32 {
    let ctx = LsmContext::new(ctx);

    let ts = unsafe { task_struct::current() };
    let cgid = match unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) } {
        Some(id) => id,
        None => return 0,
    };

    let config = match unsafe { POLICY_CGROUPS.get(&cgid) } {
        Some(cfg) => *cfg,
        None => return 0,
    };

    let bprm = unsafe { co_re::linux_binprm::from_ptr(ctx.arg::<*const gen::linux_binprm>(0)) };
    let file = match unsafe { bprm.file() } {
        Some(f) => f,
        None => return 0,
    };

    // Resolve binary path from dentry chain
    if alloc::init().is_err() {
        return 0;
    }
    let path_buf = match alloc::alloc_zero::<ebpf_mon_common::path::Path>() {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let _ = unsafe { path_buf.core_resolve_file(&file, MAX_PATH_DEPTH) };

    let path_hash = path_buf.hash_path();

    // Tier 1: Exact path match via hash
    let path_key = PathPolicyKey { cgroup_id: cgid, path_hash };
    if let Some(verdict) = unsafe { EXEC_PATH_POLICY.get(&path_key) } {
        let v = *verdict;
        if config.audit_only != 0 && v == 0 {
            emit_audit(&ctx, cgid, path_hash, 0, 5, v, Some(path_buf));
            return 0;
        }
        return verdict_to_rc(v);
    }

    // Tier 2: Path classification
    let classify_buf = path_buf.to_classify_buffer();
    let ns_tgid = unsafe { ts.ns_tgid() }.unwrap_or(0);
    let (pattern, _, _) = unsafe { classify_path(&classify_buf, ns_tgid) };

    if pattern != PathPattern::Regular {
        let pattern_key = PatternKey {
            cgroup_id: cgid,
            pattern: pattern as u8,
            action: 5,
            _pad: [0u8; 6],
        };
        if let Some(verdict) = unsafe { EXEC_PATTERN_POLICY.get(&pattern_key) } {
            let v = *verdict;
            if config.audit_only != 0 && v == 0 {
                emit_audit(&ctx, cgid, path_hash, pattern as u8, 5, v, Some(path_buf));
                return 0;
            }
            return verdict_to_rc(v);
        }
    }

    // No rule matched — default deny
    if config.default_action == 0 {
        emit_audit(&ctx, cgid, path_hash, 0xFF, 5, 0, Some(path_buf));
        if config.audit_only != 0 {
            return 0;
        }
        return -1;
    }
    0
}

// ═══════════════════════════════════════════════════════════════════
// Network enforcement: security_socket_connect
// ═══════════════════════════════════════════════════════════════════

#[map]
static NET_CONNECT_POLICY: HashMap<NetPolicyKey, u8> = HashMap::with_max_entries(4096, 0);

const AF_INET: u32 = 2;

#[lsm(hook = "socket_connect")]
pub fn enforce_socket_connect(ctx: LsmContext) -> i32 {
    let ts = unsafe { task_struct::current() };
    let cgid = match unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) } {
        Some(id) => id,
        None => return 0,
    };

    let config = match unsafe { POLICY_CGROUPS.get(&cgid) } {
        Some(cfg) => *cfg,
        None => return 0,
    };

    let addr = unsafe { co_re::sockaddr::from_ptr(ctx.arg::<*const gen::sockaddr>(1)) };
    let family = match unsafe { addr.sa_family() } {
        Some(f) => f,
        None => return 0,
    };

    if family != AF_INET {
        return 0;
    }

    let sin = unsafe { co_re::sockaddr_in::from_ptr(ctx.arg::<*const gen::sockaddr_in>(1)) };
    let dst_ip = match unsafe { sin.s_addr() } {
        Some(ip) => ip,
        None => return 0,
    };
    let dst_port = match unsafe { sin.sin_port() } {
        Some(p) => u16::from_be(p) as u32,
        None => return 0,
    };

    let key = NetPolicyKey {
        cgroup_id: cgid,
        dst_ip,
        dst_port,
        protocol: 0,
        _pad: [0u8; 7],
    };
    let net_id = ((dst_ip as u64) << 32) | (dst_port as u64);

    if let Some(verdict) = unsafe { NET_CONNECT_POLICY.get(&key) } {
        let v = *verdict;
        if config.audit_only != 0 && v == 0 {
            emit_audit(&ctx, cgid, net_id, 0, 3, v, None);
            return 0;
        }
        return verdict_to_rc(v);
    }

    let wildcard_key = NetPolicyKey {
        cgroup_id: cgid,
        dst_ip,
        dst_port: 0,
        protocol: 0,
        _pad: [0u8; 7],
    };
    if let Some(verdict) = unsafe { NET_CONNECT_POLICY.get(&wildcard_key) } {
        let v = *verdict;
        if config.audit_only != 0 && v == 0 {
            emit_audit(&ctx, cgid, net_id, 0, 3, v, None);
            return 0;
        }
        return verdict_to_rc(v);
    }

    // No rule matched — default deny
    if config.default_action == 0 {
        emit_audit(&ctx, cgid, net_id, 0xFF, 3, 0, None);
        if config.audit_only != 0 {
            return 0;
        }
        return -1;
    }
    0
}

// ═══════════════════════════════════════════════════════════════════
// Prefix matching for file paths (Tier 2.5)
// ═══════════════════════════════════════════════════════════════════

#[map]
static FILE_PREFIX_POLICY: HashMap<u64, PrefixEntry> = HashMap::with_max_entries(256, 0);

const MAX_PREFIX_SLOTS: u64 = 64;

#[inline(always)]
fn check_prefix_match(
    ctx: &LsmContext,
    config: &PolicyConfig,
    cgid: u64,
    path_hash: u64,
    path_buf: &ebpf_mon_common::path::Path,
) -> Option<i32> {
    let path_len = path_buf.len();
    if path_len == 0 {
        return None;
    }
    let (buf, start) = path_buf.raw_buffer_and_offset();

    let mut slot: u64 = 0;
    while slot < MAX_PREFIX_SLOTS {
        let key = (cgid << 8) | slot;
        if let Some(entry) = unsafe { FILE_PREFIX_POLICY.get(&key) } {
            let plen = entry.prefix_len as usize;
            if plen > 0 && plen <= path_len && plen <= ebpf_mon_common::policy::PREFIX_MAX_LEN {
                let mut matched = true;
                let mut i: usize = 0;
                while i < ebpf_mon_common::policy::PREFIX_MAX_LEN {
                    if i >= plen {
                        break;
                    }
                    if i >= path_len {
                        matched = false;
                        break;
                    }
                    let idx = (start + i) & (ebpf_mon_common::path::MAX_PATH_LEN - 1);
                    let a = buf[idx];
                    let b = unsafe { *entry.prefix.get_unchecked(i) };
                    if a != b {
                        matched = false;
                        break;
                    }
                    i += 1;
                }
                if matched {
                    let v = entry.verdict;
                    if config.audit_only != 0 && v == 0 {
                        emit_audit(ctx, cgid, path_hash, 0xFF, 0, v, Some(path_buf));
                        return Some(0);
                    }
                    return Some(verdict_to_rc(v));
                }
            }
        } else {
            break;
        }
        slot += 1;
    }
    None
}
