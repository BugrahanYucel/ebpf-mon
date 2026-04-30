use aya_ebpf::{
    EbpfContext, bindings::BPF_NOEXIST, helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes}, macros::{btf_tracepoint, map, tracepoint}, maps::LruHashMap, programs::{BtfTracePointContext, TracePointContext}
};
use ebpf_mon_common::{
    alloc, co_re::{self, core_read_kernel, task_struct}, modules::{Type, pipe_event}, path::MAX_PATH_DEPTH, process::{MAX_ARG_LEN, MAX_ARGS, MAX_FILENAME_LEN, ProcessEventRaw, ProcessType}
};

#[map]
static PROCESS_EVENT_DEDUP: LruHashMap<ProcessIdentity, u8> = LruHashMap::with_max_entries(1024, 0);

#[map]
pub static mut EXEC_STATE: LruHashMap<u64, ProcessEventRaw> = LruHashMap::with_max_entries(1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessIdentity {
    pub ps_type: u8,
    pub filename: [u8; MAX_FILENAME_LEN],
    pub argv: [[u8; MAX_ARG_LEN]; MAX_ARGS],
}

// Helper function for cache-based deduplication
unsafe fn deduplicate_and_send<C: EbpfContext>(
    ctx: &C,
    event: &ProcessEventRaw,
    identity: &ProcessIdentity,
) -> Result<(), u32> {
    match PROCESS_EVENT_DEDUP.insert(identity, &1u8, BPF_NOEXIST.into()) {
        Ok(_) => {
            pipe_event(ctx, event);
        },
        Err(_) => {}
    }
    Ok(())
}

fn check_capability(cap_effective: u64, cap_num: u32) -> bool {
    (cap_effective & (1u64 << cap_num)) != 0
}

#[btf_tracepoint] 
pub fn fork_tracepoint(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_fork_tracepoint(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_fork_tracepoint(ctx: BtfTracePointContext) -> Result<u32, u32> { // TODO: Make the same changes as execve
    let ts = unsafe { task_struct::current() };
    let cgid = unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) }.ok_or(1u32)?;

    // Cgroup based filtering
    if !super::cgroup_exists(cgid) {
        return Ok(0)
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ProcessEventRaw>().map_err(|_| 1u32)?;

    unsafe { event.init(Type::Fork, ts).map_err(|_| 1u32)? };

    let pid = bpf_get_current_pid_tgid() as u32;

    let parent = unsafe { core_read_kernel!(ts, real_parent) }.ok_or(1u32)?;
    let ppid = unsafe { core_read_kernel!(parent, pid) }.ok_or(1u32)?;
    let cred = unsafe { core_read_kernel!(ts, cred) }.ok_or(1u32)?;
    let gid = unsafe { core_read_kernel!(cred, gid) };
    let uid = unsafe { core_read_kernel!(cred, uid) };
    let is_root: bool = if uid == 0 {true} else {false};
    let capabilities = unsafe { core_read_kernel!(cred, cap_effective) }.ok_or(1u32)?;

    // Get inode from current process's executable file
    let inode_num = if let Some(exe_file) = core_read_kernel!(ts, mm, exe_file) {
        event.payload.path.core_resolve_file(&exe_file, MAX_PATH_DEPTH)?;
        let inode_ptr = exe_file.f_inode().ok_or(1u32)?;
        inode_ptr.i_ino().ok_or(1u32)?
    } else {
        0u64
    };
    event.payload.ps_type = ProcessType::Fork;
    event.payload.pid = pid;
    event.payload.cgroup_id = cgid;
    event.payload.inode = inode_num;
    event.payload.capabilities = capabilities;
    event.payload.ppid = ppid;
    event.payload.gid = gid;
    event.payload.is_root = is_root;
    event.payload.parent_comm = unsafe { parent.comm_array().ok_or(1u32)? };
    // let str_bytes = unsafe { bpf_probe_read_kernel_str_bytes(parent_comm_ptr as *const u8, &mut event.payload.parent_comm) }.unwrap_or(&[0; 16]);
    

    let identity = alloc::alloc_zero::<ProcessIdentity>().map_err(|_| 1u32)?;
    identity.ps_type = event.payload.ps_type as u8;

    deduplicate_and_send(&ctx, event, &identity)?;
    Ok(0u32)
}

#[tracepoint]
pub fn execve_tracepoint(ctx: TracePointContext) -> i32 {
    match unsafe { try_execve_tracepoint(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn execveat_tracepoint(ctx: TracePointContext) -> i32 {
    match unsafe { try_execveat_tracepoint(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
pub unsafe fn try_execve_tracepoint(ctx: &TracePointContext, ) -> Result<i32, i32> {
    let filename_ptr: u64 = ctx.read_at(16).map_err(|_| 1i32)?;
    let argv_ptr: u64 = ctx.read_at(24).map_err(|_| 1i32)?;
    handle_exec_common(ctx, filename_ptr, argv_ptr)
}

#[inline(always)]
pub unsafe fn try_execveat_tracepoint(ctx: &TracePointContext, ) -> Result<i32, i32> {
    let filename_ptr: u64 = ctx.read_at(16).map_err(|_| 1i32)?;
    let argv_ptr: u64 = ctx.read_at(24).map_err(|_| 1i32)?;
    handle_exec_common(ctx, filename_ptr, argv_ptr)
}

#[inline(always)]
pub unsafe fn handle_exec_common(
    ctx: &TracePointContext, 
    filename_ptr: u64,
    argv_ptr: u64,
    ) -> Result<i32, i32> {
    let ts = unsafe { task_struct::current() };
    let cgid = unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) }.ok_or(1i32)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    
    let parent = unsafe { core_read_kernel!(ts, real_parent) }.ok_or(1i32)?;
    let ppid = unsafe { core_read_kernel!(parent, pid) }.ok_or(1i32)?;
    let cred = unsafe { core_read_kernel!(ts, cred) }.ok_or(1i32)?;
    let gid = unsafe { core_read_kernel!(cred, gid) };
    let uid = unsafe { core_read_kernel!(cred, uid) };
    // let parent_comm_ptr = unsafe { core_read_kernel!(parent, comm) }.ok_or(1i32)?;
    let is_root: bool = if uid == 0 {true} else {false};
    let capabilities = unsafe { core_read_kernel!(cred, cap_effective) }.ok_or(1i32)?;
   
    if !super::cgroup_exists(cgid) {
        return Ok(0i32)
    }
    
    alloc::init().map_err(|_| 1i32)?;
    let event = alloc::alloc_zero::<ProcessEventRaw>().map_err(|_| 1i32)?;

    unsafe { event.init(Type::Execve, ts).map_err(|_| 1i32)? };

    let args = ctx.as_ptr() as *const usize;

    let inode_num = if let Some(exe_file) = core_read_kernel!(ts, mm, exe_file) {
        event.payload.path.core_resolve_file(&exe_file, MAX_PATH_DEPTH).map_err(|_| 1i32)?;
        let inode_ptr = exe_file.f_inode().ok_or(1i32)?;
        inode_ptr.i_ino().ok_or(1i32)?
    } else {
        0u64
    };
    event.payload.ps_type = ProcessType::Execve;
    event.payload.pid = pid;
    event.payload.tgid = tgid;
    event.payload.cgroup_id = cgid;
    event.payload.freq = 0u32;
    event.payload.capabilities = capabilities;
    event.payload.ppid = ppid;
    event.payload.gid = gid;
    event.payload.is_root = is_root;
    event.payload.parent_comm = unsafe { parent.comm_array().ok_or(1i32)? };

    // let _ = unsafe { bpf_probe_read_kernel_str_bytes(parent_comm_ptr as *const u8, &mut event.payload.parent_comm) }.unwrap_or(&[0; 16]);


    if filename_ptr != 0 {
        let _ = bpf_probe_read_user_str_bytes(
            filename_ptr as *const u8,
            &mut event.payload.filename,
        );
    }

    read_argv(argv_ptr, event);

    EXEC_STATE.insert(&pid_tgid, &event, 0);
    Ok(0i32)
}


#[tracepoint]
pub fn exit_execve_tracepoint(ctx: TracePointContext) -> i32 {
    match unsafe { try_exit_execve_tracepoint(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn exit_execveat_tracepoint(ctx: TracePointContext) -> i32 {
    match unsafe { try_exit_execveat_tracepoint(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
pub unsafe fn try_exit_execve_tracepoint(ctx: &TracePointContext, ) -> Result<i32, i32> {
    let retval_ptr: u64 = ctx.read_at(16).map_err(|_| 1i32)?;
    handle_exit_exec_common(ctx, retval_ptr)
}

#[inline(always)]
pub unsafe fn try_exit_execveat_tracepoint(ctx: &TracePointContext, ) -> Result<i32, i32> {
    let retval_ptr: u64 = ctx.read_at(16).map_err(|_| 1i32)?;
    handle_exit_exec_common(ctx, retval_ptr)
}


#[inline(always)]
pub unsafe fn handle_exit_exec_common(
    ctx: &TracePointContext,
    retval_ptr: u64
) -> Result<i32, i32> {
    let ts = unsafe { task_struct::current() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let mut pending_exec: &mut ebpf_mon_common::modules::EventRaw<ebpf_mon_common::process::ProcessPayload> = match EXEC_STATE.get_ptr_mut(&pid_tgid) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Ok(1i32)
    };
    
    let retval: i64 = ctx.read_at(16).unwrap_or(-1);
    pending_exec.payload.retval = retval as i32;

    // After successful exec, exe_file points to the NEW binary
    if retval == 0 {
        if let Some(exe_file) = core_read_kernel!(ts, mm, exe_file) {
            if let Some(inode_ptr) = exe_file.f_inode() {
                if let Some(ino) = inode_ptr.i_ino() {
                    pending_exec.payload.inode = ino;
                }
            }
        }
    }

    alloc::init().map_err(|_| 1i32)?;
    let identity = alloc::alloc_zero::<ProcessIdentity>().map_err(|_| 1i32)?;
    identity.ps_type = pending_exec.payload.ps_type as u8;
    identity.filename = pending_exec.payload.filename;
    identity.argv = pending_exec.payload.argv;

    deduplicate_and_send(ctx, pending_exec, &identity);

    EXEC_STATE.remove(&pid_tgid);
    Ok(0i32)
}

// Helper: Check if arg starts with "--"
#[inline(always)]
fn is_long_flag(arg: &[u8]) -> bool {
    arg.len() >= 2 && arg[0] == b'-' && arg[1] == b'-'
}

// Helper: Check if arg matches a long flag pattern (e.g., "--encrypt")
#[inline(always)]
fn matches_long_flag(arg: &[u8], pattern: &[u8]) -> bool {
    if arg.len() < pattern.len() + 2 || !is_long_flag(arg) {
        return false;
    }
    let arg_suffix = &arg[2..];
    if arg_suffix.len() < pattern.len() {
        return false;
    }
    for i in 0..pattern.len() {
        if arg_suffix[i] != pattern[i] {
            return false;
        }
    }
    true
}

// Helper: Check if arg matches a short flag (e.g., "-p" or "-P")
#[inline(always)]
fn matches_short_flag(arg: &[u8], c1: u8, c2: u8) -> bool {
    arg.len() == 2 && arg[0] == b'-' && (arg[1] == c1 || arg[1] == c2)
}

// qpdf --encrypt: next TWO args are user-password and owner-password
#[inline(always)]
fn is_encrypt_flag(arg: &[u8]) -> bool {
    matches_long_flag(arg, b"encrypt")
}

// --password, --pass
#[inline(always)]
fn is_password_flag(arg: &[u8]) -> bool {
    matches_long_flag(arg, b"pass")
}

// --secret
#[inline(always)]
fn is_secret_flag(arg: &[u8]) -> bool {
    matches_long_flag(arg, b"secret")
}

// --key, --api-key
#[inline(always)]
fn is_key_flag(arg: &[u8]) -> bool {
    matches_long_flag(arg, b"key")
}

// --token
#[inline(always)]
fn is_token_flag(arg: &[u8]) -> bool {
    matches_long_flag(arg, b"token")
}

// -p, -P (common short password flags)
#[inline(always)]
fn is_short_password_flag(arg: &[u8]) -> bool {
    matches_short_flag(arg, b'p', b'P')
}

// Check if an argument is a password-related flag that means the next arg(s) should be redacted
// Returns the number of following arguments to redact
#[inline(always)]
fn check_sensitive_flag(arg: &[u8]) -> u8 {
    if arg.len() < 2 {
        return 0;
    }

    // qpdf --encrypt: redact next 2 args
    if is_encrypt_flag(arg) {
        return 2;
    }

    // All other sensitive flags: redact next 1 arg
    if is_password_flag(arg)
        || is_short_password_flag(arg)
        || is_secret_flag(arg)
        || is_key_flag(arg)
        || is_token_flag(arg)
    {
        return 1;
    }

    0
}

#[inline(always)]
fn redact_arg(arg: &mut [u8; MAX_ARG_LEN]) {
    arg[0] = b'[';
    arg[1] = b'R';
    arg[2] = b'E';
    arg[3] = b'D';
    arg[4] = b'A';
    arg[5] = b'C';
    arg[6] = b'T';
    arg[7] = b'E';
    arg[8] = b'D';
    arg[9] = b']';
    arg[10] = 0; // null terminate
}

#[inline(always)]
unsafe fn read_argv(argv_ptr: u64, event: &mut ProcessEventRaw) {
    event.payload.argc = 0;
    
    if argv_ptr == 0 {
        return;
    }
    
    let argv = argv_ptr as *const *const u8;
    let mut redact_count: u8 = 0;
    
    for i in 0..MAX_ARGS {
        let arg_ptr: *const u8 = match bpf_probe_read_user(&*argv.add(i)) {
            Ok(ptr) => ptr,
            Err(_) => break,
        };
        
        // Null = end of argv
        if arg_ptr.is_null() {
            break;
        }
        
        // Read string into buffer
        let _ = bpf_probe_read_user_str_bytes(arg_ptr, &mut event.payload.argv[i]);
        event.payload.argc += 1;

        // If we need to redact this argument (flagged by previous arg)
        if redact_count > 0 {
            redact_arg(&mut event.payload.argv[i]);
            redact_count -= 1;
        } else {
            // Check if this argument is a sensitive flag
            redact_count = check_sensitive_flag(&event.payload.argv[i]);
        }
    }
}