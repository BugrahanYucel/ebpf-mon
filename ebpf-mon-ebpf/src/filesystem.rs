use aya_ebpf::{
    EbpfContext, bindings::BPF_NOEXIST, helpers::bpf_get_current_pid_tgid, macros::{fentry, fexit, map}, maps::{HashMap, LruHashMap}, programs::{FEntryContext, FExitContext}
};
use aya_log_ebpf::info;

use ebpf_mon_common::{
    alloc, co_re::{self, core_read_kernel, r#gen, task_struct}, fs::{FileOperation, FsEventRaw, PathPattern, classify_path}, modules::{Type, pipe_event}, path::{MAX_PATH_DEPTH, MAX_PATH_LEN}
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsIdentity {
    pub path: [u8; MAX_PATH_LEN as usize],
    pub r_w: u8,
    pub is_symlink: u8,
    pub path_pattern: PathPattern,
}

/// Pattern-based identity for deduplicating self-access events by pattern type
/// (e.g., all /proc/self/mountinfo reads become one event)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsPatternIdentity {
    pub path_pattern: PathPattern,
    pub r_w: u8,
    pub is_cross_process: u8,
    pub _padding: u8,
}

#[map]
static FS_EVENT_DEDUP: LruHashMap<FsIdentity, u8> = LruHashMap::with_max_entries(65536, 0);

/// Dedup map for pattern-based deduplication (reduces noise from repeated self-access patterns)
#[map]
static FS_PATTERN_DEDUP: LruHashMap<FsPatternIdentity, u8> = LruHashMap::with_max_entries(1024, 0);

#[map]
pub static VFS_STATE: HashMap<u64, usize> = HashMap::with_max_entries(1024, 0);

const S_IFMT: u16 = 0o170000;
const S_IFLNK: u16 = 0o120000;  // Symbolic link

// Helper function for cache-based deduplication
// Uses two-level dedup:
// 1. Pattern-based: For non-Regular patterns, deduplicate by pattern type (reduces /proc noise)
// 2. Path-based: For Regular patterns or sensitive files, deduplicate by exact path
unsafe fn deduplicate_and_send<C: EbpfContext>(
    ctx: &C,
    event: &FsEventRaw,
    identity: &FsIdentity,
    _is_cross_process: bool,
    is_sensitive: bool,
) -> Result<(), u32> {
    // For non-Regular patterns, use pattern-based dedup
    // This reduces noise from repeated /proc/*/mountinfo, /proc/*/status, etc.
    // Sensitive files still use path-based dedup to capture each unique access
    if identity.path_pattern != PathPattern::Regular && !is_sensitive {
        let pattern_identity = FsPatternIdentity {
            path_pattern: identity.path_pattern,
            r_w: event.payload.r_w,
            is_cross_process: 0,
            _padding: 0,
        };
        
        match FS_PATTERN_DEDUP.insert(&pattern_identity, &1u8, BPF_NOEXIST.into()) {
            Ok(_) => {
                pipe_event(ctx, event);
            },
            Err(_) => {} // Already seen this pattern, drop
        }
    } else {
        // Path-based dedup for Regular patterns or sensitive access
        match FS_EVENT_DEDUP.insert(identity, &1u8, BPF_NOEXIST.into()) {
            Ok(_) => {
                pipe_event(ctx, event);
            },
            Err(_) => {}
        }
    }
    Ok(())
}

#[map]
pub static SYMLINK_MAP: HashMap<u64, usize> = HashMap::with_max_entries(1024, 0);

#[fentry]
pub fn check_symlink(ctx: FEntryContext) -> u32 {
    check_security_inode_follow_link(ctx).unwrap_or(0)
}

fn check_security_inode_follow_link(ctx: FEntryContext) -> Result<u32, u32> {
    let ts = unsafe { task_struct::current() };
    let cgid = unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) }.ok_or(1u32)?;

    if !super::cgroup_exists(cgid) {
        return Ok(0)
    }

    let dentry = unsafe { co_re::dentry::from_ptr(ctx.arg(0)) };

    let inode = unsafe { core_read_kernel!(dentry, d_inode) }.ok_or(1u32)?;
    if (unsafe { inode.is_symlink().ok_or(1u32)? }) {
        unsafe { SYMLINK_MAP.insert(&bpf_get_current_pid_tgid(), &(dentry.as_ptr() as usize), 0) };
    }
    else {
        info!(&ctx, "ERROR: A non-symlink file is used in check_security_inode_follow_link- change the symlink hook function");
    }

    Ok(0u32)
}


/// Hook vfs_open at exit to capture ALL file opens, including those that
/// later use sendfile/splice instead of vfs_read.
/// At fexit, the struct file is fully initialized (f_inode, f_mode set).
/// Signature: int vfs_open(const struct path *path, struct file *file)
#[fexit]
pub fn vfs_open_fexit(ctx: FExitContext) -> u32 {
    process_vfs_open(ctx).unwrap_or(0)
}

fn process_vfs_open(ctx: FExitContext) -> Result<u32, u32> {
    let retval: i32 = unsafe { ctx.arg(2) };
    if retval != 0 {
        return Ok(0);
    }

    let ts = unsafe { task_struct::current() };
    let cgid = unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) }.ok_or(1u32)?;

    if !super::cgroup_exists(cgid) {
        return Ok(0)
    }

    let file = unsafe { co_re::file::from_ptr(ctx.arg::<*const gen::file>(1)) };

    let is_socket = unsafe { file.is_sock().unwrap_or(false) };
    let is_pipe = unsafe { file.is_pipe().unwrap_or(false) };
    if is_socket || is_pipe {
        return Ok(0u32);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    alloc::init()?;
    let event = alloc::alloc_zero::<FsEventRaw>().map_err(|_| 1u32)?;

    unsafe { event.init(Type::FileRead, ts).map_err(|_| 1u32)? };

    event.payload.pid = pid;
    event.payload.tgid = tgid;
    event.payload.r_w = 0;
    event.payload.freq = 1u32;
    unsafe { event.payload.path.core_resolve_file(&file, MAX_PATH_DEPTH) };

    let inode_ptr = unsafe { file.f_inode().ok_or(1u32)? };
    let inode_num = unsafe { inode_ptr.i_ino().ok_or(1u32)? };
    event.payload.inode = inode_num;

    let cred = unsafe { core_read_kernel!(ts, cred) }.ok_or(1u32)?;
    event.payload.owner_uid = unsafe { core_read_kernel!(cred, uid) };

    let identity = alloc::alloc_zero::<FsIdentity>().map_err(|_| 1u32)?;
    let classify_buf = event.payload.path.to_classify_buffer();
    identity.path = *event.payload.path.as_full_buffer();
    identity.r_w = event.payload.r_w;
    identity.is_symlink = 0;

    let ns_tgid = unsafe { ts.ns_tgid() }.unwrap_or(tgid);
    let (pattern, is_sensitive, is_cross_process) = unsafe { classify_path(&classify_buf, ns_tgid) };
    identity.path_pattern = pattern;
    event.payload.path_pattern = pattern;
    event.payload.is_sensitive = if is_sensitive { 1 } else { 0 };
    event.payload.is_cross_process = if is_cross_process { 1 } else { 0 };

    unsafe { deduplicate_and_send(&ctx, event, &identity, is_cross_process, is_sensitive)? };

    Ok(0u32)
}

#[fentry]
pub fn vfs_read_fentry(ctx: FEntryContext) -> u32 {
    process_vfs_fentry(ctx).unwrap_or(0)
}

#[fentry]
pub fn vfs_write_fentry(ctx: FEntryContext) -> u32 {
    process_vfs_fentry(ctx).unwrap_or(0)
}

#[fentry]
pub fn vfs_iter_read_fentry(ctx: FEntryContext) -> u32 {
    process_vfs_fentry(ctx).unwrap_or(0)
}

#[fentry]
pub fn vfs_iter_write_fentry(ctx: FEntryContext) -> u32 {
    process_vfs_fentry(ctx).unwrap_or(0)
}

fn process_vfs_fentry(ctx: FEntryContext) -> Result<u32, u32> {
    let ts = unsafe { task_struct::current() };
    let cgid = unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) }.ok_or(1u32)?;

    if !super::cgroup_exists(cgid) {
        return Ok(0)
    }

    let file = unsafe { co_re::file::from_ptr(ctx.arg::<*const gen::file>(0)) };

    let is_regular_file = unsafe { file.is_file().unwrap_or(false) };
    let is_block_device = unsafe { file.is_blk().unwrap_or(false) };
    let is_socket = unsafe { file.is_sock().unwrap_or(false)};
    let is_pipe = unsafe { file.is_pipe().unwrap_or(false)};

    if is_pipe || (!is_regular_file && !is_block_device) || is_socket {
        return Ok(0u32); 
    }

    VFS_STATE.insert(&bpf_get_current_pid_tgid(), &(file.as_ptr() as usize), 0);

    Ok(0u32)
}

#[fexit]
pub fn vfs_write_fexit(ctx: FExitContext) -> Result<u32,u32>  {
    process_vfs_fexit(ctx, FileOperation::WRITE)
}

#[fexit]
pub fn vfs_read_fexit(ctx: FExitContext) -> Result<u32,u32>  {
    process_vfs_fexit(ctx, FileOperation::READ)
}

#[fexit]
pub fn vfs_iter_write_fexit(ctx: FExitContext) -> Result<u32,u32>  {
    process_vfs_fexit(ctx, FileOperation::WRITE)
}

#[fexit]
pub fn vfs_iter_read_fexit(ctx: FExitContext) -> Result<u32,u32>  {
    process_vfs_fexit(ctx, FileOperation::READ)
}

fn process_vfs_fexit(ctx: FExitContext, f_op: FileOperation) -> Result<u32, u32> {
    let ts = unsafe { task_struct::current() };
    let cgid = unsafe { core_read_kernel!(ts, sched_task_group, css, cgroup, kn, id) }.ok_or(1u32)?;

    let pid_tgid = &bpf_get_current_pid_tgid();
    let pid = *pid_tgid as u32;
    let tgid = (*pid_tgid >> 32) as u32;

    let file_addr = unsafe { VFS_STATE.get(pid_tgid).ok_or(1u32)? };
    let file = co_re::file::from_ptr(*file_addr as *const _);
    if file.is_null(){
        return Ok(1u32);
    }
    unsafe { VFS_STATE.remove(&bpf_get_current_pid_tgid()); }
    
    let path = unsafe { file.f_path().ok_or(1u32)? };
    if path.is_null(){
        return Ok(1u32);
    }
    
    alloc::init()?;
    let event = alloc::alloc_zero::<FsEventRaw>().map_err(|_| 1u32)?;

    let event_type = if f_op == FileOperation::WRITE {Type::FileWrite} else {Type::FileRead};
    unsafe { event.init(event_type, ts).map_err(|_| 1u32)? };
    
    event.payload.pid = pid;
    event.payload.tgid = tgid;
    event.payload.r_w = if f_op == FileOperation::WRITE {1u8} else {0u8};
    event.payload.freq = 1u32;
    unsafe { event.payload.path.core_resolve_file(&file, MAX_PATH_DEPTH) };
    
    let symlink_path = unsafe { SYMLINK_MAP.get(&bpf_get_current_pid_tgid())};
    let mut inode_num = 0;
    if let Some(sympath) = symlink_path {

        event.payload.is_symlink = 1;
        let dentry = co_re::dentry::from_ptr(*sympath as *const _);

        unsafe { event.payload.sym_path.resolve_from_dentry(&dentry, MAX_PATH_DEPTH) };

        // Get inode number for deduplication and payload
        let inode_ptr = unsafe { dentry.d_inode().ok_or(1u32)? };
        inode_num = unsafe { inode_ptr.i_ino().ok_or(1u32)? };
        event.payload.inode = inode_num;
    }
    else {
        event.payload.is_symlink = 0;

        // Get inode number for deduplication and payload
        let inode_ptr = unsafe { file.f_inode().ok_or(1u32)? };
        inode_num = unsafe { inode_ptr.i_ino().ok_or(1u32)? };
        event.payload.inode = inode_num;
    }
    unsafe { SYMLINK_MAP.remove(&bpf_get_current_pid_tgid()); }

    let cred = unsafe { core_read_kernel!(ts, cred) }.ok_or(1u32)?;
    let owner_uid = unsafe { core_read_kernel!(cred, uid) };

    event.payload.owner_uid = owner_uid;

    // Create identity for deduplication
    let identity = alloc::alloc_zero::<FsIdentity>().map_err(|_| 1u32)?;

    // Get properly-aligned path buffer for classification (handles Prepend mode correctly)
    let classify_buf = event.payload.path.to_classify_buffer();
    
    // Copy full path buffer to identity for deduplication (fixed-size, verifier-friendly)
    // Both buffers are MAX_PATH_LEN bytes, so we can do a direct fixed-size copy
    identity.path = *event.payload.path.as_full_buffer();
    
    identity.r_w = event.payload.r_w;
    identity.is_symlink = event.payload.is_symlink;

    // Use the namespaced tgid for cross-process detection.
    // /proc/ paths use the PID from the process's namespace,
    // so we must compare against the namespace-aware tgid, not the host tgid.
    let ns_tgid = unsafe { ts.ns_tgid() }.unwrap_or(tgid);
    let (pattern, is_sensitive, is_cross_process) = unsafe { classify_path(&classify_buf, ns_tgid) };
    identity.path_pattern = pattern;
    event.payload.path_pattern = pattern;
    event.payload.is_sensitive = if is_sensitive { 1 } else { 0 };
    event.payload.is_cross_process = if is_cross_process { 1 } else { 0 };

    unsafe { deduplicate_and_send(&ctx, event, &identity, is_cross_process, is_sensitive)? };

    Ok(0u32)
}
