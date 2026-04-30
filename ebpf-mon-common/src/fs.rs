use crate::{macros::{bpf_target_code, not_bpf_target_code}, modules::EventRaw, path::Path};
pub type FsEventRaw = EventRaw<FsPayload>;

not_bpf_target_code! {
    #[cfg(feature = "user")]
    mod user;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

#[repr(C)]
pub struct FsPayload {
    pub path: Path,
    pub pid: u32,
    pub tgid: u32,
    pub sym_path: Path,
    pub inode: u64,
    pub owner_uid: u32,
    pub r_w: u8,
    pub is_symlink: u8,
    pub path_pattern: PathPattern,
    pub is_sensitive: u8,       // Sensitive file (environ, mem, maps, etc.)
    pub is_cross_process: u8,   // Accessing another process's /proc entry (0 = self access)
    pub freq: u32,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "user", derive(Debug, Hash, serde::Serialize))]
pub enum FileOperation {
    READ = 0u8,
    WRITE = 1u8,
    OPEN = 2u8,
    STAT = 3u8,
    OTHER = 4u8,
}

// common/src/lib.rs

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Debug, Hash, serde::Serialize, serde::Deserialize))]
pub enum PathPattern {
    Regular = 0,
    
    // /proc/[PID]/*
    ProcPidCmdline = 1,
    ProcPidComm = 2,
    ProcPidCwd = 3,
    ProcPidEnviron = 4,
    ProcPidExe = 5,
    ProcPidFd = 6,
    ProcPidMaps = 7,
    ProcPidMem = 8,
    ProcPidMountinfo = 9,
    ProcPidMounts = 10,
    ProcPidNet = 11,
    ProcPidNs = 12,
    ProcPidRoot = 13,
    ProcPidStat = 14,
    ProcPidStatus = 15,
    ProcPidTask = 16,
    ProcPidCgroup = 17,
    ProcPidOther = 18,
    
    // /proc/self/* - Note: kernel resolves /proc/self to /proc/[PID] before VFS hooks,
    // so we detect self-access via is_cross_process=0 instead of this pattern
    ProcSelf = 20,
    
    // /proc/[global]
    ProcGlobal = 30,
    ProcGlobalSys = 31,
    ProcGlobalNet = 32,
    
    // /sys/*
    SysCgroupDocker = 40,
    SysCgroupOther = 41,
    SysClassNet = 42,
    SysOther = 43,
    
    // /run/*
    RunDocker = 50,
    RunUser = 51,
    RunOther = 52,
    
    // /dev/*
    DevPts = 60,
    DevShm = 61,
    DevOther = 62,
    
    // /tmp/*
    TmpRandom = 70,
    TmpOther = 71,
}


impl PathPattern {
    /// Get the wildcard pattern string for this path pattern
    pub fn as_str(&self) -> &'static str {
        match self {
            PathPattern::Regular => "<regular>",
            
            PathPattern::ProcPidCmdline => "/proc/*/cmdline",
            PathPattern::ProcPidComm => "/proc/*/comm",
            PathPattern::ProcPidCwd => "/proc/*/cwd",
            PathPattern::ProcPidEnviron => "/proc/*/environ",
            PathPattern::ProcPidExe => "/proc/*/exe",
            PathPattern::ProcPidFd => "/proc/*/fd/*",
            PathPattern::ProcPidMaps => "/proc/*/maps",
            PathPattern::ProcPidMem => "/proc/*/mem",
            PathPattern::ProcPidMountinfo => "/proc/*/mountinfo",
            PathPattern::ProcPidMounts => "/proc/*/mounts",
            PathPattern::ProcPidNet => "/proc/*/net/*",
            PathPattern::ProcPidNs => "/proc/*/ns/*",
            PathPattern::ProcPidRoot => "/proc/*/root",
            PathPattern::ProcPidStat => "/proc/*/stat",
            PathPattern::ProcPidStatus => "/proc/*/status",
            PathPattern::ProcPidTask => "/proc/*/task/*",
            PathPattern::ProcPidCgroup => "/proc/*/cgroup",
            PathPattern::ProcPidOther => "/proc/*/<other>",
            
            PathPattern::ProcSelf => "/proc/self/*",
            
            PathPattern::ProcGlobal => "/proc/<global>",
            PathPattern::ProcGlobalSys => "/proc/sys/**",
            PathPattern::ProcGlobalNet => "/proc/net/*",
            
            PathPattern::SysCgroupDocker => "/sys/fs/cgroup/**/docker/**",
            PathPattern::SysCgroupOther => "/sys/fs/cgroup/**",
            PathPattern::SysClassNet => "/sys/class/net/*",
            PathPattern::SysOther => "/sys/**",
            
            PathPattern::RunDocker => "/run/docker/**",
            PathPattern::RunUser => "/run/user/*/**",
            PathPattern::RunOther => "/run/**",
            
            PathPattern::DevPts => "/dev/pts/*",
            PathPattern::DevShm => "/dev/shm/*",
            PathPattern::DevOther => "/dev/*",
            
            PathPattern::TmpRandom => "/tmp/tmp*/**",
            PathPattern::TmpOther => "/tmp/**",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsDedupKey {
    pub pattern: u8,       // PathPattern
    pub operation: u8,     // FileOperation
    pub is_sensitive: u8,  // Security-sensitive path
    pub is_cross_proc: u8, // Accessing another process's /proc
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsDedupValue {
    pub count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub example_path: [u8; 128],  // Store ONE example TODO: is this used?
}