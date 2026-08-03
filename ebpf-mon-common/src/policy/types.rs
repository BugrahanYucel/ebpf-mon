#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeKey {
    pub cgroup_id: u64,
    pub inode: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for InodeKey {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicyKey {
    pub cgroup_id: u64,
    pub path_hash: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PathPolicyKey {}

/// Access-mode bits stored in the FILE_PATH_POLICY *value* byte (exact-path tier).
/// This lets the BPF-LSM `security_file_open` hook distinguish read from write
/// instead of being open-granularity. A value of 0 means "deny"; otherwise the
/// value is the set of permitted access modes and an open is allowed only when
/// every requested mode bit is present (e.g. a write to a read-only entry is
/// denied). Read and userspace loader both use these so the encoding matches.
pub const ACCESS_READ: u8 = 1 << 0;
pub const ACCESS_WRITE: u8 = 1 << 1;
/// `f_flags & O_ACCMODE` selects the requested access: 0=RDONLY, 1=WRONLY, 2=RDWR.
pub const O_ACCMODE: u32 = 0o3;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// FNV-1a hash for path bytes. Used in both BPF and userspace to produce
/// identical hashes for the same path string.
#[inline(always)]
pub fn fnv1a_hash_bytes(data: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET_BASIS;
    let mut i: usize = 0;
    while i < data.len() {
        if data[i] == 0 {
            break;
        }
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternKey {
    pub cgroup_id: u64,
    pub pattern: u8,
    pub action: u8,
    pub _pad: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PatternKey {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConfig {
    pub default_action: u8,
    pub audit_only: u8,
    pub _pad: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyConfig {}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictValue {
    Deny = 0,
    Allow = 1,
    Audit = 2,
}

impl VerdictValue {
    pub fn to_return_code(self) -> i32 {
        match self {
            VerdictValue::Deny => -1,  // -EPERM
            VerdictValue::Allow => 0,
            VerdictValue::Audit => 0,  // allow but log
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => VerdictValue::Deny,
            1 => VerdictValue::Allow,
            _ => VerdictValue::Audit,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetPolicyKey {
    pub cgroup_id: u64,
    pub dst_ip: u32,
    pub dst_port: u32,
    pub protocol: u8,
    pub _pad: [u8; 7],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetPolicyKey {}

pub const PREFIX_MAX_LEN: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrefixEntry {
    pub prefix: [u8; PREFIX_MAX_LEN],
    pub prefix_len: u32,
    pub verdict: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PrefixEntry {}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    FileOpen = 0,
    FileRead = 1,
    FileWrite = 2,
    NetConnect = 3,
    NetBind = 4,
    ProcExec = 5,
    ProcFork = 6,
}
