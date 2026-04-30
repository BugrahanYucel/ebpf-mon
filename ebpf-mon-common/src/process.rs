use crate::{modules::EventRaw, path::Path};

pub const MAX_ARGS: usize = 20;
pub const MAX_ARG_LEN: usize = 128;
pub const MAX_FILENAME_LEN: usize = 256;

pub type ProcessEventRaw = EventRaw<ProcessPayload>;

#[derive(Clone, Copy, PartialEq, Hash, Debug)]
#[repr(u8)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum ProcessType {
    Execve = 0u8,
    Fork = 1u8,
}

#[repr(C)]
pub struct ProcessPayload {
    pub path: Path,
    pub inode: u64,
    pub ps_type: ProcessType,

    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub ppid: i32,
    pub gid: u32,

    pub filename: [u8; MAX_FILENAME_LEN],
    pub argv: [[u8; MAX_ARG_LEN]; MAX_ARGS],
    pub argc: u32,
    pub retval: i32,

    pub freq: u32,

    pub parent_comm: [u8; 16],
    pub is_root: bool,
    pub capabilities: u64,
}
