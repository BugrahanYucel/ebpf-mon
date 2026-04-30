use crate::{buffer::Buffer, cgroup::Cgroup, modules::EventRaw, path::Path};

const CONTAINER_MAX_ID: usize = 72;
pub const MAX_ARGV_SIZE: usize = 512;

pub type ForkEvent = EventRaw<ForkPayload>;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ForkPayload {
    pub executable: Path,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub cgroup: Cgroup,
}

pub type ExecveEvent = EventRaw<ExecvePayload>;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecvePayload {
    pub executable: Path,
    pub interpreter: Path,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub cgroup: Cgroup,
}

pub type CgroupMkdirEvent = EventRaw<CgroupMkdir>;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CgroupMkdir{
    pub cgroup: Cgroup,
    pub path: Path,
}