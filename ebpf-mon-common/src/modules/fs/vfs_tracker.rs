use crate::{modules::ProcessInfo, path::Path};

#[repr(C)]
#[derive(Debug)]
pub enum VFSEventType {
    READ,
    WRITE,
}

// event type - read|write ||| network connection tracking
const MAX_FS_TYPE_SIZE: usize = 100;
pub struct VfsIoEvent {
    pub process_info: ProcessInfo,
    pub path: Path,
    pub fs_type: [u8; MAX_FS_TYPE_SIZE],
    pub delay: u64,
    pub event_type: VFSEventType,
}
