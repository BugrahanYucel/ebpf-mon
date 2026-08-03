use crate::{modules::ProcessInfo, path::Path};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileOpenEvent {
    pub process_info: ProcessInfo,
    pub file_path: Path,
    pub inode: u64,
    pub access_mask: u8,
    pub allowed: bool,
}
