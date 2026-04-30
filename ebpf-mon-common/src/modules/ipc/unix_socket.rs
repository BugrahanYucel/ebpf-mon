use crate::{bpf_target_code, macros::not_bpf_target_code, modules::ProcessInfo};

#[repr(C)]
#[derive(Debug)]
pub struct UnixSockTest {
    pub process_info: ProcessInfo,
}