use crate::macros::not_bpf_target_code;

pub const MAX_PROCS: usize = 4;
pub const IPC_POLICY_MAP: &str = "IPC_POLICY";

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IPCPolicyBpf {
    pub allowed_procs: [u64; MAX_PROCS],
    pub denied_procs: [u64; MAX_PROCS],
}

impl IPCPolicyBpf {
    pub fn new(allowed_procs: [u64; MAX_PROCS], denied_procs: [u64; MAX_PROCS]) -> Self {
        Self {
            allowed_procs,
            denied_procs,
        }
    }

    pub fn check_permission(&self, exe_inode: u64) -> bool {
        if self.allowed_procs[..MAX_PROCS - 1].contains(&exe_inode) {
            return true;
        }

        if self.denied_procs[..MAX_PROCS - 1].contains(&exe_inode) {
            return false;
        }

        return true;
    }
}

not_bpf_target_code! {
    #[cfg(feature = "user")]
    unsafe impl aya::Pod for IPCPolicyBpf {}
}
