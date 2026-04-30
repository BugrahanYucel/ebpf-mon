use crate::{
    macros::{bpf_target_code, not_bpf_target_code},
    string::String,
};

const CGROUP_PATH_MAX: usize = 128;
const CGROUP_STRING_LEN: usize = CGROUP_PATH_MAX * 2;
const CONTAINER_ID_MAX_BUF: usize = 72;

not_bpf_target_code! {
    #[cfg(feature = "user")]
    mod user;
}

bpf_target_code! {
    mod bpf;
}

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Container_Type {
    KUBERNETES,
    DOCKER,
    LXC,
    PODMAN,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Cgroup {
    pub cgroup_path: String<CGROUP_STRING_LEN>,
    pub cgroup_id: [u8; CONTAINER_ID_MAX_BUF],
    pub is_parsed: u32,
    pub cgrp_id: u64,
}

impl Default for Cgroup {
    fn default() -> Self {
        Cgroup {
            cgroup_path: String::<CGROUP_STRING_LEN>::new(),
            cgroup_id: [0; CONTAINER_ID_MAX_BUF],
            is_parsed: 0,
            cgrp_id: 0,
        }
    }
}

impl Cgroup {
    pub fn new() -> Self {
        Cgroup {
            cgroup_path: String::<CGROUP_STRING_LEN>::new(),
            cgroup_id: [0; CONTAINER_ID_MAX_BUF],
            is_parsed: 0,
            cgrp_id: 0,
        }
    }
}
