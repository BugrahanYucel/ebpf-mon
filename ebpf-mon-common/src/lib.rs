#![cfg_attr(target_arch = "bpf", no_std)]

use macros::bpf_target_code;

#[macro_use]
pub mod macros;

pub mod alloc;
pub mod buffer;
pub mod cgroup;
pub mod globals;
pub mod modules;
pub mod path;
pub mod policy;
pub mod string;
pub mod time;
pub mod utils;
pub mod network;
pub mod fs;
pub mod process;
pub mod capabilities;

bpf_target_code! {
    pub mod co_re;
}
