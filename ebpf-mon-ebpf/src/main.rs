#![no_std]
#![no_main]

use aya_ebpf::{macros::map, maps::HashMap};

mod network;
mod filesystem;
mod process;
mod enforcement;

#[map]
static CGROUPS: HashMap<u64, u32> = HashMap::<u64, u32>::with_max_entries(32, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

pub fn cgroup_exists(cgroup: u64) -> bool {
    unsafe { CGROUPS.get(&cgroup).is_some() }
}