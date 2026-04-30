use aya_ebpf::helpers::gen::bpf_probe_read_kernel_str;
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_task_btf,
    bpf_probe_read_kernel_buf,
};
use crate::cgroup::Cgroup;
use crate::string::String;
use super::cred;

use super::gen::{self, *};
use super::{
    cgroup, core_read_kernel, file, fs_struct, nsproxy, pid_struct, rust_shim_kernel_impl, task_group, Core
};

const CONTAINER_MAX_ID: usize = 72;

#[allow(non_camel_case_types)]
pub type mm_struct = Core<gen::mm_struct>;
impl mm_struct {
    rust_shim_kernel_impl!(pub, mm_struct, arg_end, u64);
    rust_shim_kernel_impl!(pub, mm_struct, arg_start, u64);
    rust_shim_kernel_impl!(pub, mm_struct, exe_file, file);

    #[inline(always)]
    pub unsafe fn arg_len(&self) -> Option<u64>{
        let start = self.arg_start()?;
        let end = self.arg_end()?;
        Some({
            if end == 0 || start >= end {
                0
            }else{
                end - start
            }
        })
    }
}


#[allow(non_camel_case_types)]
pub type linux_binprm = Core<gen::linux_binprm>;

impl linux_binprm {
    rust_shim_kernel_impl!(pub, linux_binprm, file, file);
}


#[allow(non_camel_case_types)]
pub type task_struct = Core<gen::task_struct>;

impl task_struct {
    #[inline(always)]
    pub unsafe fn current() -> Self {
        Self::from_ptr(bpf_get_current_task() as *const _)
    }

    #[inline(always)]
    pub unsafe fn current_btf() -> Self {
        Self::from_ptr(bpf_get_current_task_btf() as *const _)
    }

    #[inline(always)]
    pub unsafe fn uuid(&self) -> u128 {
        unsafe { core::mem::transmute([bpf_get_current_pid_tgid(), self.as_ptr() as u64]) }
    }

    rust_shim_kernel_impl!(pub, task_struct, flags, u32);
    rust_shim_kernel_impl!(pub, task_struct, start_time, u64);
    rust_shim_kernel_impl!(pub, task_struct, cred, cred);

    rust_shim_kernel_impl!(pub(self), _start_boot_time, task_struct, start_boottime, u64);
    rust_shim_kernel_impl!(pub(self),_real_start_time, task_struct, real_start_time, u64);

    #[inline(always)]
    pub unsafe fn start_boottime(&self) -> Option<u64> {
        if let Some(sbt) = self._start_boot_time() {
            return Some(sbt);
        }

        if let Some(rst) = self._real_start_time() {
            return Some(rst);
        }

        None
    }

    #[inline(always)]
    pub unsafe fn real_start_time(&self) -> Option<u64> {
        self.start_boottime()
    }

    rust_shim_kernel_impl!(pub, task_struct, comm, *mut u8);

    #[inline(always)]
    pub unsafe fn comm_array(&self) -> Option<[u8; 16]> {
        let mut comm = [0u8; 16];
        bpf_probe_read_kernel_buf(self.comm()?, comm.as_mut_slice()).ok()?;
        Some(comm)
    }

    // #[inline(always)]
    // pub unsafe fn comm_str(&self) -> Option<String<16>> {
    //     let mut comm = String::<16>::new();
    //     comm.read_kernel_str_bytes(self.comm()?).ok()?;
    //     Some(comm)
    // }

    rust_shim_kernel_impl!(pub, task_struct, tgid, pid_t);
    rust_shim_kernel_impl!(pub, task_struct, pid, pid_t);


    rust_shim_kernel_impl!(pub, task_struct, group_leader, Self);
    rust_shim_kernel_impl!(pub, task_struct, real_parent, Self);
    rust_shim_kernel_impl!(pub, task_struct, nsproxy, nsproxy);

    rust_shim_kernel_impl!(pub, task_struct, mm, mm_struct);

    rust_shim_kernel_impl!(pub, task_struct, sched_task_group, task_group);

    rust_shim_kernel_impl!(pub, task_struct, fs, fs_struct);
    rust_shim_kernel_impl!(pub, task_struct, thread_pid, pid_struct);

    /// Read the namespaced tgid (the PID as seen inside the process's PID namespace).
    /// This is needed because /proc/[PID]/ paths use the namespaced PID,
    /// while bpf_get_current_pid_tgid() returns the host namespace PID.
    #[inline(always)]
    pub unsafe fn ns_tgid(&self) -> Option<u32> {
        let nsproxy = core_read_kernel!(self, nsproxy)?;
        let pid_ns = nsproxy.pid_ns_for_children()?;
        let level = pid_ns.level()?;

        // Use group_leader's thread_pid to get the tgid (not tid)
        let group_leader = core_read_kernel!(self, group_leader)?;
        let thread_pid = group_leader.thread_pid()?;

        // Use CO-RE shim to access pid->numbers[level].nr
        let nr = thread_pid.nr_at_level(level)?;
        Some(nr as u32)
    }

    #[inline(always)]
    pub unsafe fn get_cgroup_handle(&self) -> Option<cgroup>{      
        core_read_kernel!(self, sched_task_group, css, cgroup)
    }
    
    #[inline(always)]
    pub unsafe fn get_binprm_inode(&self) -> Option<u64>{
        core_read_kernel!(self, mm, exe_file, f_inode, i_ino)
    }

    #[inline(always)]
    pub unsafe fn is_memory_id_exists(&self) -> bool{
        shim_cgroup_subsys_id_memory_cgrp_id_exists()
    }
}


