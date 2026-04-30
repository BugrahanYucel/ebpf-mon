use aya_ebpf::{bindings::bpf_attach_type::BPF_CGROUP_INET4_BIND, cty::c_void};

use crate::{co_re::{self, core_read_kernel, kernfs_node}, utils::bound_value_for_verifier};

use super::{Cgroup, CGROUP_STRING_LEN, CONTAINER_ID_MAX_BUF};

const MAX_CGROUP_DEPTH: usize = 32;
const DOCKER_PREFIX: usize = 7;

impl Cgroup {
    /// Resolve the cgroup path. The algorithm resolves the path in reverse order
    /// to minimize the number of instructions.
    #[inline(always)]
    pub unsafe fn resolve(&mut self, cgroup: co_re::cgroup) -> Result<(), u32> {
        if cgroup.is_null() {
            return Ok(());
        }

        let mut kn: kernfs_node = core_read_kernel!(cgroup, kn).ok_or(1u32)?;

        for i in 0..MAX_CGROUP_DEPTH {
            let kn_name = core_read_kernel!(kn, name).ok_or(1u32)?;

            self.cgroup_path.append_kernel_str_bytes(kn_name).map_err(|_| {
                1u32
            })?;

            if i == 0 {
                //self.parse_container_id();
                if let Some(id)  = kn.id(){
                    self.cgrp_id = id;
                }
            }

            kn = core_read_kernel!(kn, parent).ok_or(1u32)?;
            if kn.is_null() {
                break;
            }
        
            self.cgroup_path.push_byte(b'/').map_err(|_| {
                1u32
            })?;
        }

        Ok(())
    }

    pub unsafe fn read_from_raw(&mut self, ptr: *const u8) -> Result<(), u32>{
        self.cgroup_path.read_kernel_str_bytes(ptr as *const _).map_err(|_| 1u32)?;
        Ok(())
    }

    pub unsafe fn parse_container_id(&mut self) {
        if self.cgroup_path.starts_with("docker-") {
            //self.cgroup_id[..src.len()].copy_from_slice(src);  
            let cgroup_path_len = self.cgroup_path.s.len();
            core::ptr::copy_nonoverlapping(self.cgroup_path.s[DOCKER_PREFIX..cgroup_path_len].as_mut_ptr(), self.cgroup_id[..bound_value_for_verifier(cgroup_path_len as isize, 0, CONTAINER_ID_MAX_BUF as isize) as usize - DOCKER_PREFIX].as_mut_ptr(), cgroup_path_len - DOCKER_PREFIX);
        }
    }  
}