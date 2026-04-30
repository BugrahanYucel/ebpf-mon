use aya_ebpf::helpers::gen::bpf_get_current_cgroup_id;

use super::gen::{self, *};
use super::{rust_shim_kernel_impl, Core};

#[allow(non_camel_case_types)]
pub type cgroup = Core<gen::cgroup>;
impl cgroup {
    rust_shim_kernel_impl!(cgroup, kn, kernfs_node);
}

#[allow(non_camel_case_types)]
pub type cgroup_subsys_state = Core<gen::cgroup_subsys_state>;

impl cgroup_subsys_state {
    rust_shim_kernel_impl!(cgroup_subsys_state, cgroup, cgroup);

    pub unsafe fn get(&self, i: usize) -> Self{
        self.as_ptr().add(i).into()
    }
}

#[allow(non_camel_case_types)]
pub type task_group = Core<gen::task_group>;

impl task_group {
    rust_shim_kernel_impl!(task_group, css, cgroup_subsys_state);

    pub unsafe fn get(&self, i: usize) -> cgroup_subsys_state{
        if let Some(subsys) = self.css(){
            return subsys.as_ptr().add(i).into();
        };

        (0 as *const gen::cgroup_subsys_state).into() 
    }
}


#[allow(non_camel_case_types)]
pub type kernfs_node_older_v55 = Core<gen::kernfs_node___older_v55>;

#[allow(non_camel_case_types)]
pub type kernfs_node = Core<gen::kernfs_node>;

impl kernfs_node {
    rust_shim_kernel_impl!(pub(self),_name, kernfs_node, name, *const i8);

    #[inline(always)]
    pub unsafe fn name(&self) -> Option<*const u8> {
        Some(self._name()? as *const u8)
    }

    pub unsafe fn id(&self) -> Option<u64>{
        let old_kernfs = kernfs_node_older_v55::from_ptr(self.as_ptr() as *const _);
        if shim_kernfs_node___older_v55_id_exists(old_kernfs.as_ptr_mut()) {
            let id = shim_kernfs_node___older_v55_id(old_kernfs.as_ptr_mut());
            return Some(id.id)
        } else {
            return Some(shim_kernfs_node_id(self.as_ptr_mut()))
        }
        //Some(bpf_get_current_cgroup_id())
    }

    rust_shim_kernel_impl!(kernfs_node, parent, kernfs_node);
}