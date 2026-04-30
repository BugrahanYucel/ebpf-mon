use super::gen::{self, *};
use super::{mount, rust_shim_kernel_impl, Core};

#[allow(non_camel_case_types)]
pub type nsproxy = Core<gen::nsproxy>;

impl nsproxy {
    rust_shim_kernel_impl!(pub, nsproxy, mnt_ns, mnt_namespace);
    rust_shim_kernel_impl!(pub, nsproxy, uts_ns, uts_namespace);
    rust_shim_kernel_impl!(pub, nsproxy, pid_ns_for_children, pid_namespace);
}

#[allow(non_camel_case_types)]
pub type pid_namespace = Core<gen::pid_namespace>;

impl pid_namespace {
    rust_shim_kernel_impl!(pub, pid_namespace, level, u32);
}

#[allow(non_camel_case_types)]
pub type pid_struct = Core<gen::pid>;

impl pid_struct {
    rust_shim_kernel_impl!(pub, pid, level, u32);

    /// Read the PID number at a given namespace level via CO-RE.
    #[inline(always)]
    pub unsafe fn nr_at_level(&self, level: u32) -> Option<i32> {
        if self.is_null() {
            return None;
        }
        Some(gen::shim_pid_nr_at_level(self.as_ptr() as *mut _, level))
    }
}

#[allow(non_camel_case_types)]
pub type ns_common = Core<gen::ns_common>;

impl ns_common {
    rust_shim_kernel_impl!(ns_common, inum, u32);
}

#[allow(non_camel_case_types)]
pub type mnt_namespace = Core<gen::mnt_namespace>;

impl mnt_namespace {
    rust_shim_kernel_impl!(mnt_namespace, ns, ns_common);
    rust_shim_kernel_impl!(mnt_namespace, root, mount);
    rust_shim_kernel_impl!(mnt_namespace, mounts, u32);
}

#[allow(non_camel_case_types)]
pub type uts_namespace = Core<gen::uts_namespace>;

impl uts_namespace {
    rust_shim_kernel_impl!(uts_namespace, ns, ns_common);
    rust_shim_kernel_impl!(uts_namespace, name, new_utsname);
}

#[allow(non_camel_case_types)]
pub type new_utsname = Core<gen::new_utsname>;

impl new_utsname {
    rust_shim_kernel_impl!(new_utsname, sysname, *mut i8);
    rust_shim_kernel_impl!(new_utsname, nodename, *mut i8);
    rust_shim_kernel_impl!(new_utsname, release, *mut i8);
    rust_shim_kernel_impl!(new_utsname, version, *mut i8);
    rust_shim_kernel_impl!(new_utsname, machine, *mut i8);
    rust_shim_kernel_impl!(new_utsname, domainname, *mut i8);
}