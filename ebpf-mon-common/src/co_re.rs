pub mod gen;
pub use gen::timespec64;

mod core_task_struct;
pub use core_task_struct::*;

mod core_nsproxy;
pub use core_nsproxy::*;

mod core_fs;
pub use core_fs::*;

mod core_cred;
pub use core_cred::*;

mod core_cgroup;
pub use core_cgroup::*;

mod core_net;
pub use core_net::*;

#[derive(Clone, Copy)]
pub struct Core<T> {
    ptr: *const T,
}

impl<T> PartialEq for Core<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl<T> From<*mut T> for Core<T> {
    fn from(value: *mut T) -> Self {
        Self::from_ptr(value)
    }
}

impl<T> From<*mut [T; 0usize]> for Core<T> {
    fn from(value: *mut [T; 0]) -> Self {
        Self::from_ptr(value.cast()) 
    }
}

impl<T> From<*const T> for Core<T> {
    fn from(value: *const T) -> Self {
        Self::from_ptr(value)
    }
}

impl<T> Core<T>{

    #[inline(always)]
    pub fn is_null(&self) -> bool{
        self.ptr.is_null()
    }

    pub fn as_ptr(&self) -> *const T {
        self.ptr as *mut _
    }

    fn as_ptr_mut(&self) -> *mut T {
        self.ptr as *mut _
    }

    pub fn from_ptr(ptr: *const T) -> Self{
        Core{
            ptr: ptr as *const _,
        }
    }
}



macro_rules! rust_shim_kernel_impl {
    ($struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl! (pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl! ($pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $fn_name:ident, $struct: ident, $member:ident, $ret:ty) => {
        #[inline(always)]
        $pub unsafe fn $fn_name(&self) -> Option<$ret> {
            if !self.is_null()
                && paste::paste! {[<shim_ $struct _ $member _exists>]}(self.as_ptr_mut())
            {
                return Some(paste::paste! {[<shim_ $struct _ $member>]}(self.as_ptr_mut()).into());
            }
            None
        }
    };
}

pub(crate) use rust_shim_kernel_impl;

macro_rules! rust_shim_user_impl {
    ($pub:vis, $struct:ident, $member:ident, $ret:ty) => {
        rust_shim_user_impl! ($pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $fn_name:ident, $struct: ident, $member:ident, $ret:ty) => {
        paste::item!{
        #[inline(always)]
        $pub unsafe fn [<$fn_name _user>] (&self) -> Option<$ret> {
            if !self.is_null()
                && [<shim_ $struct _ $member _exists>](self.as_ptr_mut())
            {
                return Some(paste::paste! {[<shim_ $struct _ $member _user>]}(self.as_ptr_mut()).into());
            }
            None
        }
        }
    };
}

pub(crate) use rust_shim_user_impl;
#[macro_export]
macro_rules! core_read_kernel {
    ($struc:expr, $field:ident) => {
        $struc
            .$field()
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        $struc
            .$first()
            $(
            .and_then(|r| r.$rest())
            )*
    };
}

pub use core_read_kernel;