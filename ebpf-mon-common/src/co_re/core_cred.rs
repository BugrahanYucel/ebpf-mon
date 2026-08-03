use super::gen::{self, *};
use super::{Core};


#[allow(non_camel_case_types)]
pub type cred_older = Core<gen::cred_cap_t_older_v515>;

#[allow(non_camel_case_types)]
pub type cred = Core<gen::cred>;

impl cred {
    #[inline(always)]
    pub unsafe fn uid(&self) -> u32 {
        shim_cred_uid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn gid(&self) -> u32 {
        shim_cred_gid(self.as_ptr_mut())
    }

    pub unsafe fn cap_effective(&self) -> Option<u64> {
        let older = cred_older::from_ptr(self.as_ptr() as *const _);
        if shim_cred_cap_t_older_v515_cap_effective_exists(older.as_ptr_mut()) {
            let cap = shim_cred_cap_t_older_v515_cap_effective(older.as_ptr_mut());
            let val = shim_kernel_cap_t_older_v515_cap(cap);
            // let val_1 = *(val.add(0));
            // let val_2 = *(val.add(1));
            return Some(((val.wrapping_add(0) as u64) << 32) | (val.wrapping_add(1) as u64))
        } else {
            return Some(shim_cred_cap_effective(self.as_ptr_mut()));
        }
    }
}