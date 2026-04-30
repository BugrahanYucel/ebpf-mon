use aya_ebpf::helpers::{bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes};

use super::{String};

impl<const N: usize> String<N> {
    #[inline(always)]
    pub unsafe fn read_user_str_bytes<T>(&mut self, src: *const T) -> Result<(), u32> {
        // do not return error if attempting to read null pointer
        if !src.is_null() {
            let s = bpf_probe_read_user_str_bytes(src as *const _, self.s.as_mut())
                .map_err(|_| 1u32)?;
            self.len = s.len();
        }
        Ok(())
    }

    /// This function can be used to append reading to the current string. However there is
    /// a limitation so that the verifier does not complain. It can read only up to half the size
    /// of the String. This is because we don't have the size of the string prior to reading it.
    /// Without the string len before bpf_probe_read_kernel_str we cannot upper bound the read limit
    /// efficiently so bpf_probe_read_kernel_str always think upper bound is the String size.
    pub unsafe fn append_kernel_str_bytes<T>(&mut self, src: *const T) -> Result<usize, u32> {
        let limit = self.s.len() / 2;

        // do not return error if attempting to read null pointer
        if !src.is_null() {
            let k = self.len;

            if k >= limit {
                return Err(1u32);
            }

            let dst = self.s[k..limit].as_mut();
            let s = bpf_probe_read_kernel_str_bytes(src as *const _, dst)
                .map_err(|_| 1u32)?;
            self.len += s.len();
            return Ok(s.len());
        }
        Ok(0)
    }

    #[inline(always)]
    pub unsafe fn read_kernel_str_bytes<T>(&mut self, src: *const T) -> Result<(), u32> {
        // do not return error if attempting to read null pointer
        if !src.is_null() {
            let s = bpf_probe_read_kernel_str_bytes(src as *const _, self.s.as_mut())
                .map_err(|_| 1u32)?;
            self.len = s.len();
        }
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn as_str(&self) -> &str {
        // all bytes are supposed to be valid utf8 code points
        // verifier does not like reading until self.len
        core::str::from_utf8_unchecked(&(self.s.as_ref())[..])
    }

    #[inline(always)]
    pub fn get_byte(&self, i: usize) -> core::result::Result<u8, u32> {
        // bound checking
        if i < self.s.len() {
            return Ok(unsafe { *self.s.get_unchecked(i) });
        }

        Err(1u32)
    }
    
    pub unsafe fn starts_with<T: Sized + AsRef<[u8]>>(&self, s: T) -> bool {
        let start = s.as_ref();
        // we cannot start with something that is bigger
        if start.len() > self.len() {
            return false;
        }

        for i in 0..core::mem::size_of::<T>() {
            if i == start.len() || i == self.len() {
                break;
            }

            let Ok(b) = self.get_byte(i) else {
                return false;
            };

            if b != unsafe { *start.get_unchecked(i) } {
                return false;
            }
        }

        true
    }  
}