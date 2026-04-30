use aya_ebpf::{check_bounds_signed, helpers::gen::bpf_probe_read_user};

use super::Buffer;


impl <const N: usize> Buffer<N>{
    pub unsafe fn read_user_memory<P>(&mut self, from: *const P, size: u32) -> Result<(), u32>{
        let size = (size as i64).clamp(0, N as i64);

        if check_bounds_signed(size as i64, 0, N as i64){
            let ret = bpf_probe_read_user(self.buf.as_mut_ptr() as *mut _, size as u32, from as *const _);
            if ret != 0{
                return Err(1u32)
            }
        }

        self.len = size as usize;
        Ok(())

    }
}