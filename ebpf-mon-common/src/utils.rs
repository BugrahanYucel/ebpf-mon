use core::ops::Rem;

#[inline(always)]
#[allow(unused_variables)]
pub fn bound_value_for_verifier(v: isize, min: isize, max: isize) -> isize {
    #[cfg(target_arch = "bpf")]
    {
        if v < min {
            return min;
        }
        if v > max {
            return max;
        }
    }
    v
}

// This function must be used to limit the size of a bpf_probe_read call
// it seems to be a generic enough solution that meet the requirements
// the verifier expects to be happy
#[inline(always)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_assignments)]
#[allow(clippy::let_and_return)]
pub fn cap_size<T: Copy + PartialOrd + Rem<Output = T>>(size: T, cap: T) -> T {
    let mut ret = size;
    #[cfg(target_arch = "bpf")]
    {
        if size >= cap {
            return cap;
        }
        ret = size % cap;
    }
    ret
}
