macro_rules! bpf_target_code {
    ($($tokens:tt)*) => {
        cfg_if::cfg_if!{
            if #[cfg(any(target_arch = "bpf"))] {
                $($tokens)*
            }
        }
    };
}

pub(crate) use bpf_target_code;

macro_rules! not_bpf_target_code {
    ($($tokens:tt)*) => {
        cfg_if::cfg_if!{
            // negating target_arch = "bpf" causes IDE macro analysis not working properly (no autocomplete/help)
            if #[cfg(any(target_arch = "x86_64", target_arch="x86", target_arch="mips", target_arch="powerpc", target_arch="powerpc64", target_arch="arm", target_arch="aarch64"))] {
                // identity
                $($tokens)*
            }
        }
    };
}

macro_rules! unroll_impl {
    ($i:ident, $body:block, []) => {};
    ($i:ident, $body:block, [$first:tt $($rest:tt)*]) => {
        { const $i: usize = $first; $body }
        unroll_impl!($i, $body, [$($rest)*]);
    };
}

/// Unroll a loop from 0 to 119 (120 iterations)
macro_rules! unroll_120 {
    ($i:ident, $body:block) => {
        unroll_impl!($i, $body, [
            0 1 2 3 4 5 6 7 8 9
            10 11 12 13 14 15 16 17 18 19
            20 21 22 23 24 25 26 27 28 29
            30 31 32 33 34 35 36 37 38 39
            40 41 42 43 44 45 46 47 48 49
            50 51 52 53 54 55 56 57 58 59
            60 61 62 63 64 65 66 67 68 69
            70 71 72 73 74 75 76 77 78 79
            80 81 82 83 84 85 86 87 88 89
            90 91 92 93 94 95 96 97 98 99
            100 101 102 103 104 105 106 107 108 109
            110 111 112 113 114 115 116 117 118 119
        ]);
    };
}

/// Unroll a loop from 0 to 6 (7 iterations) - for PID parsing
macro_rules! unroll_7 {
    ($i:ident, $body:block) => {
        unroll_impl!($i, $body, [0 1 2 3 4 5 6]);
    };
}

/// Unroll a loop from 0 to 9 (10 iterations)
macro_rules! unroll_10 {
    ($i:ident, $body:block) => {
        unroll_impl!($i, $body, [0 1 2 3 4 5 6 7 8 9]);
    };
}

/// Unroll a loop from 0 to 31 (32 iterations) - for short path copying
/// 32 bytes is enough for all classification prefixes like /proc/*/cmdline
macro_rules! unroll_32 {
    ($i:ident, $body:block) => {
        unroll_impl!($i, $body, [
            0 1 2 3 4 5 6 7 8 9
            10 11 12 13 14 15 16 17 18 19
            20 21 22 23 24 25 26 27 28 29
            30 31
        ]);
    };
}

pub(crate) use not_bpf_target_code;
pub(crate) use unroll_impl;
pub(crate) use unroll_120;
pub(crate) use unroll_32;
pub(crate) use unroll_7;
pub(crate) use unroll_10;
