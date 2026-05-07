use crate::{macros::bpf_target_code, macros::not_bpf_target_code, macros::unroll_32, utils::cap_size};

use super::time::Time;
use super::utils::bound_value_for_verifier;

#[allow(unused_imports)]
use core::{cmp::min, ffi::c_long};

not_bpf_target_code! {
    mod user;
}

bpf_target_code! {
    mod bpf;
}

// for path resolution
pub const MAX_PATH_DEPTH: u16 = 128;
// in theory MAX_PATH_LEN is 4096, however (considering the
// TM where someones wants to fool path resolution) path resolution can
// be exhausted by making a path depth > 128 so it is not so
// relevant to use 4096 as MAX_PATH_LEN (as it does not prevent
// anything to be bypassed). However, making a smaller PATH_LEN makes
// the program less memory consuming. Maybe a path exhaustion event should
// be raised when limits are reached.
pub const MAX_PATH_LEN: usize = 1024;
pub const MAX_NAME: usize = u8::MAX as usize;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Append,
    Prepend,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    // inode number of the file
    pub ino: u64,
    // inode number of superblock
    pub sb_ino: u64,
    pub size: i64,
    pub atime: Time,
    pub mtime: Time,
    pub ctime: Time,
}

type Error = u32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq)]
pub struct Path {
    buffer: [u8; MAX_PATH_LEN],
    null: u8, // easy str break
    len: u32,
    depth: u16,
    real: bool, // flag if path is a realpath
    pub metadata: Option<Metadata>,
    pub mode: Mode,
    pub error: Option<Error>,
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        let meta_eq = {
            if self.metadata.is_none() && other.metadata.is_none() {
                return true;
            }

            if let Some(sm) = self.metadata {
                if let Some(om) = other.metadata {
                    // we don't consider atime (access time)
                    // as being relevant for path Eq checking
                    return sm.ino == om.ino
                        && sm.sb_ino == om.sb_ino
                        && sm.size == om.size
                        && sm.mtime == om.mtime
                        && sm.ctime == om.ctime;
                }
            }

            false
        };

        self.buffer == other.buffer
            && self.len == other.len
            && self.depth == other.depth
            && self.real == other.real
            && meta_eq
    }
}

impl Default for Path {
    fn default() -> Self {
        Path {
            buffer: [0; MAX_PATH_LEN],
            null: 0,
            len: 0,
            depth: 0,
            real: false,
            metadata: None,
            mode: Mode::Append,
            error: None,
        }
    }
}

// common implementation
impl Path {
    pub fn copy_from_u8_array(
        &mut self,
        src: &[u8],
        mode: Mode,
    ) -> core::result::Result<usize, usize> {
        // Find the null terminator in source
        let src_len = src.iter()
            .position(|&c| c == 0)
            .unwrap_or(src.len());
        
        let n = min(src_len, self.buffer.len());
        
        self.len = 0;
        self.mode = mode;
        self.error = None;
        
        let mut start = 0;
        if matches!(mode, Mode::Prepend) {
            start = self.buffer.len() - n;
        }
        
        self.buffer[start..start + n].copy_from_slice(&src[..n]);
        self.len = n as u32;
        
        if src_len > self.buffer.len() {
            self.error = Some(1u32);
            return Err(n);
        }
        
        Ok(n)
    }

    pub fn copy_from_str<T: AsRef<str>>(
        &mut self,
        s: T,
        mode: Mode,
    ) -> core::result::Result<usize, usize> {
        let src = s.as_ref().as_bytes();
        let n = min(src.len(), self.buffer.len());

        self.len = 0;
        self.mode = mode;
        self.error = None;

        let mut start = 0;
        if matches!(mode, Mode::Prepend) {
            start = self.buffer.len() - n;
        }
        self.buffer[start..start + n].copy_from_slice(&src[..n]);

        self.len = n as u32;

        if src.len() > self.buffer.len() {
            self.error = Some(1u32);
            return Err(n);
        }

        Ok(n)
    }

    pub fn copy_from(&mut self, other: &Path) {
        unsafe { core::ptr::copy_nonoverlapping(other as *const Path, self as *mut Path, 1) };
    }

    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    pub fn is_absolute(&self) -> bool {
        let s = self.as_slice();
        if !s.is_empty() {
            return s[0] == b'/';
        }
        false
    }

    pub fn is_realpath(&self) -> bool {
        self.real
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.len = 0;
        self.depth = 0;
        self.real = false;
        self.metadata = None;
        self.error = None;
    }

    #[inline(always)]
    pub fn get_byte(&self, i: usize) -> core::result::Result<u8, Error> {
        let i = match self.mode {
            Mode::Append => i,
            Mode::Prepend => {
                let len = self.len;
                if len > self.buffer.len() as u32 {
                    return Err(1u32);
                }
                self.buffer.len() - len as usize + i
            }
        };

        // bound checking
        if i < self.buffer.len() {
            return Ok(unsafe { *self.buffer.get_unchecked(i) });
        }

        Err(1u32)
    }

    #[inline(always)]
    pub fn starts_with<T: Sized + AsRef<[u8]>>(&self, start: T) -> bool {
        let start = start.as_ref();

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

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match self.mode {
            Mode::Append => {
                let len =
                    bound_value_for_verifier(self.len as isize, 0, self.buffer.len() as isize);
                &self.buffer[..len as usize]
            }
            Mode::Prepend => {
                let len = cap_size(self.len(), MAX_PATH_LEN - 255);
                &self.buffer[(self.buffer.len() - len)..]
            }
        }
    }

    /// Returns the raw buffer and the start offset of the path data.
    /// Use `idx & (MAX_PATH_LEN - 1)` when indexing to satisfy the BPF verifier.
    #[inline(always)]
    pub fn raw_buffer_and_offset(&self) -> (&[u8; MAX_PATH_LEN], usize) {
        match self.mode {
            Mode::Append => (&self.buffer, 0),
            Mode::Prepend => {
                let len = cap_size(self.len(), MAX_PATH_LEN - 255);
                (&self.buffer, MAX_PATH_LEN - len)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn depth(&self) -> usize {
        self.depth as usize
    }

    /// Get a fixed-size reference to the first MAX_PATH_DEPTH bytes of the buffer.
    /// This is useful for path classification where we only need to check prefixes.
    /// Returns a statically-sized array reference that the eBPF verifier can track.
    /// 
    /// WARNING: This method does NOT account for Prepend mode and will return
    /// incorrect data when mode is Prepend. Use `to_classify_buffer()` instead.
    #[inline(always)]
    pub fn as_classify_buffer(&self) -> &[u8; MAX_PATH_DEPTH as usize] {
        // Safety: buffer is MAX_PATH_LEN (1024) bytes, MAX_PATH_DEPTH is 128
        // So we're always within bounds.
        // We use pointer cast to get a fixed-size array reference that the verifier understands.
        unsafe { &*(self.buffer.as_ptr() as *const [u8; MAX_PATH_DEPTH as usize]) }
    }

    /// Returns a copy of the first MAX_PATH_DEPTH bytes of the path content,
    /// properly left-aligned for classification regardless of storage mode.
    /// 
    /// This handles both Append mode (data at start of buffer) and Prepend mode
    /// (data at end of buffer) correctly. Uses verifier-friendly operations:
    /// - Long paths (>= 128 bytes): direct pointer cast
    /// - Short paths (< 128 bytes): unrolled loop copy (32 iterations, enough for classification)
    #[inline(always)]
    pub fn to_classify_buffer(&self) -> [u8; MAX_PATH_DEPTH as usize] {
        match self.mode {
            Mode::Append => {
                // In Append mode, data is at the start of buffer
                // Direct pointer cast - no stack allocation, fully verifier-friendly
                unsafe { *(self.buffer.as_ptr() as *const [u8; MAX_PATH_DEPTH as usize]) }
            }
            Mode::Prepend => {
                // For Prepend mode, path is at the end of buffer
                // Path starts at buffer[MAX_PATH_LEN - len]
                
                let len = self.len as usize;
                
                if len == 0 || len > MAX_PATH_LEN {
                    return [0u8; MAX_PATH_DEPTH as usize];
                }
                
                if len >= MAX_PATH_DEPTH as usize {
                    // Long paths (>= 128 bytes): use pointer cast (verifier-friendly)
                    // start = MAX_PATH_LEN - len, which is in range [0, MAX_PATH_LEN - MAX_PATH_DEPTH]
                    let bounded_len = cap_size(len, MAX_PATH_LEN);
                    let start = MAX_PATH_LEN - bounded_len;
                    
                    // Explicitly bound start for verifier
                    let bounded_start = bound_value_for_verifier(
                        start as isize,
                        0,
                        (MAX_PATH_LEN - MAX_PATH_DEPTH as usize) as isize
                    ) as usize;
                    
                    unsafe { 
                        *(self.buffer.as_ptr().add(bounded_start) as *const [u8; MAX_PATH_DEPTH as usize])
                    }
                } else {
                    // Short paths (< 128 bytes): use unrolled loop to copy
                    // This handles paths like /proc/123/cmdline, /etc/hostname, etc.
                    // We copy 32 bytes which is enough for all classification prefixes
                    let mut buf = [0u8; MAX_PATH_DEPTH as usize];
                    
                    // Path starts at buffer[MAX_PATH_LEN - len]
                    // Bound len to ensure start is valid  
                    let bounded_len = cap_size(len, MAX_PATH_DEPTH as usize);
                    
                    // Bound start to valid range [896, 1023] for short paths
                    let start = bound_value_for_verifier(
                        (MAX_PATH_LEN - bounded_len) as isize,
                        (MAX_PATH_LEN - MAX_PATH_DEPTH as usize) as isize,
                        (MAX_PATH_LEN - 1) as isize
                    ) as usize;
                    
                    // Use unrolled loop - 32 iterations, all indices bounded
                    // 32 bytes is enough for prefixes like /proc/12345/cmdline
                    unroll_32!(I, {
                        let src_idx = bound_value_for_verifier(
                            (start + I) as isize,
                            0,
                            (MAX_PATH_LEN - 1) as isize
                        ) as usize;
                        buf[I] = self.buffer[src_idx];
                    });
                    
                    buf
                }
            }
        }
    }

    /// Returns a reference to the full internal buffer.
    /// Useful for fixed-size copy operations that the eBPF verifier can track.
    #[inline(always)]
    pub fn as_full_buffer(&self) -> &[u8; MAX_PATH_LEN] {
        &self.buffer
    }

    /// FNV-1a hash of the path content. Produces identical output to
    /// `fnv1a_hash_bytes(path_string.as_bytes())` in userspace.
    /// Uses bounded indexing so the BPF verifier can track all accesses.
    #[inline(always)]
    pub fn hash_path(&self) -> u64 {
        let (buf, start) = self.raw_buffer_and_offset();
        let len = self.len();
        let mut hash: u64 = 0xcbf29ce484222325u64;
        let mut i: usize = 0;
        while i < MAX_PATH_LEN {
            if i >= len {
                break;
            }
            let idx = (start + i) & (MAX_PATH_LEN - 1);
            let byte = buf[idx];
            if byte == 0 {
                break;
            }
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3u64);
            i += 1;
        }
        hash
    }
}
