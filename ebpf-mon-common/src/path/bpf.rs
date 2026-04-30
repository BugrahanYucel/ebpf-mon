use crate::co_re::{self, core_read_kernel, task_struct};
use crate::utils::{bound_value_for_verifier, cap_size};
use aya_ebpf::helpers::gen;

use super::{Metadata, Mode, Path, MAX_NAME};

type Result<T> = core::result::Result<T, u32>;

impl Path {
    #[inline(always)]
    unsafe fn init_from_inode(&mut self, i: &co_re::inode) -> Result<()> {
        let atime = core_read_kernel!(i, i_atime).ok_or(1u32)?;
        let ctime = core_read_kernel!(i, i_ctime).ok_or(1u32)?;
        let mtime = core_read_kernel!(i, i_mtime).ok_or(1u32)?;

        self.metadata = Some(Metadata {
            ino: core_read_kernel!(i, i_ino).ok_or(1u32)?,
            sb_ino: core_read_kernel!(i, i_sb, s_root, d_inode, i_ino)
                .ok_or(1u32)?,
            size: core_read_kernel!(i, i_size).ok_or(1u32)?,
            atime: atime.into(),
            ctime: ctime.into(),
            mtime: mtime.into(),
        });

        Ok(())
    }

    pub unsafe fn resolve_from_dentry(&mut self, dentry: &co_re::dentry, max_depth: u16) -> Result<()> {
        if dentry.is_null() {
            return Ok(());
        }
        
        let mut entry = *dentry;
        let d_inode = core_read_kernel!(entry, d_inode).ok_or(1u32)?;
        
        // Initialize
        self.mode = Mode::Prepend;
        self.init_from_inode(&d_inode)?;
        
        // Get mount info from current task
        let task = task_struct::current();
        let fs = core_read_kernel!(task, fs).ok_or(1u32)?;
        let root_path = core_read_kernel!(fs, root).ok_or(1u32)?;
        let root_mnt = root_path.mnt().ok_or(1u32)?;
        let mut mount = root_mnt.mount();
        let mut mnt_parent = mount.mnt_parent().ok_or(1u32)?;
        let mut mnt_root= root_mnt.mnt_root().ok_or(1u32)?;
        
        // Walk the dentry tree
        for _i in 0..max_depth {
            if entry == mnt_root {
                if mount == mnt_parent {
                    break;
                }

                entry = mount.mnt_mountpoint().ok_or(1u32)?;
                mount = mnt_parent;
                mnt_parent = mount.mnt_parent().ok_or(1u32)?;
                mnt_root = core_read_kernel!(mount, mnt, mnt_root).ok_or(1u32)?;
                continue;
            }

            let parent = entry.d_parent().ok_or(1u32)?;
            if entry == parent {
                break;
            }

            // read the qstr
            if !self.is_empty() {
                self.prepend_path_sep()?;
            }

            // prepend segment
            self.prepend_dentry(&entry)?;

            if parent.is_null() {
                break;
            }
            entry = parent;
        }

        // Always prepend "/" as the root - don't use the root dentry name
        // which could be "diff" or other overlay-internal names
        self.prepend_path_sep()?;

        Ok(())
    }

    #[inline(always)]
    pub unsafe fn core_resolve_file(&mut self, f: &co_re::file, max_depth: u16) -> Result<()> {
        if !f.is_null() {
            return self.core_resolve(&f.f_path().ok_or(1u32)?, max_depth);
        }
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn core_resolve(&mut self, p: &co_re::path, max_depth: u16) -> Result<()> {
        // if path is null we return Ok
        // this is mostly to massage our friend verifier
        if p.is_null() {
            return Ok(());
        }

        let mut entry = p.dentry().ok_or(1u32)?;
        let d_inode = core_read_kernel!(entry, d_inode).ok_or(1u32)?;

        // initialization
        self.mode = Mode::Prepend;
        self.init_from_inode(&d_inode)?;

        let mnt = p.mnt().ok_or(1u32)?;
        let mut mount = mnt.mount();

        let mut mnt_parent = mount.mnt_parent().ok_or(1u32)?;

        let mut mnt_root = mnt.mnt_root().ok_or(1u32)?;

        for _i in 0..max_depth {
            if entry == mnt_root {
                if mount == mnt_parent {
                    break;
                }

                entry = mount.mnt_mountpoint().ok_or(1u32)?;
                mount = mnt_parent;
                mnt_parent = mount.mnt_parent().ok_or(1u32)?;
                mnt_root = core_read_kernel!(mount, mnt, mnt_root).ok_or(1u32)?;
                continue;
            }

            let parent = entry.d_parent().ok_or(1u32)?;
            if entry == parent {
                break;
            }

            // read the qstr
            if !self.is_empty() {
                self.prepend_path_sep()?;
            }

            // prepend segment
            self.prepend_dentry(&entry)?;

            if parent.is_null() {
                break;
            }
            entry = parent;
        }

        // Always prepend "/" as the root - don't use the root dentry name
        // which could be "diff" or other overlay-internal names
        self.prepend_path_sep()?;

        Ok(())
    }

    fn prepend_path_sep(&mut self) -> Result<()> {
        let mut i = (self.buffer.len() - self.len() - 1) as isize;

        // we need to bound check index to massage the verifier
        i = bound_value_for_verifier(i, 0, (self.buffer.len() - 1) as isize);
        self.buffer[i as usize] = b'/';
        self.len += 1;
        Ok(())
    }

    #[inline(always)]
    fn space_left(&self) -> usize {
        self.buffer.len() - self.len()
    }

    #[inline(always)]
    pub unsafe fn prepend_dentry(&mut self, entry: &co_re::dentry) -> Result<()> {
        let name = core_read_kernel!(entry, d_name, name).ok_or(1u32)?;
        let len = core_read_kernel!(entry, d_name, len).ok_or(1u32)?;
        self.prepend_qstr_name(name, len)
    }

    unsafe fn prepend_qstr_name(&mut self, name: *const u8, qstr_len: u32) -> Result<()> {
        // needed so that the verifier knows self.len is bounded
        let left = self.space_left() as u32;
        // a way to restrict the length to read for the verifier
        let size = (qstr_len as u8) as u32;

        // we need this check otherwise verifier fails with invalid numeric 1u32
        if qstr_len > MAX_NAME as u32 {
            return Err(1u32);
        }

        if left < qstr_len {
            return Err(1u32);
        }

        let i = left - size;

        if i > self.buffer.len() as u32 {
            return Err(1u32);
        }

        let dst = &mut self.buffer[i as usize..];

        if gen::bpf_probe_read(
            dst.as_mut_ptr() as *mut _,
            // some probes were taking size out of stack discarding
            // any previous checks so we force new value checking
            cap_size(qstr_len, MAX_NAME as u32),
            name as *const _,
        ) >= 0
        {
            self.len += size;
            self.depth += 1;
        } else {
            return Err(1u32);
        }

        Ok(())
    }

    pub unsafe fn bpf_probe_read_str(&mut self, addr: u64) -> Result<()> {
        self.mode = Mode::Append;

        let len = gen::bpf_probe_read_str(
            self.buffer.as_ptr() as *mut _,
            core::mem::size_of_val(&self.buffer) as u32,
            addr as *const _,
        );
        if len <= 0 {
            return Err(1u32);
        }
        // len is the size read including NULL byte
        // len cannot be 0 so it is Ok to substract 1
        self.len = (len - 1) as u32;
        Ok(())
    }

    #[inline]
    /// function aiming at being used in bpf_printk
    pub unsafe fn as_str_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    pub unsafe fn to_aya_debug_str(&self) -> &str {
        return core::str::from_utf8_unchecked(&self.buffer[..]);
        //return core::str::from_utf8_unchecked(self.as_slice());
    }
}