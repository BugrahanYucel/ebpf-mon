use aya_ebpf::cty::c_void;

use super::gen::{self, *};
use super::{rust_shim_kernel_impl, Core};

#[allow(non_camel_case_types)]
pub type inode = Core<gen::inode>;

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;
const S_IFSOCK: u16 = 0o0140000;
const S_IFBLK: u16 = 0x6000;
const S_IFIFO: u16 = 0o010000;
const S_IFLNK: u16 = 0o120000;

impl inode {
    rust_shim_kernel_impl!(inode, i_ino, u64);
    rust_shim_kernel_impl!(inode, i_mode, u16);
    rust_shim_kernel_impl!(inode, i_sb, super_block);
    rust_shim_kernel_impl!(inode, i_size, i64);

    // for kernels < 6.7
    rust_shim_kernel_impl!(pub(self),_i_atime, inode, i_atime, timespec64);
    // for kernels in [6.7; 6.11]
    rust_shim_kernel_impl!(pub(self), ___i_atime, inode, __i_atime, timespec64);
    // for kernels >= 6.11
    rust_shim_kernel_impl!(pub(self), i_atime_sec, inode, i_atime_sec, i64);
    rust_shim_kernel_impl!(pub(self), i_atime_nsec, inode, i_atime_nsec, i64);

    pub unsafe fn i_atime(&self) -> Option<timespec64> {
        self._i_atime().or_else(|| self.___i_atime()).or_else(|| {
            Some(timespec64 {
                tv_sec: self.i_atime_sec()?,
                tv_nsec: self.i_atime_nsec()?,
            })
        })
    }

    // for kernels < 6.7
    rust_shim_kernel_impl!(pub(self),_i_mtime, inode, i_mtime, timespec64);
    // for kernels in [6.7; 6.11]
    rust_shim_kernel_impl!(pub(self), ___i_mtime, inode, __i_mtime, timespec64);
    // for kernels >= 6.11
    rust_shim_kernel_impl!(pub(self),i_mtime_sec, inode, i_mtime_sec, i64);
    rust_shim_kernel_impl!(pub(self),i_mtime_nsec, inode, i_mtime_nsec, i64);

    pub unsafe fn i_mtime(&self) -> Option<timespec64> {
        self._i_mtime().or_else(|| self.___i_mtime()).or_else(|| {
            Some(timespec64 {
                tv_sec: self.i_mtime_sec()?,
                tv_nsec: self.i_mtime_nsec()?,
            })
        })
    }

    // for kernels < 6.6
    rust_shim_kernel_impl!(pub(self),_i_ctime, inode, i_ctime, timespec64);
    // for kernels in [6.6; 6.11]
    rust_shim_kernel_impl!(pub(self), ___i_ctime, inode, __i_ctime, timespec64);
    // for kernels >= 6.11
    rust_shim_kernel_impl!(pub(self),i_ctime_sec, inode, i_ctime_sec, i64);
    rust_shim_kernel_impl!(pub(self),i_ctime_nsec, inode, i_ctime_nsec, i64);

    pub unsafe fn i_ctime(&self) -> Option<timespec64> {
        self._i_ctime().or_else(|| self.___i_ctime()).or_else(|| {
            Some(timespec64 {
                tv_sec: self.i_ctime_sec()?,
                tv_nsec: self.i_ctime_nsec()?,
            })
        })
    }

    #[inline(always)]
    pub unsafe fn is_file(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFREG)
    }

    #[inline(always)]
    pub unsafe fn is_sock(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFSOCK)
    }

    #[inline(always)]
    pub unsafe fn is_blk(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFBLK)
    }

    #[inline(always)]
    pub unsafe fn is_pipe(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFIFO)
    } 

    #[inline(always)]
    pub unsafe fn is_symlink(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFLNK)
    } 

}

#[allow(non_camel_case_types)]
pub type file = Core<gen::file>;

impl file {
    rust_shim_kernel_impl!(pub, file, f_path, path);
    rust_shim_kernel_impl!(pub, file, f_inode, inode);
    rust_shim_kernel_impl!(pub, file, f_flags, u32);

    #[inline(always)]
    pub unsafe fn is_file(&self) -> Option<bool> {
        self.f_inode()?.is_file()
    }

    #[inline(always)]
    pub unsafe fn is_sock(&self) -> Option<bool> {
        self.f_inode()?.is_sock()
    }

    #[inline(always)]
    pub unsafe fn is_blk(&self) -> Option<bool> {
        self.f_inode()?.is_blk()
    }

    #[inline(always)]
    pub unsafe fn is_pipe(&self) -> Option<bool> {
        self.f_inode()?.is_pipe()
    }

    #[inline(always)]
    pub unsafe fn is_symlink(&self) -> Option<bool> {
        self.f_inode()?.is_symlink()
    }

    rust_shim_kernel_impl!(pub, file, private_data, *mut c_void);
}

#[allow(non_camel_case_types)]
pub type fd = Core<gen::fd>;

impl fd {
    rust_shim_kernel_impl!(pub, fd, file, file);
}

#[allow(non_camel_case_types)]
pub type path = Core<gen::path>;

impl path {
    rust_shim_kernel_impl!(pub, path, mnt, vfsmount);
    rust_shim_kernel_impl!(pub, path, dentry, dentry);
}

#[allow(non_camel_case_types)]
pub type qstr = Core<gen::qstr>;

impl qstr {
    rust_shim_kernel_impl!(pub, qstr, name, *const u8);
    rust_shim_kernel_impl!(pub, qstr, hash_len, u64);

    #[inline(always)]
    pub unsafe fn hash(&self) -> Option<u32> {
        Some(self.hash_len()? as u32)
    }

    #[inline(always)]
    pub unsafe fn len(&self) -> Option<u32> {
        //(shim_qstr_hash_len(self.as_ptr_mut()) >> 32) as u32
        Some((self.hash_len()? >> 32) as u32)
    }
}

#[allow(non_camel_case_types)]
pub type dentry = Core<gen::dentry>;

const DCACHE_MOUNTED: u32 = 0x00010000;

impl dentry {
    rust_shim_kernel_impl!(pub, dentry, d_sb, super_block);
    rust_shim_kernel_impl!(pub, dentry, d_parent, dentry);
    rust_shim_kernel_impl!(pub, dentry, d_flags, u32);

    #[inline(always)]
    pub unsafe fn is_mountpoint(&self) -> Option<bool> {
        Some(self.d_flags()? & DCACHE_MOUNTED == DCACHE_MOUNTED)
    }

    rust_shim_kernel_impl!(pub, dentry, d_name, qstr);
    rust_shim_kernel_impl!(pub, dentry, d_inode, inode);

    #[inline(always)]
    pub unsafe fn is_file(&self) -> Option<bool> {
        self.d_inode()?.is_file()
    }
}

#[allow(non_camel_case_types)]
pub type file_system_type = Core<gen::file_system_type>;
impl file_system_type{
    rust_shim_kernel_impl!(pub(self), _name, file_system_type, name, *const i8);

    #[inline(always)]
    pub unsafe fn name(&self) -> Option<*const u8> {
        Some(self._name()? as *const u8)
    }
}

#[allow(non_camel_case_types)]
pub type super_block = Core<gen::super_block>;

impl super_block {
    rust_shim_kernel_impl!(pub, super_block, s_root, dentry);
    rust_shim_kernel_impl!(pub, super_block, s_type, file_system_type);
}

#[allow(non_camel_case_types)]
pub type mount = Core<gen::mount>;

impl mount {
    rust_shim_kernel_impl!(pub, mount, mnt, vfsmount);
    rust_shim_kernel_impl!(pub, mount, mnt_mountpoint, dentry);
    rust_shim_kernel_impl!(pub, mount, mnt_parent, mount);
    rust_shim_kernel_impl!(mount, mnt_mp, mountpoint);
}

#[allow(non_camel_case_types)]
pub type vfsmount = Core<gen::vfsmount>;

impl vfsmount {
    #[inline(always)]
    pub unsafe fn mount(&self) -> mount {
        mount::from_ptr(shim_mount_from_vfsmount(self.as_ptr_mut()))
    }

    rust_shim_kernel_impl!(pub, vfsmount, mnt_root, dentry);
}

#[allow(non_camel_case_types)]
pub type mountpoint = Core<gen::mountpoint>;

impl mountpoint {
    rust_shim_kernel_impl!(mountpoint, m_dentry, dentry);
}

#[allow(non_camel_case_types)]
pub type filename = Core<gen::filename>;

impl filename {
    rust_shim_kernel_impl!(pub, filename, name, *const i8);
    rust_shim_kernel_impl!(pub, filename, uptr, *const i8);

    #[inline(always)]
    fn from(value: filename) -> Self {
        Self::from_ptr(value.as_ptr() as *const _)
    }
}

#[allow(non_camel_case_types)]
pub type fs_struct = Core<gen::fs_struct>;

impl fs_struct {
    rust_shim_kernel_impl!(pub, fs_struct, root, path);
    rust_shim_kernel_impl!(pub, fs_struct, pwd, path);
}