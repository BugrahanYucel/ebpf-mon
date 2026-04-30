use crate::{
    buffer::Buffer,
    cgroup::Cgroup,
    macros::{bpf_target_code, not_bpf_target_code},
    path::Path,
};

const CONTAINER_MAX_ID: usize = 72;

mod process;
pub use process::*;

mod fs;
pub use fs::*;

mod ipc;
pub use ipc::*;

#[cfg(feature = "user")]
not_bpf_target_code! {
    mod user;
    pub use user::*;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Namespaces {
    pub mnt: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessInfo {
    pub comm: [u8; 16],
    pub uid: u32,
    pub gid: u32,
    pub tgid: i32,
    pub pid: i32,
    pub executable: Path,
    pub interpreter: Path,
    pub namespaces: Option<Namespaces>,
    pub start_time: u64,
    pub cgroup: Cgroup,
    pub args: Buffer<512>,
}

impl ProcessInfo {
    pub fn comm_str(&self) -> &str {
        if let Some(first) = self.comm.split(|&b| b == b'\0').next() {
            return unsafe { core::str::from_utf8_unchecked(first) };
        }
        unsafe { core::str::from_utf8_unchecked(&self.comm[..]) }
    }

    not_bpf_target_code! {
        #[inline(always)]
        pub fn comm_string(&self) -> std::string::String {
            self.comm_str().into()
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    InetOut = 0,
    InetIn,
    FileWrite,
    FileRead,
    Fork,
    Execve,
    Unknown,
}

impl Default for Type {
    fn default() -> Self {
        Self::Unknown
    }
}
pub const MAX_BPF_EVENT_SIZE: usize = max_bpf_event_size();

/// function defined so that it generates an error in case of
/// new Type created and we forgot to take it into account
const fn max_bpf_event_size() -> usize {
    1000
    //to be implemented
    // let mut i = 0;
    // let variants = Type::variants();
    // let mut max = 0;
    // loop {
    //     if i == variants.len() {
    //         break;
    //     }
    //     let size = match variants[i] {
    //         Type::SCHED_EXEC => ExecveEvent::size_of(),
    //         Type::SCHED_CLONE => ForkEvent::size_of(),
    //     };
    //     if size > max {
    //         max = size;
    //     }
    //     i += 1;
    // }
    // max
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct EventInfo {
    pub event_type: Type,
    pub process: ProcessInfo,
    pub parent: ProcessInfo,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EventRaw<T> {
    pub header: EventInfo,
    pub payload: T,
}

impl<T> EventRaw<T> {
    #[inline]
    pub const fn size_of() -> usize {
        core::mem::size_of::<EventRaw<T>>()
    }

    #[inline]
    pub fn ty(&self) -> Type {
        self.header.event_type
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut T {
        &mut self.payload
    }

    #[inline]
    pub fn as_ptr(&self) -> *const EventRaw<T> {
        self as *const EventRaw<T>
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut EventRaw<T> {
        self as *mut EventRaw<T>
    }

    #[inline]
    pub fn encode(&self) -> &[u8] {
        unsafe { self.as_byte_slice() }
    }

    #[inline]
    unsafe fn as_byte_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(
            (self as *const Self) as *const u8,
            core::mem::size_of::<EventRaw<T>>(),
        )
    }
}
