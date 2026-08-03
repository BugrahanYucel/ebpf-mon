use super::gen::{self, *};
use super::{file, mount, path, rust_shim_kernel_impl, rust_shim_user_impl, Core};

#[allow(non_camel_case_types)]
pub type sockaddr = Core<gen::sockaddr>;

impl sockaddr {
    rust_shim_kernel_impl!(pub, sockaddr, sa_family, u32);
    rust_shim_user_impl!(pub, sockaddr, sa_family, u32);
}

#[allow(non_camel_case_types)]
pub type sockaddr_in = Core<gen::sockaddr_in>;

impl From<sockaddr> for sockaddr_in {
    #[inline(always)]
    fn from(value: sockaddr) -> Self {
        Self::from_ptr(value.as_ptr() as *const _)
    }
}

impl sockaddr_in {
    rust_shim_kernel_impl!(pub, sockaddr_in, sin_family, u32);
    rust_shim_user_impl!(pub, sockaddr_in, sin_family, u32);

    rust_shim_kernel_impl!(pub, sockaddr_in, sin_port, u16);
    rust_shim_user_impl!(pub, sockaddr_in, sin_port, u16);

    rust_shim_kernel_impl!(pub, sockaddr_in, s_addr, u32);
    rust_shim_user_impl!(pub, sockaddr_in, s_addr, u32);
}

#[allow(non_camel_case_types)]
pub type unix_sock = Core<gen::unix_sock>;

impl unix_sock{
    rust_shim_kernel_impl!(pub, unix_sock, peer, sock);
    rust_shim_kernel_impl!(pub, unix_sock, path, path);
}


#[allow(non_camel_case_types)]
pub type sock_common = Core<gen::sock_common>;

impl sock_common{
    rust_shim_kernel_impl!(pub, sock_common, skc_family, u16);
    rust_shim_kernel_impl!(pub, sock_common, skc_daddr, u32);
    rust_shim_kernel_impl!(pub, sock_common, skc_rcv_saddr, u32);
    rust_shim_kernel_impl!(pub, sock_common, skc_dport, u32);
    rust_shim_kernel_impl!(pub, sock_common, skc_num, u32);
}


#[allow(non_camel_case_types)]
pub type sock = Core<gen::sock>;


impl From<sock> for unix_sock {
    #[inline(always)]
    fn from(value: sock) -> Self {
        Self::from_ptr(value.as_ptr() as *const _)
    }
}

impl sock{
    rust_shim_kernel_impl!(pub, sock, __sk_common, sock_common);
    
    pub unsafe fn sk_uid(&self) -> Option<gen::kuid_t> {
        if !self.is_null() && gen::shim_sock_sk_uid_exists(self.as_ptr_mut()) {
            return Some(gen::shim_sock_sk_uid(self.as_ptr_mut()));
        }
        None
    }
    
    rust_shim_kernel_impl!(pub, sock, sk_type, u16);
}

#[allow(non_camel_case_types)]
pub type socket = Core<gen::socket>;

impl socket {
    rust_shim_kernel_impl!(pub, socket, file, file);
    rust_shim_kernel_impl!(pub, socket, sk, sock);
    // rust_shim_kernel_impl!(pub, socket, flags);
}