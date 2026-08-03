use crate::{modules::{EventRaw, EventInfo}};

pub type NetworkEventRaw = EventRaw<NetworkPayload>;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum Direction {
    Egress = 1u8,
    Ingress = 0u8,
}

#[repr(C)]
#[derive(Copy,Clone)]
pub struct NetworkPayload {
    pub comm: [u8; 16],
    pub pid: u32,
    pub tgid: u32,
    pub sk_uid: u32,
    pub sk_type: u16,
    pub skc_family: u16,
    pub protocol: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u32,
    pub dst_port: u32,
    pub doff_flags: u16,
    pub direction: Direction,
}

impl Default for EventRaw<NetworkPayload> {
    fn default() -> Self {
        let a = NetworkPayload {
            comm: [0u8; 16],
            pid: 0u32,
            tgid: 0u32,
            sk_uid: 0u32,
            sk_type: 0u16,
            skc_family: 0u16,
            protocol: 0u8,
            src_ip: 0u32,
            dst_ip: 0u32,
            src_port: 0u32,
            dst_port: 0u32,
            doff_flags: 0u16,
            direction: Direction::Ingress,
        };
        EventRaw { header: EventInfo::default(), payload: a }
    }
}

#[repr(C)]
pub struct ConnectionKey {
    pub container_ip: u32,
    pub container_port: u32,
    pub protocol: u8,
    pub _pad: u8
}

#[repr(C)]
pub struct RealSource {
    pub real_ip: u32,
    pub real_port: u32,
}