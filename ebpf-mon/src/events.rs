use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use ebpf_mon_common::fs::{FsEventRaw, PathPattern};
use ebpf_mon_common::modules::EventInfo;
use ebpf_mon_common::network::{Direction, NetworkEventRaw};
use ebpf_mon_common::process::{ProcessEventRaw, ProcessType};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessContext {
    pub executable: String,
    pub comm: String,
    pub uid: u32,
    pub gid: u32,
    pub tgid: i32,
    pub cgroup_id: u64,
}

impl ProcessContext {
    pub fn from_header(header: &EventInfo) -> Self {
        let executable = header.process.executable.to_string();
        let comm = bytes_to_string(&header.process.comm);
        ProcessContext {
            executable,
            comm,
            uid: header.process.uid,
            gid: header.process.gid,
            tgid: header.process.tgid,
            cgroup_id: header.process.cgroup.cgrp_id,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AllEvents {
    pub cgroup: String,
    pub network: Vec<NetworkEvent>,
    pub fs: Vec<FsEvent>,
    pub process: Vec<ProcessEvent>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkEvent {
    pub process_ctx: ProcessContext,
    pub comm: String,
    pub sk_type: u16,
    pub skc_family: u16,
    #[serde(serialize_with = "serialize_protocol")]
    pub protocol: u8,
    pub doff_flags: u16,
    #[serde(serialize_with = "serialize_ip")]
    pub src_ip: u32,
    pub src_port: u32,
    #[serde(serialize_with = "serialize_ip")]
    pub dst_ip: u32,
    pub dst_port: u32,
    #[serde(serialize_with = "serialize_direction")]
    pub direction: Direction,
    pub freq: u32,
}

impl PartialEq for NetworkEvent {
    fn eq(&self, other: &Self) -> bool {
        self.dst_ip == other.dst_ip
            && self.dst_port == other.dst_port
            && self.direction == other.direction
    }
}

impl Eq for NetworkEvent {}

impl Hash for NetworkEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.dst_port.hash(state);
    }
}

impl NetworkEvent {
    pub fn from_raw(raw: &NetworkEventRaw) -> Self {
        let comm = bytes_to_string(&raw.payload.comm);
        NetworkEvent {
            process_ctx: ProcessContext::from_header(&raw.header),
            comm,
            sk_type: raw.payload.sk_type,
            skc_family: raw.payload.skc_family,
            protocol: raw.payload.protocol,
            doff_flags: raw.payload.doff_flags,
            src_ip: raw.payload.src_ip,
            src_port: raw.payload.src_port,
            dst_ip: raw.payload.dst_ip,
            dst_port: raw.payload.dst_port,
            direction: raw.payload.direction,
            freq: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsEvent {
    pub process_ctx: ProcessContext,
    pub path: String,
    pub sym_path: String,
    pub inode: u64,
    pub owner_uid: u32,
    #[serde(serialize_with = "serialize_r_w")]
    pub r_w: u8,
    pub is_symlink: u8,
    pub path_pattern: PathPattern,
    pub is_sensitive: u8,
    pub is_cross_process: u8,
    pub freq: u32,
}

impl PartialEq for FsEvent {
    fn eq(&self, other: &Self) -> bool {
        self.inode == other.inode
            && self.r_w == other.r_w
            && self.owner_uid == other.owner_uid
    }
}

impl Eq for FsEvent {}

impl Hash for FsEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inode.hash(state);
        self.r_w.hash(state);
        self.owner_uid.hash(state);
    }
}

impl FsEvent {
    pub fn from_raw(raw: &FsEventRaw) -> Self {
        FsEvent {
            process_ctx: ProcessContext::from_header(&raw.header),
            path: raw.payload.path.to_string(),
            sym_path: raw.payload.sym_path.to_string(),
            inode: raw.payload.inode,
            owner_uid: raw.payload.owner_uid,
            r_w: raw.payload.r_w,
            is_symlink: raw.payload.is_symlink,
            path_pattern: raw.payload.path_pattern,
            is_sensitive: raw.payload.is_sensitive,
            is_cross_process: raw.payload.is_cross_process,
            freq: 1u32,
        }
    }
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessEvent {
    pub process_ctx: ProcessContext,
    pub exec_path: String,
    pub inode: u64,
    #[serde(serialize_with = "serialize_ps_type")]
    pub ps_type: ProcessType,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub ppid: i32,
    pub gid: u32,
    pub filename: String,
    pub argv: Vec<String>,
    pub argc: u32,
    pub retval: i32,
    pub freq: u32,
    pub parent_comm: String,
    pub is_root: bool,
    pub capabilities: u64,
}

impl PartialEq for ProcessEvent {
    fn eq(&self, other: &Self) -> bool {
        self.inode == other.inode
            && self.ps_type == other.ps_type
            && self.cgroup_id == other.cgroup_id
    }
}

impl Eq for ProcessEvent {}

impl Hash for ProcessEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inode.hash(state);
        self.ps_type.hash(state);
        self.cgroup_id.hash(state);
        self.argv.hash(state);
    }
}

impl ProcessEvent {
    pub fn from_raw(raw: &ProcessEventRaw) -> Self {
        let filename = bytes_to_string(&raw.payload.filename);

        let argv: Vec<String> = raw.payload.argv
        .iter()
        .take(raw.payload.argc as usize)
        .map(|arg| bytes_to_string(arg))
        .collect();

        let comm = bytes_to_string(&raw.payload.parent_comm);
        ProcessEvent {
            process_ctx: ProcessContext::from_header(&raw.header),
            exec_path: raw.payload.path.to_string(),
            inode: raw.payload.inode,
            ps_type: raw.payload.ps_type,
            pid: raw.payload.pid,
            tgid: raw.payload.tgid,
            cgroup_id: raw.payload.cgroup_id,
            filename: filename,
            argv: argv,
            argc: raw.payload.argc,
            retval: raw.payload.retval,
            freq: 1u32,
            ppid: raw.payload.ppid,
            gid: raw.payload.gid,
            parent_comm: comm,
            is_root: raw.payload.is_root,
            capabilities: raw.payload.capabilities
        }
    }
}


// Event map to track unique events and their frequencies
pub type EventMap = HashMap<Event, u32>;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Event {
    Network(NetworkEvent),
    Fs(FsEvent),
    Process(ProcessEvent),
}

impl Hash for Event {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Event::Network(event) => {
                "Network".hash(state);
                event.hash(state);
            }
            Event::Fs(event) => {
                "Fs".hash(state);
                event.hash(state);
            }
            Event::Process(event) => {
                "Process".hash(state);
                event.hash(state);
            }
        }
    }
}

// Custom serialization functions for pretty-printing boolean values
fn serialize_direction<S>(direction: &Direction, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let direction_str = if *direction == Direction::Egress { "outgoing" } else { "incoming" };
    serializer.serialize_str(direction_str)
}

fn serialize_r_w<S>(r_w: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let operation_str = if *r_w == 1{ "write" } else { "read" };
    serializer.serialize_str(operation_str)
}

fn serialize_ip<S>(ip: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Convert u32 to CIDR notation in standard byte order (a.b.c.d)
    let ip_str = format!("{}.{}.{}.{}", 
        ip & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF
    );
    serializer.serialize_str(&ip_str)
}

fn serialize_protocol<S>(num: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let num_string = num.to_string();
    let protocol = match num {
        1 => "DHCP",
        6 => "TCP",
        17 => "UDP",
        _ => num_string.as_str()
    };
    serializer.serialize_str(&protocol)
}


fn serialize_ps_type<S>(ps_type: &ProcessType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let operation_str = if *ps_type == ProcessType::Execve{ "execve" } else { "fork" };
    serializer.serialize_str(operation_str)
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
