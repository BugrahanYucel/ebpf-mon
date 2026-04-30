use core::mem::offset_of;

use aya_ebpf::{EbpfContext, bindings::BPF_NOEXIST, helpers::{bpf_get_current_pid_tgid, r#gen::bpf_ktime_get_ns}, macros::{cgroup_skb, fentry, fexit, map}, maps::{HashMap, LruHashMap}, programs::{FEntryContext, FExitContext, SkBuffContext}};
use network_types::{tcp::TcpHdr, ip::Ipv4Hdr, udp::UdpHdr};

use ebpf_mon_common::{alloc::{self, alloc_zero, init}, co_re::{self, task_struct}, core_read_kernel, modules::{Type, pipe_event}, network::{ConnectionKey, Direction , RealSource}};
use ebpf_mon_common::network::NetworkEventRaw;

const ETH_P_IP: u32 = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkIdentity {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub dst_port: u32,
    pub direction: Direction,
}

// Store expiry timestamp instead of just a marker for time-based deduplication
#[map]
static NETWORK_EVENT_DEDUP: LruHashMap<NetworkIdentity, u64> = LruHashMap::with_max_entries(32768, 0);

// Deduplication TTL: 60 seconds (in nanoseconds)
const NETWORK_DEDUP_TTL_NS: u64 = 60_000_000_000;


#[map]
pub static DOCKER_PROXY_IPS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(16, 0);

#[map]
static PROXY_TEMP_MAP: LruHashMap<u64, RealSource> = LruHashMap::with_max_entries(10240, 0);
#[map]
static REAL_SOURCE_MAP: LruHashMap<ConnectionKey, RealSource> = LruHashMap::with_max_entries(10240, 0);

#[map]
static INCOMPLETE_PACKETS: LruHashMap<ConnectionKey, NetworkEventRaw> = LruHashMap::with_max_entries(1024, 0);

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// TCP flags
const TCP_FIN: u16 = 0x0001;
const TCP_SYN: u16 = 0x0002;
const TCP_RST: u16 = 0x0004;
const TCP_PSH: u16 = 0x0008;
const TCP_ACK: u16 = 0x0010;

// Helper function for time-based deduplication
// Events with the same identity are deduplicated for NETWORK_DEDUP_TTL_NS
unsafe fn deduplicate_and_send<C: EbpfContext>(
    ctx: &C,
    event: &NetworkEventRaw,
    identity: &NetworkIdentity,
) -> Result<(), u32> {
    let now = bpf_ktime_get_ns();
    let expiry = now + NETWORK_DEDUP_TTL_NS;

    // Try atomic insert first (fastest path for new entries)
    match NETWORK_EVENT_DEDUP.insert(identity, &expiry, BPF_NOEXIST.into()) {
        Ok(_) => {
            // New entry, send the event
            pipe_event(ctx, event);
        },
        Err(_) => {
            // Entry exists - check if expired
            if let Some(&old_expiry) = NETWORK_EVENT_DEDUP.get(identity) {
                if now > old_expiry {
                    // Expired, update expiry and send
                    let _ = NETWORK_EVENT_DEDUP.insert(identity, &expiry, 0);
                    pipe_event(ctx, event);
                }
                // else: not expired, drop (deduplicated)
            }
        }
    }
    Ok(())
}

#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    process_skb(ctx, Direction::Egress).unwrap_or(0)
}

#[cgroup_skb]
pub fn cgroup_skb_ingress(ctx: SkBuffContext) -> i32 {
    process_skb(ctx, Direction::Ingress).unwrap_or(0)
}
#[inline(always)]
pub fn process_skb(ctx: SkBuffContext, direction: Direction) -> Result<i32, i64> {
    match alloc::init() {
        Ok(_) => (),
        Err(e) => {
            return Err(e as i64);
        }
    }

    let ts = unsafe { task_struct::current() };

    let skb = unsafe { &(&ctx).skb };
    let protocol = skb.protocol();

    if protocol != ETH_P_IP {
        return Ok(1);
    }

    // Use heap allocation instead of stack allocation
    let event = alloc_zero::<NetworkEventRaw>().map_err(|_| 1i32)?;

    let event_type = if direction == Direction::Ingress {Type::InetIn} else {Type::InetOut};
    event.header.event_type = event_type;
    event.header.timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    unsafe {
        event.header.process.comm = ts.comm_array().ok_or(1)?;
        event.header.process.tgid = ts.tgid().ok_or(1)?;
        event.header.process.pid = ts.pid().ok_or(1)?;
        event.header.process.start_time = ts.start_boottime().ok_or(1)?;
    }

    event.payload.direction = direction;
    event.payload.src_ip = ctx.load(offset_of!(Ipv4Hdr, src_addr))?;
    event.payload.dst_ip = ctx.load(offset_of!(Ipv4Hdr, dst_addr))?;
    event.payload.protocol = ctx.load(offset_of!(Ipv4Hdr, proto))?;
    event.payload.comm = unsafe { ts.comm_array().ok_or(1)? };

    let version_ihl: u8 = ctx.load(offset_of!(Ipv4Hdr, vihl)).map_err(|_| 1)?;
    let ihl = (version_ihl & 0x0F) as usize;
    let ip_header_len = ihl * 4;  // Convert to bytes

    let (src_port, dst_port, doff_flags) =  extract_ports(&ctx, event, ip_header_len).unwrap_or((0, 0, 0));

    event.payload.src_port = src_port.into();
    event.payload.dst_port = dst_port.into();
    event.payload.doff_flags = doff_flags;
    if event.payload.protocol == IPPROTO_TCP && !is_tcp_connection_start(doff_flags) {
        return Ok(1);
    }
    if unsafe { DOCKER_PROXY_IPS.get(&event.payload.src_ip).is_some() } {
        // This packet came through docker-proxy!
        // Lookup the real source
        let mut key: ConnectionKey = unsafe { core::mem::zeroed() };
        key.container_ip = event.payload.dst_ip;
        key.container_port = dst_port as u32;
        key.protocol = event.payload.protocol;
        key._pad = 0;
    
        if let Some(real_source) = unsafe { REAL_SOURCE_MAP.get(&key) } {
            event.payload.src_ip = real_source.real_ip;
            event.payload.src_port = real_source.real_port as u32;
        }
        else {
            let pid_tgid = bpf_get_current_pid_tgid();
            event.payload.pid = pid_tgid as u32;
            event.payload.tgid = (pid_tgid >> 32) as u32;
            unsafe { 
                INCOMPLETE_PACKETS.insert(&key, &event, 0);
            }
            return Ok(1);
        }
    }

    // TODO: As it says in the cgroup_skb document, using bpf_get_current_pid_tgid on cgroup_skb needs a new kernel version, might resort to another solution.
    let pid_tgid = bpf_get_current_pid_tgid();
    event.payload.pid = pid_tgid as u32;
    event.payload.tgid = (pid_tgid >> 32) as u32;

    if !is_valid_event(event) {
        return Ok(1);
    }

    // Create identity for deduplication
    // IMPORTANT: Use zeroed() to ensure padding bytes are zero, otherwise
    // the eBPF map may treat identical identities as different keys due to
    // uninitialized padding bytes in the struct.
    let mut identity: NetworkIdentity = unsafe { core::mem::zeroed() };
    identity.src_ip = event.payload.src_ip;
    identity.dst_ip = event.payload.dst_ip;
    identity.dst_port = event.payload.dst_port;
    identity.direction = direction;

    if event.payload.protocol == IPPROTO_UDP && !is_new_udp_flow(event.payload.src_ip, event.payload.src_port as u16, event.payload.dst_ip, event.payload.dst_port as u16) {
        return Ok(1)
    }

    unsafe { deduplicate_and_send(&ctx, event, &identity)? };
    Ok(1)
}

fn extract_ports(
    ctx: &SkBuffContext,
    event: &mut NetworkEventRaw,
    ip_header_len: usize
) -> Result<(u16, u16, u16), i64> {
    // Validate once
    if ip_header_len < 20 || ip_header_len > 60 {
        return Err(-1);
    }

    match event.payload.protocol {
        6 => parse_tcp(ctx, ip_header_len),
        17 => parse_udp_ports(ctx, ip_header_len),
        _ => Ok((0, 0, 0)),
    }
}

fn parse_tcp(
    ctx: &SkBuffContext,
    ip_header_len: usize,
) -> Result<(u16, u16, u16), i64> {
        let sport: u16 = ctx.load(ip_header_len + offset_of!(TcpHdr, source)).map_err(|_| 1)?;
        let dport: u16 = ctx.load(ip_header_len + offset_of!(TcpHdr, dest)).map_err(|_| 1)?;
        let doff_flags: u16 = ctx.load(ip_header_len + offset_of!(TcpHdr, _bitfield_1)).map_err(|_| 1)?;
    Ok((
        u16::from_be(sport),
        u16::from_be(dport),
        u16::from_be(doff_flags)
    ))
}

fn parse_udp_ports(
    ctx: &SkBuffContext,
    ip_header_len: usize,
) -> Result<(u16, u16, u16), i64> {
        let sport: u16 = ctx.load(ip_header_len + offset_of!(UdpHdr, src)).map_err(|_| 1)?;
        let dport: u16 = ctx.load(ip_header_len + offset_of!(UdpHdr, dst)).map_err(|_| 1)?;
    Ok((
        u16::from_be(sport),
        u16::from_be(dport),
        0
    ))
}

fn is_tcp_connection_start(flags: u16) -> bool {
    (flags & (TCP_SYN | TCP_ACK)) == TCP_SYN
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpFlowKey {
    pub ip_low: u32,
    pub ip_high: u32,
    pub port_low: u16,
    pub port_high: u16,
}

#[map]
static UDP_FLOWS: LruHashMap<UdpFlowKey, u64> = LruHashMap::with_max_entries(8192, 0);

const UDP_FLOW_TTL_NS: u64 = 5_000_000_000;

#[inline(always)]
fn normalize_udp_key(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> UdpFlowKey {
    if src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
        UdpFlowKey {
            ip_low: src_ip,
            ip_high: dst_ip,
            port_low: src_port,
            port_high: dst_port,
        }
    } else {
        UdpFlowKey {
            ip_low: dst_ip,
            ip_high: src_ip,
            port_low: dst_port,
            port_high: src_port,
        }
    }
}

// TODO: Test this function. It seems like time-based elimination is a naive solution. Instead resort to keeping states based on who initiated the dialogue.
// But it might eliminate actual new connections. We must find a solid method for this. Maybe check other projects if they do deduplication.
#[inline(always)]
pub fn is_new_udp_flow(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> bool {
    let key = normalize_udp_key(src_ip, src_port, dst_ip, dst_port);
    let now = unsafe { bpf_ktime_get_ns() };
    let expiry = now + UDP_FLOW_TTL_NS;

    // Atomic check-and-insert: only succeeds if key doesn't exist
    match unsafe { UDP_FLOWS.insert(&key, &expiry, BPF_NOEXIST.into()) } {
        Ok(_) => true,   // We inserted it, so it's new
        Err(_) => {
            // Key exists - but check if it's expired
            if let Some(&old_expiry) = unsafe { UDP_FLOWS.get(&key) } {
                if now > old_expiry {
                    // Expired, update and treat as new
                    let _ = UDP_FLOWS.insert(&key, &expiry, 0);
                    return true;
                }
            }
            false  // Not new (or couldn't update)
        }
    }
}

#[inline(always)]
fn is_valid_event(event: &NetworkEventRaw) -> bool {
    if event.payload.src_ip == 0 && event.payload.dst_ip == 0 {
        return false;
    }
    
    if event.payload.src_port == 0 && event.payload.dst_port == 0 {
        return false;
    }

    if event.payload.protocol == 0 {
        return false;
    }

    true
}

#[fexit]
pub fn docker_proxy_accept(ctx: FExitContext) -> u32 {
    match track_proxy_accept(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn track_proxy_accept(ctx: FExitContext) -> Result<(), u32> {

    let ts = unsafe { task_struct::current() };
    // Check if this is docker-proxy process
    let comm = unsafe { ts.comm_array().ok_or(1u32)? };
    if !comm.starts_with(b"docker-proxy") {
        return Ok(());
    }

    let socket= unsafe { co_re::socket::from_ptr(ctx.arg(1)) };
    if socket.is_null() {
        return Ok(());
    }
    let sk = unsafe { core_read_kernel!(socket, sk) }.ok_or(1u32)?;

    unsafe {
        // Get the REAL source (external client)
        let real_src_ip = unsafe { core_read_kernel!(sk, __sk_common, skc_rcv_saddr) }.ok_or(1u32)?;
        let real_src_port = 
                   u16::from_be( unsafe { core_read_kernel!(sk, __sk_common, skc_dport) }.ok_or(1u32)? as u16) as u32;
        let pid_tgid = bpf_get_current_pid_tgid();

        let real_source = RealSource {
            real_ip: real_src_ip,
            real_port: real_src_port,
        };

        // Store temporarily by PID (will correlate with connect)
        PROXY_TEMP_MAP.insert(&pid_tgid, &real_source, 0);
    }

    Ok(())
}

// Hook when docker-proxy CONNECTS to container (establishes mapping)
#[fexit]
pub fn docker_proxy_connect(ctx: FExitContext) -> u32 {
    match track_proxy_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn track_proxy_connect(ctx: FExitContext) -> Result<u32, u32> {
    let ts: co_re::Core<co_re::gen::task_struct> = unsafe { task_struct::current() };
    // Check if this is docker-proxy process
    let comm = unsafe { ts.comm_array().ok_or(1u32)? };
    if !comm.starts_with(b"docker-proxy") {
        return Ok(0u32);
    }

    let sk= unsafe { co_re::sock::from_ptr(ctx.arg(0)) };
    if sk.is_null() {
        return Ok(0u32);
    }

    let pid_tgid = bpf_get_current_pid_tgid();

    let container_ip = unsafe { core_read_kernel!(sk, __sk_common, skc_daddr) }.ok_or(1u32)?;
    let container_port = u16::from_be(unsafe { core_read_kernel!(sk, __sk_common, skc_dport) }.ok_or(1u32)? as u16) as u32;
    let protocol = IPPROTO_TCP;
    let mut key: ConnectionKey = unsafe { core::mem::zeroed() };    
    key.container_ip = container_ip;
    key.container_port = container_port;
    key.protocol = protocol;
    key._pad = 0;

    unsafe {
    if let Some(mevent) = INCOMPLETE_PACKETS.get(&key) {

        if let Some(real_source) = PROXY_TEMP_MAP.get(&pid_tgid) {

            // Allocate on heap FIRST while map references are still valid
            let event = match alloc_zero::<NetworkEventRaw>() {
                Ok(e) => e,
                Err(_) => {
                    // Clean up maps even on allocation failure
                    INCOMPLETE_PACKETS.remove(&key);
                    PROXY_TEMP_MAP.remove(&pid_tgid);
                    return Ok(0u32);
                }
            };
            
            // Copy from map to heap-allocated event (no stack variables)
            event.header = mevent.header;
            event.payload = mevent.payload;
            event.payload.src_ip = real_source.real_ip;
            event.payload.src_port = real_source.real_port;
            
            // Now safe to clean up the maps
            INCOMPLETE_PACKETS.remove(&key);
            PROXY_TEMP_MAP.remove(&pid_tgid);
            
            let mut identity: NetworkIdentity = core::mem::zeroed();
            identity.src_ip = event.payload.src_ip;
            identity.dst_ip = event.payload.dst_ip;
            identity.dst_port = event.payload.dst_port;
            identity.direction = event.payload.direction;
            
            if event.payload.protocol == IPPROTO_UDP 
                && !is_new_udp_flow(
                    event.payload.src_ip, 
                    event.payload.src_port as u16, 
                    event.payload.dst_ip, 
                    event.payload.dst_port as u16
                ) {
                return Ok(0u32);
            }
            
            // Ignore the result - maps are already cleaned up
            let _ = deduplicate_and_send(&ctx, event, &identity);
            
            return Ok(0u32);
        }
    }
}
    
    unsafe {
        // Get the container connection details
        
        // Retrieve the real source we stored earlier
        if let Some(real_source) = PROXY_TEMP_MAP.get(&pid_tgid) {
            
            REAL_SOURCE_MAP.insert(&key, real_source, 0);

            // Clean up temp storage
            PROXY_TEMP_MAP.remove(&pid_tgid);
        }
    }

    Ok(1u32)
}