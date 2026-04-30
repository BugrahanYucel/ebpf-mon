use aya::{
    maps::{perf::PerfBufferError, AsyncPerfEventArray, Map},
    util::online_cpus,
};
use bytes::BytesMut;
use log::{debug, error, info, warn};
use ebpf_mon_common::{fs::FsPayload, modules::{DecoderError, EncodedEvent, Type}, network::{Direction, NetworkPayload}, process::{self, ProcessPayload, ProcessType}, capabilities::Capabilities};
use tokio::sync::mpsc;

use ebpf_mon_common::fs::PathPattern;

use crate::{events::{Event::{self}, EventMap, FsEvent, NetworkEvent, ProcessEvent}};
use std::sync::{Arc, Mutex};

// Read the events from the array and pass them into the simple_event_reader
pub async fn listen_all_events(
    event_array: Map,
    tx_event: mpsc::Sender<EncodedEvent>,
    ) {
    let mut perf_array = AsyncPerfEventArray::try_from(event_array).unwrap();

    let buffers = online_cpus()
        .unwrap()
        .into_iter()
        .map(|cpu_id| perf_array.open(cpu_id, Some(128)))
        .collect::<Result<Vec<_>, PerfBufferError>>()
        .unwrap();

    for mut buf in buffers {
        let tx_clone = tx_event.clone();

        info!("Starting event listener for security events");

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(110240))
                .collect::<Vec<_>>();

            loop {
                debug!("Waiting for eBPF events...");
                let events = buf.read_events(&mut buffers).await;

                match events {
                    Ok(events) => {

                        if events.lost > 0 {
                            warn!("Lost {} events (read {})", events.lost, events.read);
                        }

                        if events.read > 0 {
                            debug!("Processing {} security events", events.read);
                        } else {
                            // Add periodic debug to show we're still listening
                            debug!("No events received in this iteration, continuing to listen...");
                        }

                        for buffer in buffers.iter_mut().take(events.read) {
                            // Create the decoded event
                            let encoded_event = EncodedEvent::from_bytes(buffer);

                            // Send to event channel for processing by EventManager
                            // Use async send instead of try_send for better reliability
                            match tx_clone.send(encoded_event).await {
                                Ok(_) => {
                                    debug!("Successfully sent event to channel");
                                }
                                Err(e) => {
                                    error!("Error sending event to channel: {}", e);
                                }
                            };
                        }
                    }
                    Err(e) => error!("Error reading events: {}", e),
                };
            }
        });
    }
}

pub async fn simple_event_reader(mut rx: mpsc::Receiver<EncodedEvent>, event_map: Arc<Mutex<EventMap>>) {
    println!("Event reader started");

    // Add a debug log to confirm we're waiting for events
    info!("Event reader waiting for events...");

    // Remove the unnecessary tokio::spawn and run the loop directly
    while let Some(e) = rx.recv().await {
        debug!("Received event in simple_event_reader");

        // Transform and log the event
        match transform_event(&e) {
            Ok(event) => {
                {
                    let mut map = event_map.lock().unwrap();
                    let count = map.entry(event.clone()).or_insert(0);
                    *count += 1;
                    
                    // Log the event with frequency information
                    let freq = *count;
                    
                    match event {
                        Event::Network(network_event) => {
                            if let Ok(_) = unsafe { e.as_event_with_data::<NetworkPayload>() } {
                                let direction = if network_event.direction == Direction::Egress { "OUTGOING" } else { "INCOMING" };
                                let comm = network_event.comm.as_str();

                                let src_ip = format_ip(network_event.src_ip);
                                let dst_ip = format_ip(network_event.dst_ip);

                                let flags = if network_event.protocol == 6 {network_event.doff_flags} else {0};

                                println!("{} NETWORK: {} {}:{} -> {}:{} (proto: {}, flags: {}) [freq: {}]", 
                                    direction,
                                    comm,
                                    src_ip,
                                    network_event.src_port,
                                    dst_ip,
                                    network_event.dst_port,
                                    network_event.protocol,
                                    flags,
                                    freq
                                );
                            }
                        },
                        Event::Fs(fs_event) => {
                            if let Ok(_) = unsafe { e.as_event_with_data::<FsPayload>() } {
                                let operation = if fs_event.r_w == 1 { "WRITE" } else { "READ" };
                                let path = fs_event.path.to_string();
                                let sym_path = if fs_event.sym_path == "" {"".to_string()} else {format!(", sym_path: {}", fs_event.sym_path)};
                                let path_pattern = if fs_event.path_pattern == 
                                    PathPattern::Regular {"".to_string()} else {format!(", pattern: {:?}", fs_event.path_pattern)};
                                // Show self/cross-process access for /proc paths
                                let proc_access = if fs_event.path_pattern != PathPattern::Regular {
                                    if fs_event.is_cross_process == 1 {
                                        ", CROSS_PROCESS".to_string()
                                    } else {
                                        ", self".to_string()
                                    }
                                } else { "".to_string() };
                                let sensitive = if fs_event.is_sensitive == 1 {
                                    ", SENSITIVE".to_string()
                                } else { "".to_string() };

                                println!("FILE {}: {:?} (owner_uid: {}, inode: {}, is_symlink: {}{}{}{}{}) [freq: {}]",
                                    operation,
                                    path,
                                    fs_event.owner_uid,
                                    fs_event.inode,
                                    fs_event.is_symlink == 1,
                                    sym_path,
                                    path_pattern,
                                    proc_access,
                                    sensitive,
                                    freq
                                );
                            }
                        },
                        Event::Process(process_event) => {
                            if let Ok(_) = unsafe { e.as_event_with_data::<ProcessPayload>() } {
                                let ps_type = match process_event.ps_type {
                                    ProcessType::Execve => {"execve"}
                                    ProcessType::Fork => {"fork"}
                                };
                                let path = process_event.exec_path.to_string();
                                let retval = translate_retval(process_event.retval);
                                let caps = Capabilities::new(process_event.capabilities);
                                
                                println!("PROCESS {}: {:?}, inode: {} (pid: {}) ppid: {}, argv: {:?}, argc: {} retval: {}, gid: {}, parent_comm: {}, is_root: {} ,caps: {}, [freq: {}]",
                                    ps_type,
                                    path,
                                    process_event.inode,
                                    process_event.pid,
                                    process_event.ppid,
                                    process_event.argv,
                                    process_event.argc,
                                    retval,
                                    process_event.gid,
                                    process_event.parent_comm,
                                    process_event.is_root,
                                    caps,
                                    freq,
                                );
                            }
                        },
                        _ => {
                            match event {
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!("Failed to transform event: {:?}", err);
            }
        }
    }

    info!("Event processing loop terminated");
    println!("Event reader stopped");
}

pub fn format_ip(ip: u32) -> String {
    format!("{}.{}.{}.{}", 
    (ip & 0xFF),
    (ip >> 8) & 0xFF,
    (ip >> 16) & 0xFF,
    (ip >> 24) & 0xFF)
}

pub fn transform_event(event: &EncodedEvent) -> Result<Event, DecoderError> {
    let info = unsafe { event.info() }?;

    match info.event_type {
            Type::InetOut => {
                let raw: &ebpf_mon_common::modules::EventRaw<NetworkPayload> = unsafe { event.as_event_with_data::<NetworkPayload>()? };
                Ok(Event::Network(NetworkEvent::from_raw(raw)))
            },
            Type::InetIn => {
                let raw: &ebpf_mon_common::modules::EventRaw<NetworkPayload> = unsafe { event.as_event_with_data::<NetworkPayload>()? };
                Ok(Event::Network(NetworkEvent::from_raw(raw)))
            },
            Type::FileRead => {
                let raw: &ebpf_mon_common::modules::EventRaw<FsPayload> = unsafe { event.as_event_with_data::<FsPayload>()? };
                Ok(Event::Fs(FsEvent::from_raw(raw)))
            },
            Type::FileWrite => {
                let raw: &ebpf_mon_common::modules::EventRaw<FsPayload> = unsafe { event.as_event_with_data::<FsPayload>()? };
                Ok(Event::Fs(FsEvent::from_raw(raw)))
            },
            Type::Execve => {
                let raw: &ebpf_mon_common::modules::EventRaw<ProcessPayload> = unsafe { event.as_event_with_data::<ProcessPayload>()? };
                Ok(Event::Process(ProcessEvent::from_raw(raw)))
            },
            Type::Fork => {
                let raw: &ebpf_mon_common::modules::EventRaw<ProcessPayload> = unsafe { event.as_event_with_data::<ProcessPayload>()? };
                Ok(Event::Process(ProcessEvent::from_raw(raw)))
            },
            Type::Unknown => Err(DecoderError::UnknownType),
        }
}

pub fn export_events_to_json(event_map: &Arc<Mutex<EventMap>>, filename: &str, cgroup: u64) -> Result<(), Box<dyn std::error::Error>> {
    use crate::events::AllEvents;
    use std::fs::File;
    use std::io::Write;

    let map = event_map.lock().unwrap();
    let total_events: u32 = map.values().sum();
    
    // Convert event map to AllProfile structure
    let mut network_events = Vec::new();
    let mut fs_events = Vec::new();
    let mut process_events = Vec::new();
    
    for (event, freq) in map.iter() {
        match event {
            Event::Network(net) => {
                let mut net_with_freq = net.clone();
                net_with_freq.freq = *freq;
                network_events.push(net_with_freq);
            }
            Event::Fs(fs) => {
                let mut fs_with_freq = fs.clone();
                fs_with_freq.freq = *freq;
                fs_events.push(fs_with_freq);
            }
            Event::Process(proc) => {
                let mut proc_with_freq = proc.clone();
                proc_with_freq.freq = *freq;
                process_events.push(proc_with_freq);
            }
        }
    }
    
    let all_events = AllEvents {
        cgroup: cgroup.to_string(),
        network: network_events,
        fs: fs_events,
        process: process_events,
    };
    
    let json_output = serde_json::to_string_pretty(&all_events)?;
    let mut file = File::create(filename)?;
    file.write_all(json_output.as_bytes())?;
    
    debug!("Events exported to JSON: {} (Total: {}, Unique: {}, Network: {}, FS: {}, Process: {})", 
             filename, total_events, map.len(), all_events.network.len(), 
             all_events.fs.len(), all_events.process.len());
    
    Ok(())
}

fn translate_retval (val: i32) -> String {
    let t = match val {
        0 => "success",
        -1 => "EPERM (operation not permitted)",
        -2 => "ENOENT (file not found)",
        -8 => "ENOEXEC (exec format error)",
        -12 => "ENOMEM (out of memory)",
        -13 => "EACCES (permission denied)",
        -14 => "EFAULT (bad address)",
        -22 => "EINVAL (invalid argument)",
        e => &e.to_string(),
    };
    t.to_string()
}
