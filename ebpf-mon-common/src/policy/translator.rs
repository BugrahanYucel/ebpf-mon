use super::ir::*;
use crate::fs::PathPattern;

pub struct ProfileTranslator {
    next_id: RuleId,
    default_verdict: Verdict,
}

impl ProfileTranslator {
    pub fn new() -> Self {
        ProfileTranslator {
            next_id: 1,
            default_verdict: Verdict::Allow,
        }
    }

    pub fn with_default_verdict(mut self, verdict: Verdict) -> Self {
        self.default_verdict = verdict;
        self
    }

    fn alloc_id(&mut self) -> RuleId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn translate_fs_event(
        &mut self,
        path: &str,
        path_pattern: PathPattern,
        r_w: u8,
        is_sensitive: bool,
        freq: u64,
        executable: &str,
        uid: u32,
        cgroup_id: u64,
        inode: Option<u64>,
    ) -> BehaviorRule {
        let file_pattern = if path_pattern == PathPattern::Regular {
            FilePattern::ExactPath(path.to_string())
        } else {
            FilePattern::Classified(path_pattern)
        };

        let action = if r_w == 1 { Action::FileWrite } else { Action::FileRead };

        BehaviorRule {
            id: self.alloc_id(),
            subject: Subject {
                container: if cgroup_id != 0 { Some(ContainerRef::CgroupId(cgroup_id)) } else { None },
                binary: if !executable.is_empty() { Some(BinaryRef::Path(executable.to_string())) } else { None },
                uid: Some(uid),
            },
            object: Object::File(FileObject {
                pattern: file_pattern,
                is_sensitive,
                profiled_inode: inode.filter(|&i| i != 0),
            }),
            action,
            verdict: self.default_verdict,
            metadata: RuleMetadata {
                source_module: SourceModule::Fs,
                observation_count: freq,
                confidence: Self::freq_to_confidence(freq),
                first_seen: 0,
                last_seen: 0,
            },
        }
    }

    pub fn translate_network_event(
        &mut self,
        dst_ip: u32,
        dst_port: u32,
        protocol: u8,
        direction: u8,
        freq: u64,
        executable: &str,
        uid: u32,
        cgroup_id: u64,
    ) -> BehaviorRule {
        let action = if direction == 1 { Action::NetConnect } else { Action::NetBind };

        BehaviorRule {
            id: self.alloc_id(),
            subject: Subject {
                container: if cgroup_id != 0 { Some(ContainerRef::CgroupId(cgroup_id)) } else { None },
                binary: if !executable.is_empty() { Some(BinaryRef::Path(executable.to_string())) } else { None },
                uid: Some(uid),
            },
            object: Object::Network(NetworkObject {
                dst_ip: Some(dst_ip),
                dst_port: Some(dst_port),
                protocol: Some(protocol),
                direction: Some(direction),
            }),
            action,
            verdict: self.default_verdict,
            metadata: RuleMetadata {
                source_module: SourceModule::Net,
                observation_count: freq,
                confidence: Self::freq_to_confidence(freq),
                first_seen: 0,
                last_seen: 0,
            },
        }
    }

    pub fn translate_process_event(
        &mut self,
        exec_path: &str,
        ps_type: u8,
        freq: u64,
        uid: u32,
        cgroup_id: u64,
        inode: Option<u64>,
    ) -> BehaviorRule {
        let action = if ps_type == 0 { Action::ProcExec } else { Action::ProcFork };

        BehaviorRule {
            id: self.alloc_id(),
            subject: Subject {
                container: if cgroup_id != 0 { Some(ContainerRef::CgroupId(cgroup_id)) } else { None },
                binary: None,
                uid: Some(uid),
            },
            object: Object::Process(ProcessObject {
                binary: BinaryRef::Path(exec_path.to_string()),
                profiled_inode: inode.filter(|&i| i != 0),
            }),
            action,
            verdict: self.default_verdict,
            metadata: RuleMetadata {
                source_module: SourceModule::Proc,
                observation_count: freq,
                confidence: Self::freq_to_confidence(freq),
                first_seen: 0,
                last_seen: 0,
            },
        }
    }

    fn freq_to_confidence(freq: u64) -> f32 {
        match freq {
            0..=1 => 0.3,
            2..=10 => 0.6,
            11..=100 => 0.8,
            _ => 0.95,
        }
    }
}

pub fn translate_all_events_json(json_str: &str) -> Result<Vec<BehaviorRule>, std::string::String> {
    let all_events: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    let mut translator = ProfileTranslator::new().with_default_verdict(Verdict::Allow);
    let mut rules = Vec::new();

    if let Some(fs_events) = all_events.get("fs").and_then(|v| v.as_array()) {
        for ev in fs_events {
            let path = ev.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let pattern_val = ev.get("path_pattern");
            let path_pattern = pattern_val
                .and_then(|v| serde_json::from_value::<PathPattern>(v.clone()).ok())
                .unwrap_or(PathPattern::Regular);
            let r_w = match ev.get("r_w").and_then(|v| v.as_str()) {
                Some("write") => 1u8,
                _ => 0u8,
            };
            let is_sensitive = ev.get("is_sensitive").and_then(|v| v.as_u64()).unwrap_or(0) != 0;
            let freq = ev.get("freq").and_then(|v| v.as_u64()).unwrap_or(1);

            let executable = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("executable"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let uid = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("uid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let cgroup_id = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("cgroup_id"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let inode = ev.get("inode").and_then(|v| v.as_u64());

            rules.push(translator.translate_fs_event(
                path, path_pattern, r_w, is_sensitive, freq, executable, uid, cgroup_id, inode,
            ));
        }
    }

    if let Some(net_events) = all_events.get("network").and_then(|v| v.as_array()) {
        for ev in net_events {
            let dst_ip = ev.get("dst_ip").and_then(|v| v.as_str())
                .map(|s| parse_ip_str(s))
                .unwrap_or(0);
            let dst_port = ev.get("dst_port").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let protocol = match ev.get("protocol").and_then(|v| v.as_str()) {
                Some("TCP") => 6u8,
                Some("UDP") => 17u8,
                _ => 0u8,
            };
            let direction = match ev.get("direction").and_then(|v| v.as_str()) {
                Some("outgoing") => 1u8,
                _ => 0u8,
            };
            let freq = ev.get("freq").and_then(|v| v.as_u64()).unwrap_or(1);

            let executable = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("executable"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let uid = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("uid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let cgroup_id = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("cgroup_id"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            rules.push(translator.translate_network_event(
                dst_ip, dst_port, protocol, direction, freq, executable, uid, cgroup_id,
            ));
        }
    }

    if let Some(proc_events) = all_events.get("process").and_then(|v| v.as_array()) {
        for ev in proc_events {
            let exec_path = ev.get("exec_path").and_then(|v| v.as_str()).unwrap_or("");
            let ps_type = match ev.get("ps_type").and_then(|v| v.as_str()) {
                Some("execve") => 0u8,
                _ => 1u8,
            };
            let freq = ev.get("freq").and_then(|v| v.as_u64()).unwrap_or(1);
            let uid = ev.get("process_ctx")
                .and_then(|ctx| ctx.get("uid"))
                .and_then(|v| v.as_u64())
                .or_else(|| ev.get("gid").and_then(|v| v.as_u64()))
                .unwrap_or(0) as u32;
            let cgroup_id = ev.get("cgroup_id").and_then(|v| v.as_u64()).unwrap_or(0);

            let inode = ev.get("inode").and_then(|v| v.as_u64());

            rules.push(translator.translate_process_event(
                exec_path, ps_type, freq, uid, cgroup_id, inode,
            ));
        }
    }

    Ok(rules)
}

fn parse_ip_str(ip_str: &str) -> u32 {
    let parts: Vec<u8> = ip_str.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() == 4 {
        u32::from_le_bytes([parts[0], parts[1], parts[2], parts[3]])
    } else {
        0
    }
}
