use std::fmt;
use super::*;

impl Capabilities {
    pub fn new(val: u64) -> Self {
        Self(val)
    }
    
    pub fn has(&self, cap: u32) -> bool {
        (self.0 & (1u64 << cap)) != 0
    }
    
    pub fn raw(&self) -> u64 {
        self.0
    }
    
    pub fn is_root(&self) -> bool {
        self.0 == 0x1FFFFFFFFFF
    }
    
    pub fn count(&self) -> u32 {
        self.0.count_ones()
    }
    
    fn cap_name(cap_num: u32) -> Option<&'static str> {
        match cap_num {
            0 => Some("CHOWN"),
            1 => Some("DAC_OVERRIDE"),
            2 => Some("DAC_READ_SEARCH"),
            3 => Some("FOWNER"),
            4 => Some("FSETID"),
            5 => Some("KILL"),
            6 => Some("SETGID"),
            7 => Some("SETUID"),
            8 => Some("SETPCAP"),
            9 => Some("LINUX_IMMUTABLE"),
            10 => Some("NET_BIND_SERVICE"),
            11 => Some("NET_BROADCAST"),
            12 => Some("NET_ADMIN"),
            13 => Some("NET_RAW"),
            14 => Some("IPC_LOCK"),
            15 => Some("IPC_OWNER"),
            16 => Some("SYS_MODULE"),
            17 => Some("SYS_RAWIO"),
            18 => Some("SYS_CHROOT"),
            19 => Some("SYS_PTRACE"),
            20 => Some("SYS_PACCT"),
            21 => Some("SYS_ADMIN"),
            22 => Some("SYS_BOOT"),
            23 => Some("SYS_NICE"),
            24 => Some("SYS_RESOURCE"),
            25 => Some("SYS_TIME"),
            26 => Some("SYS_TTY_CONFIG"),
            27 => Some("MKNOD"),
            28 => Some("LEASE"),
            29 => Some("AUDIT_WRITE"),
            30 => Some("AUDIT_CONTROL"),
            31 => Some("SETFCAP"),
            32 => Some("MAC_OVERRIDE"),
            33 => Some("MAC_ADMIN"),
            34 => Some("SYSLOG"),
            35 => Some("WAKE_ALARM"),
            36 => Some("BLOCK_SUSPEND"),
            37 => Some("AUDIT_READ"),
            38 => Some("PERFMON"),
            39 => Some("BPF"),
            40 => Some("CHECKPOINT_RESTORE"),
            _ => None,
        }
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return write!(f, "None");
        }
        
        if self.is_root() {
            return write!(f, "ALL");
        }
        
        let mut caps = Vec::new();
        for cap_num in 0..=40 {
            if self.has(cap_num) {
                if let Some(name) = Self::cap_name(cap_num) {
                    caps.push(name);
                }
            }
        }
        
        if caps.is_empty() {
            write!(f, "None")
        } else {
            write!(f, "{}", caps.join(","))
        }
    }
}