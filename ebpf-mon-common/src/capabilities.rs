use crate::macros::not_bpf_target_code;

#[derive(Debug, Clone, Copy)]
pub struct Capabilities(pub u64);

not_bpf_target_code! {
    mod user;
}

// Most common capabilities:
pub const CAP_CHOWN: u32 = 0;            // Change file ownership
pub const CAP_DAC_OVERRIDE: u32 = 1;     // Bypass file permission checks
pub const CAP_DAC_READ_SEARCH: u32 = 2;  // Bypass file read permission checks
pub const CAP_FOWNER: u32 = 3;           // Bypass permission checks on operations
pub const CAP_FSETID: u32 = 4;           // Don't clear setuid/setgid bits
pub const CAP_KILL: u32 = 5;             // Bypass permission checks for sending signals
pub const CAP_SETGID: u32 = 6;           // Make arbitrary manipulations of GIDs
pub const CAP_SETUID: u32 = 7;           // Make arbitrary manipulations of UIDs
pub const CAP_SETPCAP: u32 = 8;          // Transfer capability
pub const CAP_LINUX_IMMUTABLE: u32 = 9;  // Set immutable and append-only flags
pub const CAP_NET_BIND_SERVICE: u32 = 10; // Bind to ports < 1024
pub const CAP_NET_BROADCAST: u32 = 11;   // Allow broadcasting
pub const CAP_NET_ADMIN: u32 = 12;       // Network administration
pub const CAP_NET_RAW: u32 = 13;         // Use RAW and PACKET sockets
pub const CAP_IPC_LOCK: u32 = 14;        // Lock memory
pub const CAP_IPC_OWNER: u32 = 15;       // Bypass permission checks for IPC
pub const CAP_SYS_MODULE: u32 = 16;      // Load/unload kernel modules
pub const CAP_SYS_RAWIO: u32 = 17;       // Perform I/O port operations
pub const CAP_SYS_CHROOT: u32 = 18;      // Use chroot()
pub const CAP_SYS_PTRACE: u32 = 19;      // Trace arbitrary processes
pub const CAP_SYS_PACCT: u32 = 20;       // Use acct()
pub const CAP_SYS_ADMIN: u32 = 21;       // System administration operations
pub const CAP_SYS_BOOT: u32 = 22;        // Use reboot()
pub const CAP_SYS_NICE: u32 = 23;        // Raise process nice value
pub const CAP_SYS_RESOURCE: u32 = 24;    // Override resource limits
pub const CAP_SYS_TIME: u32 = 25;        // Set system clock
pub const CAP_SYS_TTY_CONFIG: u32 = 26;  // Configure TTY
pub const CAP_MKNOD: u32 = 27;           // Create special files
pub const CAP_LEASE: u32 = 28;           // Establish leases on files
pub const CAP_AUDIT_WRITE: u32 = 29;     // Write to audit log
pub const CAP_AUDIT_CONTROL: u32 = 30;   // Configure audit subsystem
pub const CAP_SETFCAP: u32 = 31;         // Set file capabilities

// Capabilities 32-37 (in cap[1] sometimes, not in our case since it is u64 in ours)
pub const CAP_MAC_OVERRIDE: u32 = 32;    // Override MAC access
pub const CAP_MAC_ADMIN: u32 = 33;       // Configure MAC
pub const CAP_SYSLOG: u32 = 34;          // Perform privileged syslog operations
pub const CAP_WAKE_ALARM: u32 = 35;      // Trigger wake-up events
pub const CAP_BLOCK_SUSPEND: u32 = 36;   // Block system suspend
pub const CAP_AUDIT_READ: u32 = 37;      // Read audit log
pub const CAP_PERFMON: u32 = 38;         // Performance monitoring
pub const CAP_BPF: u32 = 39;             // BPF operations
pub const CAP_CHECKPOINT_RESTORE: u32 = 40; // Checkpoint/restore
