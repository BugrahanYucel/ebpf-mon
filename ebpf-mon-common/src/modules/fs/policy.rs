use crate::macros::not_bpf_target_code;

// Constants for filesystem policy
pub const MAX_PATHS: usize = 16;

pub const FS_POLICY_MAP_NAME: &str = "FS_POLICY_MAP";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    Read = 0x01,    // Read operations
    Write = 0x02,   // Write operations
    Execute = 0x04, // Execute operations
    Delete = 0x08,  // Delete operations
    Create = 0x10,  // Create operations
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FileSystemPolicyBpf {
    pub allowed_resource: [(u64, u8); MAX_PATHS], // (inode, access_mask) pairs
    pub denied_resource: [(u64, u8); MAX_PATHS],  // (inode, access_mask) pairs
    pub audit_resource: [(u64, u8); MAX_PATHS],   // (inode, access_mask) pairs
    pub default_action: u8,                       // 0 = deny, 1 = allow
}

impl FileSystemPolicyBpf {
    pub fn new(
        allowed_resource: [(u64, u8); MAX_PATHS],
        denied_resource: [(u64, u8); MAX_PATHS],
        audit_resource: [(u64, u8); MAX_PATHS],
        default_action: u8,
    ) -> Self {
        Self {
            allowed_resource,
            denied_resource,
            audit_resource,
            default_action,
        }
    }

    pub fn check_permission(&self, path_inode: u64, access_mask: u8) -> bool {
        // First check denied paths (deny takes precedence)
        for i in 0..MAX_PATHS {
            let (inode, mask) = self.denied_resource[i];
            if inode == 0 {
                break; // End of valid entries
            }

            if inode == path_inode && (access_mask & mask) != 0 {
                return false; // Explicitly denied
            }
        }

        // Then check allowed paths
        for i in 0..MAX_PATHS {
            let (inode, mask) = self.allowed_resource[i];
            if inode == 0 {
                break; // End of valid entries
            }

            if inode == path_inode && (access_mask & mask) == access_mask {
                return true; // Explicitly allowed
            }
        }

        // If neither explicitly allowed nor denied, use default action
        self.default_action != 0
    }

    pub fn should_audit(&self, path_inode: u64, access_mask: u8) -> bool {
        // Check if path should be audited
        for i in 0..MAX_PATHS {
            let (inode, mask) = self.audit_resource[i];
            if inode == 0 {
                break; // End of valid entries
            }

            if inode == path_inode && (access_mask & mask) != 0 {
                return true; // Should audit
            }
        }

        false
    }
}

not_bpf_target_code! {
    #[cfg(feature = "user")]
    unsafe impl aya::Pod for FileSystemPolicyBpf {}
}
