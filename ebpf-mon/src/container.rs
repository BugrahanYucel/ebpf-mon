use log::{info, warn};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

/// Represents the type of identifier used to specify the target container
#[derive(Debug, Clone)]
pub enum ContainerIdentifier {
    /// Container specified by name (supports restart tracking)
    Name(String),
    /// Container specified by ID (will resolve to name for restart tracking)
    ContainerId(String),
    /// Direct cgroup path (no restart tracking possible)
    CgroupPath(String),
}

/// Tracks container state across restarts
#[derive(Debug, Clone)]
pub struct TrackedContainer {
    /// Container name - persists across restarts
    pub name: Option<String>,
    /// Current 64-char container ID
    pub current_id: String,
    /// Current cgroup inode for eBPF filter
    pub current_cgroup_id: u64,
    /// Current cgroup path
    pub current_cgroup_path: String,
    /// Whether restart tracking is enabled
    pub restart_tracking_enabled: bool,
}

/// Container state change events sent to main thread
#[derive(Debug, Clone)]
pub enum ContainerStateChange {
    /// Container has stopped
    Stopped,
    /// Container has started with potentially new ID
    Started {
        container_id: String,
        cgroup_id: u64,
        cgroup_path: String,
    },
    /// Error occurred while watching
    Error(String),
}

impl TrackedContainer {
    /// Create a new TrackedContainer from a container identifier
    pub fn from_identifier(identifier: &ContainerIdentifier) -> io::Result<Self> {
        match identifier {
            ContainerIdentifier::Name(name) => {
                info!("Resolving container by name: {}", name);
                
                // Validate container exists and get current ID
                let container_id = get_container_id_by_name(name)?;
                let cgroup_path = container_id_to_cgroup_path(&container_id)?;
                let cgroup_id = get_cgroup_id_from_path(&cgroup_path)?;
                
                info!("Container '{}' resolved: ID={:.12}..., cgroup_id={}", 
                      name, container_id, cgroup_id);
                
                Ok(TrackedContainer {
                    name: Some(name.clone()),
                    current_id: container_id,
                    current_cgroup_id: cgroup_id,
                    current_cgroup_path: cgroup_path,
                    restart_tracking_enabled: true,
                })
            }
            ContainerIdentifier::ContainerId(id) => {
                info!("Resolving container by ID: {}", id);
                
                // Get full container ID and cgroup info
                let full_id = get_full_container_id(id)?;
                let cgroup_path = container_id_to_cgroup_path(&full_id)?;
                let cgroup_id = get_cgroup_id_from_path(&cgroup_path)?;
                
                // Try to resolve container name for restart tracking
                match get_container_name(&full_id) {
                    Ok(name) => {
                        info!("Container ID resolved to name '{}': cgroup_id={}", name, cgroup_id);
                        info!("Restart tracking enabled for container '{}'", name);
                        
                        Ok(TrackedContainer {
                            name: Some(name),
                            current_id: full_id,
                            current_cgroup_id: cgroup_id,
                            current_cgroup_path: cgroup_path,
                            restart_tracking_enabled: true,
                        })
                    }
                    Err(e) => {
                        warn!("Could not resolve container name: {}. Restart tracking disabled.", e);
                        
                        Ok(TrackedContainer {
                            name: None,
                            current_id: full_id,
                            current_cgroup_id: cgroup_id,
                            current_cgroup_path: cgroup_path,
                            restart_tracking_enabled: false,
                        })
                    }
                }
            }
            ContainerIdentifier::CgroupPath(path) => {
                info!("Using direct cgroup path: {}", path);
                warn!("Restart tracking is not available when using --cgroup directly");
                
                let cgroup_id = get_cgroup_id_from_path(path)?;
                
                // Try to extract container ID from cgroup path for logging
                let container_id = extract_container_id_from_cgroup_path(path)
                    .unwrap_or_else(|| "unknown".to_string());
                
                Ok(TrackedContainer {
                    name: None,
                    current_id: container_id,
                    current_cgroup_id: cgroup_id,
                    current_cgroup_path: path.clone(),
                    restart_tracking_enabled: false,
                })
            }
        }
    }
    
    /// Log startup information about the tracked container
    pub fn log_startup_info(&self) {
        info!("=== Container Tracking Configuration ===");
        if let Some(ref name) = self.name {
            info!("  Name: {}", name);
        }
        info!("  Container ID: {:.12}...", self.current_id);
        info!("  Cgroup ID: {}", self.current_cgroup_id);
        info!("  Cgroup Path: {}", self.current_cgroup_path);
        info!("  Restart Tracking: {}", 
              if self.restart_tracking_enabled { "ENABLED" } else { "DISABLED" });
        info!("========================================");
    }
}

/// Get container ID by name using docker inspect
fn get_container_id_by_name(name: &str) -> io::Result<String> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", name])
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Container '{}' not found: {}", name, stderr.trim()),
        ));
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get container name from container ID using docker inspect
fn get_container_name(container_id: &str) -> io::Result<String> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.Name}}", container_id])
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Container '{}' not found: {}", container_id, stderr.trim()),
        ));
    }
    
    // Docker prefixes names with '/', remove it
    let name = String::from_utf8_lossy(&output.stdout)
        .trim()
        .trim_start_matches('/')
        .to_string();
    
    Ok(name)
}

/// Get full container ID (docker inspect can expand short IDs)
fn get_full_container_id(short_id: &str) -> io::Result<String> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", short_id])
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Container '{}' not found: {}", short_id, stderr.trim()),
        ));
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get container state: (container_id, is_running)
fn get_container_state(name: &str) -> io::Result<(String, bool)> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}} {{.State.Running}}", name])
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Container '{}' not found: {}", name, stderr.trim()),
        ));
    }
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = output_str.trim().split_whitespace().collect();
    
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected docker inspect output: {}", output_str),
        ));
    }
    
    let container_id = parts[0].to_string();
    let is_running = parts[1] == "true";
    
    Ok((container_id, is_running))
}

/// Convert container ID to cgroup path (Docker cgroup v2)
fn container_id_to_cgroup_path(container_id: &str) -> io::Result<String> {
    // Try cgroup v2 path first (more common on modern systems)
    let cgroup_v2_path = format!(
        "/sys/fs/cgroup/system.slice/docker-{}.scope",
        container_id
    );
    
    if fs::metadata(&cgroup_v2_path).is_ok() {
        return Ok(cgroup_v2_path);
    }
    
    // Try cgroup v1 path
    let cgroup_v1_path = format!("/sys/fs/cgroup/memory/docker/{}", container_id);
    
    if fs::metadata(&cgroup_v1_path).is_ok() {
        return Ok(cgroup_v1_path);
    }
    
    // Fallback: use container PID to find cgroup path
    let pid = get_container_pid(container_id)?;
    let rel_path = get_cgroup_rel_path(pid)?;
    Ok(format!("/sys/fs/cgroup{}", rel_path))
}

/// Get container PID using docker inspect
fn get_container_pid(container_id: &str) -> io::Result<u32> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Pid}}", container_id])
        .output()?;
    
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "docker inspect failed",
        ));
    }
    
    let pid_str = String::from_utf8_lossy(&output.stdout);
    pid_str.trim().parse::<u32>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PID: {}", e),
        )
    })
}

/// Get cgroup relative path from /proc/<pid>/cgroup
fn get_cgroup_rel_path(pid: u32) -> io::Result<String> {
    let path = format!("/proc/{}/cgroup", pid);
    let content = fs::read_to_string(path)?;
    
    for line in content.lines() {
        // cgroup v2 unified hierarchy: look for line like 0::/docker/<id>
        if let Some(path) = line.splitn(3, ':').nth(2) {
            return Ok(path.trim().to_string());
        }
    }
    
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Cgroup path not found",
    ))
}

/// Get cgroup ID (inode) from a cgroup path
pub fn get_cgroup_id_from_path(cgroup_path: &str) -> io::Result<u64> {
    let meta = fs::metadata(cgroup_path)?;
    Ok(meta.ino())
}

/// Extract container ID from cgroup path (e.g., docker-<id>.scope)
pub fn extract_container_id_from_cgroup_path(cgroup_path: &str) -> Option<String> {
    use regex::Regex;
    
    let re = Regex::new(r"docker-([a-f0-9]{64})\.scope").ok()?;
    
    if let Some(caps) = re.captures(cgroup_path) {
        return Some(caps[1].to_string());
    }
    
    // Try cgroup v1 format: /sys/fs/cgroup/memory/docker/<id>
    if cgroup_path.contains("/docker/") {
        let parts: Vec<&str> = cgroup_path.split('/').collect();
        if let Some(id) = parts.last() {
            if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id.to_string());
            }
        }
    }
    
    None
}

/// Container watcher that monitors container state and sends changes via channel
pub struct ContainerWatcher {
    container_name: String,
    tx: Sender<ContainerStateChange>,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ContainerWatcher {
    /// Start a new container watcher in a background thread
    pub fn start(
        container_name: String,
        initial_id: String,
        initial_cgroup_id: u64,
    ) -> (Receiver<ContainerStateChange>, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let (tx, rx) = mpsc::channel();
        let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();
        
        let watcher = ContainerWatcher {
            container_name,
            tx,
            stop_flag: stop_flag_clone,
        };
        
        thread::spawn(move || {
            watcher.run(initial_id, initial_cgroup_id);
        });
        
        (rx, stop_flag)
    }
    
    fn run(self, mut current_id: String, mut current_cgroup_id: u64) {
        use std::sync::atomic::Ordering;
        
        let mut was_running = true;
        // Use shorter polling interval (2 seconds) to catch fast restarts
        let mut poll_interval = Duration::from_secs(2);
        
        info!("Container watcher started for '{}' (cgroup_id: {})", self.container_name, current_cgroup_id);
        
        loop {
            if self.stop_flag.load(Ordering::Relaxed) {
                info!("Container watcher stopping");
                break;
            }
            
            thread::sleep(poll_interval);
            
            match get_container_state(&self.container_name) {
                Ok((container_id, is_running)) => {
                    if !is_running && was_running {
                        // Container just stopped
                        info!("Container '{}' stopped, switching to fast polling", self.container_name);
                        was_running = false;
                        poll_interval = Duration::from_millis(100);
                        let _ = self.tx.send(ContainerStateChange::Stopped);
                    } else if is_running && !was_running {
                        // Container just started after being stopped
                        info!("Container '{}' started after stop", self.container_name);
                        was_running = true;
                        poll_interval = Duration::from_secs(2);
                        
                        // Always resolve and send new cgroup info after restart
                        self.send_cgroup_update(&container_id, &mut current_id, &mut current_cgroup_id);
                        
                    } else if is_running {
                        // Container is running - check if cgroup ID changed (handles docker restart)
                        // This catches the case where restart happened between polls
                        match container_id_to_cgroup_path(&container_id) {
                            Ok(cgroup_path) => {
                                match get_cgroup_id_from_path(&cgroup_path) {
                                    Ok(new_cgroup_id) => {
                                        if new_cgroup_id != current_cgroup_id {
                                            // Cgroup ID changed! This is a restart we missed
                                            info!(
                                                "Detected cgroup change (fast restart): {} -> {}",
                                                current_cgroup_id, new_cgroup_id
                                            );
                                            
                                            if container_id != current_id {
                                                info!(
                                                    "Container ID also changed: {:.12} -> {:.12}",
                                                    current_id, container_id
                                                );
                                                current_id = container_id.clone();
                                            }
                                            
                                            current_cgroup_id = new_cgroup_id;
                                            
                                            let _ = self.tx.send(ContainerStateChange::Started {
                                                container_id,
                                                cgroup_id: new_cgroup_id,
                                                cgroup_path,
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to get cgroup ID during poll: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to resolve cgroup path during poll: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        if was_running {
                            warn!("Container '{}' was removed", self.container_name);
                            was_running = false;
                            let _ = self.tx.send(ContainerStateChange::Error(
                                format!("Container '{}' was removed", self.container_name),
                            ));
                        }
                        poll_interval = Duration::from_secs(5);
                    } else {
                        warn!("Failed to get container state: {}", e);
                        let _ = self.tx.send(ContainerStateChange::Error(e.to_string()));
                    }
                }
            }
        }
    }
    
    /// Helper to send cgroup update after container restart
    fn send_cgroup_update(&self, container_id: &str, current_id: &mut String, current_cgroup_id: &mut u64) {
        if container_id != current_id {
            info!(
                "Container ID changed: {:.12} -> {:.12}",
                current_id, container_id
            );
            *current_id = container_id.to_string();
        }
        
        match container_id_to_cgroup_path(container_id) {
            Ok(cgroup_path) => {
                match get_cgroup_id_from_path(&cgroup_path) {
                    Ok(new_cgroup_id) => {
                        if new_cgroup_id != *current_cgroup_id {
                            info!(
                                "Cgroup ID changed: {} -> {}",
                                current_cgroup_id, new_cgroup_id
                            );
                        }
                        *current_cgroup_id = new_cgroup_id;
                        
                        let _ = self.tx.send(ContainerStateChange::Started {
                            container_id: container_id.to_string(),
                            cgroup_id: new_cgroup_id,
                            cgroup_path,
                        });
                    }
                    Err(e) => {
                        let _ = self.tx.send(ContainerStateChange::Error(
                            format!("Failed to get cgroup ID: {}", e),
                        ));
                    }
                }
            }
            Err(e) => {
                let _ = self.tx.send(ContainerStateChange::Error(
                    format!("Failed to resolve cgroup path: {}", e),
                ));
            }
        }
    }
}
