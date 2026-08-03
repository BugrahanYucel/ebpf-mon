use std::fmt;
use super::Cgroup;

impl Cgroup {
    pub fn to_vec(&self) -> Vec<String> {
        self.cgroup_path.to_string().split('/').map(|s| s.to_string()).rev().collect()
    }

    pub fn cgroup_id_to_str(&self) -> Option<&str>{
        if let Ok(cgroup_id) = std::str::from_utf8(&self.cgroup_id){
            return Some(cgroup_id);
        }
        None
    }
}

impl fmt::Display for Cgroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_vec().join("/"))
    }
}
