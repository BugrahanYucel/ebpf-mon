//! Externalized, validated tuning knobs for the optimization passes.
//!
//! These are *policy*, not *logic*: they tune how aggressively — and how safely —
//! the semantics-widening `PrefixGeneralizationPass` fires. They live in a config
//! struct (overridable at runtime from a JSON file) precisely because changing
//! them is a security-posture decision, not an algorithm change.
//!
//! Note the deliberate boundary: the `PathPattern` classification taxonomy is
//! NOT here and cannot be. It is a compile-time ABI shared with the in-kernel
//! eBPF program — the kernel matches on the enum discriminants and uses them as
//! map keys, so runtime config cannot change what already-loaded bytecode
//! matches. Only these userspace-only knobs are externalizable.

use super::types::PREFIX_MAX_LEN;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PassConfig {
    /// Minimum sibling `ExactPath` rules under one directory before the prefix
    /// pass collapses them. Higher = more conservative.
    pub prefix_min_cluster: usize,
    /// Minimum directory depth (path components) eligible for collapse; refuses
    /// shallow dirs like `/etc/` (depth 1). Must be >= 1.
    pub prefix_min_depth: usize,
    /// Minimum shared prefix/suffix length among leaf names for them to count as
    /// "machine-generated". Must be >= 1.
    pub prefix_min_affix: usize,
    /// Directories that must never be generalized regardless of the thresholds
    /// (belt-and-suspenders denylist). Must include "/".
    pub sensitive_roots: Vec<String>,
}

impl Default for PassConfig {
    fn default() -> Self {
        PassConfig {
            prefix_min_cluster: 4,
            prefix_min_depth: 2,
            prefix_min_affix: 3,
            sensitive_roots: default_sensitive_roots(),
        }
    }
}

/// The built-in sensitive-root denylist (previously hard-coded in the pass).
pub fn default_sensitive_roots() -> Vec<String> {
    [
        "/", "/etc/", "/root/", "/boot/", "/proc/", "/sys/", "/dev/", "/usr/", "/bin/", "/sbin/",
        "/lib/", "/lib64/",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl PassConfig {
    /// Reject configurations that would silently and dangerously widen the
    /// allowlist. A mis-set knob must fail loudly, not open a hole.
    pub fn validate(&self) -> Result<(), String> {
        if self.prefix_min_cluster < 2 {
            return Err("prefix_min_cluster must be >= 2".into());
        }
        if self.prefix_min_depth < 1 {
            return Err("prefix_min_depth must be >= 1 (0 would allow generalizing at '/')".into());
        }
        if self.prefix_min_affix < 1 {
            return Err("prefix_min_affix must be >= 1".into());
        }
        if !self.sensitive_roots.iter().any(|r| r == "/") {
            return Err("sensitive_roots must include \"/\"".into());
        }
        if let Some(bad) = self.sensitive_roots.iter().find(|r| r.len() > PREFIX_MAX_LEN) {
            return Err(format!(
                "sensitive root '{}' exceeds PREFIX_MAX_LEN ({})",
                bad, PREFIX_MAX_LEN
            ));
        }
        Ok(())
    }

    /// Load and validate a config from a JSON file. Missing fields fall back to
    /// the conservative defaults (so a partial file is fine).
    pub fn from_json_file(path: &str) -> Result<PassConfig, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read pass config '{}': {}", path, e))?;
        let cfg: PassConfig = serde_json::from_str(&text)
            .map_err(|e| format!("failed to parse pass config '{}': {}", path, e))?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert!(PassConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_dangerous_knobs() {
        let mut c = PassConfig::default();
        c.prefix_min_cluster = 1;
        assert!(c.validate().is_err());

        let mut c = PassConfig::default();
        c.prefix_min_depth = 0;
        assert!(c.validate().is_err());

        let mut c = PassConfig::default();
        c.sensitive_roots = vec!["/etc/".into()]; // missing "/"
        assert!(c.validate().is_err());
    }

    #[test]
    fn partial_json_fills_defaults() {
        let cfg: PassConfig = serde_json::from_str(r#"{"prefix_min_cluster": 8}"#).unwrap();
        assert_eq!(cfg.prefix_min_cluster, 8);
        assert_eq!(cfg.prefix_min_depth, 2); // default
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert!(serde_json::from_str::<PassConfig>(r#"{"bogus": 1}"#).is_err());
    }
}
