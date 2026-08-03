//! Backends: lower the normalized IR into a concrete enforcement target.
//!
//! The existing BPF-LSM backend currently lives in the userspace binary
//! (`ebpf-mon/src/enforcement.rs::PolicyLoader`); new backends land here until
//! that logic is extracted as part of the full frontends/backends split.

pub mod apparmor;
