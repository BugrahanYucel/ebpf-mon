//! Frontends: translate external inputs into the normalized IR.
//!
//! The existing monitor-JSON frontend currently lives in `policy::translator`
//! (`translate_all_events_json`); new frontends land here until that file is
//! moved as part of the full frontends/backends split.

pub mod apparmor;
