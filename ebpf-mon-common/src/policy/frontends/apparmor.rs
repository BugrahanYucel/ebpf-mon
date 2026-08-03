//! AppArmor frontend: parse a *subset* of AppArmor profile syntax into the IR.
//!
//! This is intentionally a subset parser — enough to round-trip what our backend
//! emits and to ingest simple hand-written profiles. Grounded in `apparmor.d(5)`
//! (see `docs/apparmor-format-reference.md`). It handles: file rules in both
//! `path perms` and `perms path` orders, quoted paths, `deny`/`allow` verdicts,
//! `owner`/`audit`/`priority=` qualifiers (dropped), exec transitions, and network
//! rules including fine-grained `ip=`/`port=`/`peer=(...)`.
//!
//! It does NOT handle includes (`#include`), variables (`@{...}`), abi/tunables,
//! `{ab,cd}` alternation, or capability/mount/dbus/signal/ptrace/unix rules — those
//! lines are skipped rather than erroring, so a partial parse still yields usable
//! rules. This is the documented "expressibility envelope", not silent loss.

use crate::fs::PathPattern;
use crate::policy::{
    Action, BehaviorRule, BinaryRef, FileObject, FilePattern, NetworkObject, Object, ProcessObject,
    RuleId, RuleMetadata, SourceModule, Subject, Verdict,
};

/// All non-placeholder patterns, used to reverse-map a glob back to a
/// `Classified` pattern via `PathPattern::as_str()`.
const KNOWN_PATTERNS: &[PathPattern] = &[
    PathPattern::ProcPidCmdline, PathPattern::ProcPidComm, PathPattern::ProcPidCwd,
    PathPattern::ProcPidEnviron, PathPattern::ProcPidExe, PathPattern::ProcPidFd,
    PathPattern::ProcPidMaps, PathPattern::ProcPidMem, PathPattern::ProcPidMountinfo,
    PathPattern::ProcPidMounts, PathPattern::ProcPidNet, PathPattern::ProcPidNs,
    PathPattern::ProcPidRoot, PathPattern::ProcPidStat, PathPattern::ProcPidStatus,
    PathPattern::ProcPidTask, PathPattern::ProcPidCgroup, PathPattern::ProcSelf,
    PathPattern::ProcGlobalSys, PathPattern::ProcGlobalNet, PathPattern::SysCgroupDocker,
    PathPattern::SysCgroupOther, PathPattern::SysClassNet, PathPattern::SysOther,
    PathPattern::RunDocker, PathPattern::RunUser, PathPattern::RunOther, PathPattern::DevPts,
    PathPattern::DevShm, PathPattern::DevOther, PathPattern::TmpRandom, PathPattern::TmpOther,
];

/// Parse an AppArmor profile into IR rules. Unrecognized lines are skipped.
pub fn parse_apparmor(text: &str) -> Result<Vec<BehaviorRule>, String> {
    let mut rules = Vec::new();
    let mut next_id: RuleId = 1;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip structural / unsupported preamble lines.
        if line.starts_with("profile")
            || line.starts_with("abi ")
            || line.starts_with("include")
            || line.starts_with('@')
            || line == "{"
            || line == "}"
            || line.ends_with('{')
        {
            continue;
        }

        let line = line.trim_end_matches(',').trim();
        if line.is_empty() {
            continue;
        }

        let (verdict, line) = if let Some(rest) = line.strip_prefix("deny ") {
            (Verdict::Deny, rest.trim())
        } else if let Some(rest) = line.strip_prefix("allow ") {
            (Verdict::Allow, rest.trim())
        } else {
            (Verdict::Allow, line)
        };

        // Strip non-verdict leading qualifiers we don't model (audit, owner).
        let line = strip_qualifiers(line);

        if let Some(rest) = line.strip_prefix("network") {
            rules.push(parse_network(&mut next_id, verdict, rest));
            continue;
        }

        let (path, perms) = match split_path_perms(line) {
            Some(v) => v,
            None => continue,
        };

        // A single AppArmor line may carry multiple permission classes.
        if perms.contains('x') {
            rules.push(exec_rule(&mut next_id, verdict, &path));
        }
        if perms.contains('w') || perms.contains('a') {
            rules.push(file_rule(&mut next_id, verdict, &path, Action::FileWrite));
        }
        if perms.contains('r') {
            rules.push(file_rule(&mut next_id, verdict, &path, Action::FileRead));
        }
    }

    Ok(rules)
}

/// Strip leading rule qualifiers we recognize but do not model, so the remaining
/// text is a bare file/network rule. `deny`/`allow` are handled earlier (verdict);
/// `priority=N`, `audit`, and `owner` carry no IR meaning for our subset.
fn strip_qualifiers(mut line: &str) -> &str {
    loop {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("owner ") {
            line = rest;
        } else if let Some(rest) = trimmed.strip_prefix("audit ") {
            line = rest;
        } else if trimmed.starts_with("priority=") {
            // Drop the "priority=N" token.
            line = trimmed.split_once(char::is_whitespace).map(|(_, r)| r).unwrap_or("");
        } else {
            return trimmed;
        }
    }
}

/// A permission token is one of AppArmor's ACCESS letters (r w a l k m) or an
/// exec-transition letter (x and its i/p/c/u variants, upper/lower case).
fn is_perm_token(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c, 'r' | 'w' | 'a' | 'l' | 'k' | 'm'
        | 'x' | 'i' | 'p' | 'c' | 'u' | 'P' | 'C' | 'U'))
}

/// Split a file rule into (path, perms). Handles a quoted path and both AppArmor
/// orderings: `FILEGLOB ACCESS` (`/etc/foo r`) and `ACCESS FILEGLOB` (`r /etc/foo`).
fn split_path_perms(line: &str) -> Option<(String, String)> {
    if let Some(rest) = line.strip_prefix('"') {
        let end = rest.find('"')?;
        let path = rest[..end].to_string();
        let perms = rest[end + 1..].trim().to_string();
        if perms.is_empty() {
            return None;
        }
        Some((path, perms))
    } else {
        // Leading-permission form: `<perms> /path` (path is absolute -> starts with '/').
        if let Some((first, rest)) = line.split_once(char::is_whitespace) {
            let rest = rest.trim();
            if is_perm_token(first) && rest.starts_with('/') {
                return Some((rest.to_string(), first.to_string()));
            }
        }
        // Trailing-permission form: `/path <perms>`.
        let idx = line.rfind(char::is_whitespace)?;
        let path = line[..idx].trim();
        let perms = line[idx + 1..].trim();
        if path.is_empty() || !is_perm_token(perms) {
            return None;
        }
        Some((path.to_string(), perms.to_string()))
    }
}

fn glob_to_pattern(glob: &str) -> FilePattern {
    for p in KNOWN_PATTERNS {
        if p.as_str() == glob {
            return FilePattern::Classified(*p);
        }
    }
    if let Some(prefix) = glob.strip_suffix("**") {
        return FilePattern::Prefix(ensure_trailing_slash(prefix));
    }
    if let Some(prefix) = glob.strip_suffix("/*") {
        return FilePattern::Prefix(ensure_trailing_slash(prefix));
    }
    FilePattern::ExactPath(glob.to_string())
}

fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{}/", s)
    }
}

fn alloc(next_id: &mut RuleId) -> RuleId {
    let id = *next_id;
    *next_id += 1;
    id
}

fn meta(source_module: SourceModule) -> RuleMetadata {
    RuleMetadata {
        source_module,
        observation_count: 0,
        confidence: 1.0,
        first_seen: 0,
        last_seen: 0,
    }
}

fn empty_subject() -> Subject {
    Subject { container: None, binary: None, uid: None }
}

fn file_rule(next_id: &mut RuleId, verdict: Verdict, path: &str, action: Action) -> BehaviorRule {
    BehaviorRule {
        id: alloc(next_id),
        subject: empty_subject(),
        object: Object::File(FileObject {
            pattern: glob_to_pattern(path),
            is_sensitive: false,
        }),
        action,
        verdict,
        metadata: meta(SourceModule::Fs),
    }
}

fn exec_rule(next_id: &mut RuleId, verdict: Verdict, path: &str) -> BehaviorRule {
    BehaviorRule {
        id: alloc(next_id),
        subject: empty_subject(),
        object: Object::Process(ProcessObject {
            binary: BinaryRef::Path(path.to_string()),
        }),
        action: Action::ProcExec,
        verdict,
        metadata: meta(SourceModule::Proc),
    }
}

/// Parse the tail of a `network ...` rule into an IR network object.
///
/// Recognizes `stream`/`dgram` types and `tcp`/`udp` protocols anywhere in the
/// token list, and extracts ip/port from either a bare `ip=`/`port=` (local) or a
/// `peer=(ip=.. port=..)` block (remote destination). Anything else is ignored.
fn parse_network(next_id: &mut RuleId, verdict: Verdict, rest: &str) -> BehaviorRule {
    let mut protocol: Option<u8> = None;
    for tok in rest.split_whitespace() {
        match tok.trim_end_matches(',') {
            "stream" | "tcp" => protocol = Some(6),
            "dgram" | "udp" => protocol = Some(17),
            _ => {}
        }
    }

    // Prefer the peer endpoint (connect destination); fall back to a bare local expr.
    let (dst_ip, dst_port) = if let Some(peer) = extract_peer(rest) {
        parse_ip_port(&peer)
    } else {
        parse_ip_port(rest)
    };

    BehaviorRule {
        id: alloc(next_id),
        subject: empty_subject(),
        object: Object::Network(NetworkObject { dst_ip, dst_port, protocol, direction: Some(1) }),
        action: Action::NetConnect,
        verdict,
        metadata: meta(SourceModule::Net),
    }
}

/// Return the text inside `peer=( ... )`, if present.
fn extract_peer(s: &str) -> Option<String> {
    let start = s.find("peer=(")? + "peer=(".len();
    let end = s[start..].find(')')? + start;
    Some(s[start..end].to_string())
}

/// Extract `ip=` (IPv4 only, as u32) and `port=` (first value of any range) from a
/// whitespace-separated conditional string.
fn parse_ip_port(s: &str) -> (Option<u32>, Option<u32>) {
    let mut ip = None;
    let mut port = None;
    for tok in s.split_whitespace() {
        let tok = tok.trim_end_matches(&[',', ')'][..]);
        if let Some(v) = tok.strip_prefix("ip=") {
            ip = parse_ipv4(v);
        } else if let Some(v) = tok.strip_prefix("port=") {
            // A range like 8080-8084 keeps only the low bound in our IR.
            port = v.split('-').next().and_then(|p| p.parse::<u32>().ok());
        }
    }
    (ip, port)
}

/// Parse a dotted-quad IPv4 string into the IR's `dst_ip` u32.
///
/// The IR/enforcement convention is `from_le_bytes(octets)` — the same encoding
/// the kernel hook sees when it loads `sockaddr_in.sin_addr.s_addr` (a `__be32`)
/// on a little-endian host, and the encoding the monitor frontend
/// (`translator::parse_ip_str`) and `manager::format_ip` already use. Matching it
/// here keeps a single IP representation across every frontend and backend.
/// Returns None for non-IPv4 (e.g. IPv6, `none`).
fn parse_ipv4(s: &str) -> Option<u32> {
    let octets: Vec<u8> = s.split('.').map(|o| o.parse::<u8>().ok()).collect::<Option<_>>()?;
    if octets.len() != 4 {
        return None;
    }
    Some(u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]))
}

#[cfg(test)]
mod tests {
    use super::parse_apparmor;
    use crate::fs::PathPattern;
    use crate::policy::{Action, BehaviorRule, FilePattern, Object, Verdict};

    #[test]
    fn parses_exact_classified_prefix_exec_network() {
        let profile = r#"
profile demo flags=(attach_disconnected) {
  # files
  /app/config.yaml r,
  /proc/*/status r,
  /app/** w,
  /usr/bin/python3 ix,
  network inet stream,
}
"#;
        let rules = parse_apparmor(profile).unwrap();

        let has = |pred: &dyn Fn(&BehaviorRule) -> bool| rules.iter().any(pred);

        assert!(has(&|r| matches!(&r.object, Object::File(f)
            if matches!(&f.pattern, FilePattern::ExactPath(p) if p == "/app/config.yaml"))
            && r.action == Action::FileRead));
        assert!(has(&|r| matches!(&r.object, Object::File(f)
            if matches!(&f.pattern, FilePattern::Classified(PathPattern::ProcPidStatus)))));
        assert!(has(&|r| matches!(&r.object, Object::File(f)
            if matches!(&f.pattern, FilePattern::Prefix(p) if p == "/app/"))
            && r.action == Action::FileWrite));
        assert!(has(&|r| matches!(&r.object, Object::Process(_)) && r.action == Action::ProcExec));
        assert!(has(&|r| matches!(&r.object, Object::Network(_))));
    }

    #[test]
    fn deny_prefix_and_quoted_path() {
        let rules = parse_apparmor("deny \"/etc/shadow\" r,\n").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].verdict, Verdict::Deny);
        assert!(matches!(&rules[0].object, Object::File(f)
            if matches!(&f.pattern, FilePattern::ExactPath(p) if p == "/etc/shadow")));
    }

    #[test]
    fn network_peer_ip_port_is_parsed() {
        let rules =
            parse_apparmor("network inet stream peer=(ip=1.1.1.1 port=443),\n").unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(&rules[0].object, Object::Network(n)
            if n.dst_ip == Some(0x0101_0101) && n.dst_port == Some(443) && n.protocol == Some(6)));
    }

    #[test]
    fn leading_perms_and_owner_qualifier() {
        // `owner` qualifier is dropped; `rw /path` (perms-first) is accepted.
        let rules = parse_apparmor("owner rw /var/data/x,\n").unwrap();
        assert!(rules.iter().any(|r| matches!(&r.object, Object::File(f)
            if matches!(&f.pattern, FilePattern::ExactPath(p) if p == "/var/data/x"))
            && r.action == Action::FileWrite));
        assert!(rules.iter().any(|r| r.action == Action::FileRead));
    }
}
