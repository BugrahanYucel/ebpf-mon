use std::collections::{HashMap, HashSet};
use super::ir::*;
use super::types::PREFIX_MAX_LEN;
use super::config::{default_sensitive_roots, PassConfig};

pub trait OptimizationPass {
    fn name(&self) -> &'static str;
    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule>;
}

/// Normalizes file paths to a canonical byte form so downstream passes
/// (dedup, subsumption) compare like-for-like, and so the enforcement-time
/// path hash matches the profiled hash regardless of how the path was written.
/// Lexical only (no filesystem access): collapses `//`, drops `.`, resolves
/// `..`, and trims a redundant trailing slash on exact paths while preserving
/// it on prefixes (so `/app/` cannot match `/application`).
pub struct CanonicalizationPass;

impl OptimizationPass for CanonicalizationPass {
    fn name(&self) -> &'static str { "canonicalize" }

    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
        rules.into_iter().map(|mut rule| {
            if let Object::File(ref mut file_obj) = rule.object {
                file_obj.pattern = match &file_obj.pattern {
                    FilePattern::ExactPath(p) => FilePattern::ExactPath(canonicalize_path(p)),
                    FilePattern::Prefix(p) => FilePattern::Prefix(canonicalize_prefix(p)),
                    FilePattern::Classified(c) => FilePattern::Classified(*c),
                };
            }
            rule
        }).collect()
    }
}

/// Lexically normalize an absolute or relative path (no symlink/fs resolution).
fn canonicalize_path(path: &str) -> String {
    if path.is_empty() {
        return path.to_string();
    }
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if out.last().map_or(false, |&c| c != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            c => out.push(c),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Canonicalize a directory prefix, guaranteeing a single trailing slash so
/// prefix matching stays directory-scoped.
fn canonicalize_prefix(prefix: &str) -> String {
    let c = canonicalize_path(prefix);
    if c.ends_with('/') { c } else { format!("{}/", c) }
}

pub struct DeduplicationPass;

impl OptimizationPass for DeduplicationPass {
    fn name(&self) -> &'static str { "dedup" }

    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
        let mut seen: HashMap<(Subject, Object, Action), BehaviorRule> = HashMap::new();

        for rule in rules {
            let sig = rule.signature();
            if let Some(existing) = seen.get_mut(&sig) {
                existing.metadata.observation_count += rule.metadata.observation_count;
                if rule.metadata.first_seen < existing.metadata.first_seen {
                    existing.metadata.first_seen = rule.metadata.first_seen;
                }
                if rule.metadata.last_seen > existing.metadata.last_seen {
                    existing.metadata.last_seen = rule.metadata.last_seen;
                }
            } else {
                seen.insert(sig, rule);
            }
        }

        seen.into_values().collect()
    }
}

pub struct GeneralizationPass;

impl OptimizationPass for GeneralizationPass {
    fn name(&self) -> &'static str { "generalize" }

    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
        rules.into_iter().map(|mut rule| {
            if let Object::File(ref mut file_obj) = rule.object {
                if let FilePattern::ExactPath(ref path) = file_obj.pattern {
                    if let Some(classified) = Self::try_classify(path) {
                        file_obj.pattern = FilePattern::Classified(classified);
                    }
                }
            }
            rule
        }).collect()
    }
}

impl GeneralizationPass {
    fn try_classify(path: &str) -> Option<crate::fs::PathPattern> {
        if path.starts_with("/proc/") {
            let remainder = &path[6..];
            if let Some(slash_pos) = remainder.find('/') {
                let after_pid = &remainder[slash_pos + 1..];
                return match after_pid {
                    "cmdline" => Some(crate::fs::PathPattern::ProcPidCmdline),
                    "comm" => Some(crate::fs::PathPattern::ProcPidComm),
                    "cwd" => Some(crate::fs::PathPattern::ProcPidCwd),
                    "environ" => Some(crate::fs::PathPattern::ProcPidEnviron),
                    "exe" => Some(crate::fs::PathPattern::ProcPidExe),
                    "maps" => Some(crate::fs::PathPattern::ProcPidMaps),
                    "mem" => Some(crate::fs::PathPattern::ProcPidMem),
                    "mountinfo" => Some(crate::fs::PathPattern::ProcPidMountinfo),
                    "mounts" => Some(crate::fs::PathPattern::ProcPidMounts),
                    "root" => Some(crate::fs::PathPattern::ProcPidRoot),
                    "stat" => Some(crate::fs::PathPattern::ProcPidStat),
                    "status" => Some(crate::fs::PathPattern::ProcPidStatus),
                    "cgroup" => Some(crate::fs::PathPattern::ProcPidCgroup),
                    s if s.starts_with("fd/") => Some(crate::fs::PathPattern::ProcPidFd),
                    s if s.starts_with("net/") => Some(crate::fs::PathPattern::ProcPidNet),
                    s if s.starts_with("ns/") => Some(crate::fs::PathPattern::ProcPidNs),
                    s if s.starts_with("task/") => Some(crate::fs::PathPattern::ProcPidTask),
                    _ => Some(crate::fs::PathPattern::ProcPidOther),
                };
            }
        }
        None
    }
}

/// Auto-generalization: invents directory `Prefix` rules from clusters of
/// sibling `ExactPath` rules that share an immediate parent directory. This is
/// the "strength reduction" analogue — collapsing many concrete accesses (e.g.
/// dozens of PostgreSQL WAL segments under `/var/lib/postgresql/data/pg_wal/`)
/// into one directory-scoped rule, which then lets `SubsumptionPass` sweep up
/// any deeper stragglers under the same tree.
///
/// SECURITY NOTE: unlike canonicalization/dedup, this pass is **not**
/// semantics-preserving — it *widens* the allowlist to files under the
/// directory that were never observed. Every guard below exists to bound that
/// widening; the pass errs toward NOT generalizing when the evidence is weak.
///
/// A group (same subject/action/verdict, same parent dir) collapses into
/// `Prefix(parent_dir)` only when ALL hold:
///   1. size >= `min_cluster`             — not a coincidental handful
///   2. parent depth >= `min_depth`       — refuses `/etc/`, `/tmp/`, root
///   3. parent not a sensitive system root — belt-and-suspenders denylist
///   4. parent byte-len <= `PREFIX_MAX_LEN` — else enforcement truncates the
///      prefix and silently over-matches
///   5. no sensitive member in the cluster — never fold a secret into a dir
///   6. leaves look machine-generated      — shared affix or hex/numeric names,
///      not a hand-picked set of configs that merely sit together
///   7. no opposing-verdict rule under the dir — an allow-prefix must not
///      swallow a deny (and vice-versa)
pub struct PrefixGeneralizationPass {
    pub min_cluster: usize,
    pub min_depth: usize,
    pub min_affix: usize,
    /// Directories that are never generalized (guard 3). Externalized so the
    /// denylist is policy, not a hard-coded constant.
    pub sensitive_roots: Vec<String>,
}

impl Default for PrefixGeneralizationPass {
    fn default() -> Self {
        // Conservative defaults: 4 siblings, 2 directory components deep, 3-char
        // shared affix. Tuned to fire on app data dirs (WAL, sessions, rotated
        // logs) while leaving shallow and system directories untouched.
        PrefixGeneralizationPass {
            min_cluster: 4,
            min_depth: 2,
            min_affix: 3,
            sensitive_roots: default_sensitive_roots(),
        }
    }
}

impl PrefixGeneralizationPass {
    /// Build the pass from an externalized, validated [`PassConfig`].
    pub fn from_config(cfg: &PassConfig) -> Self {
        PrefixGeneralizationPass {
            min_cluster: cfg.prefix_min_cluster,
            min_depth: cfg.prefix_min_depth,
            min_affix: cfg.prefix_min_affix,
            sensitive_roots: cfg.sensitive_roots.clone(),
        }
    }
}

impl OptimizationPass for PrefixGeneralizationPass {
    fn name(&self) -> &'static str { "prefix-generalize" }

    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
        // Bucket candidate exact-file rules by (subject, action, verdict, parent dir).
        let mut groups: HashMap<(Subject, Action, Verdict, String), Vec<usize>> = HashMap::new();
        for (i, rule) in rules.iter().enumerate() {
            if let Object::File(fo) = &rule.object {
                if fo.is_sensitive {
                    continue; // guard 5: never fold a sensitive file into a dir
                }
                if let FilePattern::ExactPath(p) = &fo.pattern {
                    if let Some(dir) = parent_dir(p) {
                        groups
                            .entry((rule.subject.clone(), rule.action, rule.verdict, dir))
                            .or_default()
                            .push(i);
                    }
                }
            }
        }

        let mut collapsed: HashSet<usize> = HashSet::new();
        let mut synthesized: Vec<BehaviorRule> = Vec::new();

        for ((subject, action, verdict, dir), idxs) in &groups {
            if idxs.len() < self.min_cluster {
                continue; // guard 1
            }
            if !self.dir_generalizable(dir) {
                continue; // guards 2, 3
            }
            if dir.len() > PREFIX_MAX_LEN {
                continue; // guard 4
            }

            let leaves: Vec<&str> = idxs
                .iter()
                .filter_map(|&i| match &rules[i].object {
                    Object::File(fo) => match &fo.pattern {
                        FilePattern::ExactPath(p) => p.get(dir.len()..),
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            if !leaves_look_generated(&leaves, self.min_affix) {
                continue; // guard 6
            }
            if opposing_verdict_under(&rules, subject, *verdict, dir) {
                continue; // guard 7
            }

            // Collapse: fold member metadata into a single prefix rule.
            let mut obs: u64 = 0;
            let mut first: u64 = u64::MAX;
            let mut last: u64 = 0;
            let mut min_conf = f32::INFINITY;
            let mut src = SourceModule::Fs;
            for (n, &i) in idxs.iter().enumerate() {
                let m = &rules[i].metadata;
                obs = obs.saturating_add(m.observation_count);
                first = first.min(m.first_seen);
                last = last.max(m.last_seen);
                min_conf = min_conf.min(m.confidence);
                if n == 0 {
                    src = m.source_module;
                }
                collapsed.insert(i);
            }

            synthesized.push(BehaviorRule {
                id: rules[idxs[0]].id,
                subject: subject.clone(),
                object: Object::File(FileObject {
                    pattern: FilePattern::Prefix(dir.clone()),
                    is_sensitive: false,
                }),
                action: *action,
                verdict: *verdict,
                metadata: RuleMetadata {
                    source_module: src,
                    observation_count: obs,
                    confidence: if min_conf.is_finite() { min_conf } else { 0.0 },
                    first_seen: if first == u64::MAX { 0 } else { first },
                    last_seen: last,
                },
            });
        }

        if collapsed.is_empty() {
            return rules;
        }

        let mut out: Vec<BehaviorRule> = Vec::with_capacity(rules.len());
        for (i, rule) in rules.into_iter().enumerate() {
            if !collapsed.contains(&i) {
                out.push(rule);
            }
        }
        out.extend(synthesized);
        out
    }
}

impl PrefixGeneralizationPass {
    /// Guards 2 & 3: the directory must be deep enough and not a sensitive
    /// system root. Depth counts path components, so `/etc/` (1) is refused
    /// while `/etc/nginx/conf.d/` (3) is allowed.
    fn dir_generalizable(&self, dir: &str) -> bool {
        if self.sensitive_roots.iter().any(|r| r == dir) {
            return false;
        }
        let depth = dir.split('/').filter(|s| !s.is_empty()).count();
        depth >= self.min_depth
    }
}

/// Immediate parent directory (with trailing slash) of an absolute path.
/// `/a/b/c` -> `/a/b/`. Returns `None` when the parent would be root `/`
/// (too broad to ever be a safe prefix) or the path has no `/`.
fn parent_dir(path: &str) -> Option<String> {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let idx = trimmed.rfind('/')?;
    if idx == 0 {
        return None;
    }
    Some(trimmed[..=idx].to_string())
}

/// Guard 6: are these leaf names plausibly machine-generated (so the directory
/// is a data/scratch dir worth generalizing) rather than a hand-picked set of
/// unrelated files? True when they share a long enough prefix/suffix (WAL
/// segments, timestamped logs) OR are all hex/numeric tokens (OIDs, inodes).
fn leaves_look_generated(leaves: &[&str], min_affix: usize) -> bool {
    if leaves.len() < 2 {
        return false;
    }
    if common_affix_len(leaves) >= min_affix {
        return true;
    }
    leaves.iter().all(|s| {
        !s.is_empty()
            && s.bytes().all(|c| c.is_ascii_hexdigit())
            && s.bytes().any(|c| c.is_ascii_digit())
    })
}

fn common_affix_len(leaves: &[&str]) -> usize {
    common_prefix_len(leaves).max(common_suffix_len(leaves))
}

fn common_prefix_len(leaves: &[&str]) -> usize {
    let first = leaves[0].as_bytes();
    let mut len = first.len();
    for s in &leaves[1..] {
        let b = s.as_bytes();
        let mut i = 0;
        while i < len && i < b.len() && b[i] == first[i] {
            i += 1;
        }
        len = i;
        if len == 0 {
            break;
        }
    }
    len
}

fn common_suffix_len(leaves: &[&str]) -> usize {
    let first = leaves[0].as_bytes();
    let mut len = first.len();
    for s in &leaves[1..] {
        let b = s.as_bytes();
        let mut i = 0;
        while i < len && i < b.len() && b[b.len() - 1 - i] == first[first.len() - 1 - i] {
            i += 1;
        }
        len = i;
        if len == 0 {
            break;
        }
    }
    len
}

/// Guard 7: true if any same-subject rule with the opposite verdict references
/// a file that could sit under `dir`, meaning an allow-prefix here would shadow a
/// deny (or vice-versa). Uses the shared `path_relation` primitive: any relation
/// other than `Disjoint` (equal, sub/superset, or uncertain overlap) blocks
/// generalization — including classified globs rooted under `dir`, which the
/// previous hand-rolled check missed.
fn opposing_verdict_under(
    rules: &[BehaviorRule],
    subject: &Subject,
    verdict: Verdict,
    dir: &str,
) -> bool {
    let dir_pat = FilePattern::Prefix(dir.to_string());
    rules.iter().any(|r| {
        r.subject == *subject
            && r.verdict != verdict
            && match &r.object {
                Object::File(fo) => dir_pat.relation_to(&fo.pattern) != PathRelation::Disjoint,
                _ => false,
            }
    })
}

pub struct SubsumptionPass;

impl OptimizationPass for SubsumptionPass {
    fn name(&self) -> &'static str { "subsumption" }

    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
        let mut result: Vec<BehaviorRule> = Vec::new();

        for rule in &rules {
            let is_subsumed = rules.iter().any(|other| {
                std::ptr::eq(rule, other) == false
                    && rule.subject == other.subject
                    && rule.action == other.action
                    && rule.verdict == other.verdict
                    && Self::object_subsumed(&rule.object, &other.object)
            });
            if !is_subsumed {
                result.push(rule.clone());
            }
        }

        result
    }
}

impl SubsumptionPass {
    fn object_subsumed(narrow: &Object, broad: &Object) -> bool {
        match (narrow, broad) {
            // Strict `Superset` only: `Equal` patterns are left for dedup, never
            // dropped here (both rules could carry distinct metadata).
            (Object::File(n), Object::File(b)) => {
                matches!(b.pattern.relation_to(&n.pattern), PathRelation::Superset)
            }
            _ => false,
        }
    }
}

pub struct ConflictDetectionPass;

#[derive(Debug, Clone)]
pub struct PolicyConflict {
    pub rule_a: BehaviorRule,
    pub rule_b: BehaviorRule,
}

impl ConflictDetectionPass {
    pub fn detect(rules: &[BehaviorRule]) -> Vec<PolicyConflict> {
        let mut conflicts = Vec::new();
        for (i, a) in rules.iter().enumerate() {
            for b in rules.iter().skip(i + 1) {
                if a.conflicts_with(b) {
                    conflicts.push(PolicyConflict {
                        rule_a: a.clone(),
                        rule_b: b.clone(),
                    });
                }
            }
        }
        conflicts
    }
}

/// Rule-count effect of a single optimization pass — the compiler-style
/// "what optimization did" report (analogous to instructions eliminated).
#[derive(Debug, Clone)]
pub struct PassStat {
    pub name: &'static str,
    pub before: usize,
    pub after: usize,
}

impl PassStat {
    pub fn removed(&self) -> usize {
        self.before.saturating_sub(self.after)
    }
}

/// Run the optimization pipeline with the default (conservative) pass config.
pub fn run_pipeline_reported(
    rules: Vec<BehaviorRule>,
) -> (Vec<BehaviorRule>, Vec<PolicyConflict>, Vec<PassStat>) {
    run_pipeline_reported_with(rules, &PassConfig::default())
}

/// Run the optimization pipeline with an explicit (externalized) pass config and
/// return per-pass rule-count stats alongside the optimized rules and conflicts.
pub fn run_pipeline_reported_with(
    rules: Vec<BehaviorRule>,
    config: &PassConfig,
) -> (Vec<BehaviorRule>, Vec<PolicyConflict>, Vec<PassStat>) {
    let passes: Vec<Box<dyn OptimizationPass>> = vec![
        Box::new(CanonicalizationPass),
        Box::new(DeduplicationPass),
        Box::new(GeneralizationPass),
        // Invents directory prefixes from sibling clusters (semantics-widening,
        // guarded); must run before subsumption so the new prefixes can absorb
        // deeper stragglers.
        Box::new(PrefixGeneralizationPass::from_config(config)),
        Box::new(SubsumptionPass),
        // Final dedup: generalization/classification can turn distinct exact
        // paths (e.g. /proc/101/status, /proc/202/status) into identical
        // patterns (/proc/*/status). Collapse those duplicates now.
        Box::new(DeduplicationPass),
    ];

    let mut optimized = rules;
    let mut stats = Vec::with_capacity(passes.len());
    for pass in &passes {
        let before = optimized.len();
        optimized = pass.run(optimized);
        stats.push(PassStat { name: pass.name(), before, after: optimized.len() });
    }

    let conflicts = ConflictDetectionPass::detect(&optimized);
    (optimized, conflicts, stats)
}

pub fn run_pipeline(rules: Vec<BehaviorRule>) -> (Vec<BehaviorRule>, Vec<PolicyConflict>) {
    let (optimized, conflicts, _) = run_pipeline_reported(rules);
    (optimized, conflicts)
}

#[cfg(test)]
mod prefix_generalization_tests {
    use crate::policy::*;

    fn subj() -> Subject {
        Subject { container: Some(ContainerRef::CgroupId(1)), binary: None, uid: None }
    }

    fn meta() -> RuleMetadata {
        RuleMetadata {
            source_module: SourceModule::Fs,
            observation_count: 1,
            confidence: 1.0,
            first_seen: 0,
            last_seen: 0,
        }
    }

    fn exact(path: &str, verdict: Verdict) -> BehaviorRule {
        BehaviorRule {
            id: 0,
            subject: subj(),
            object: Object::File(FileObject {
                pattern: FilePattern::ExactPath(path.to_string()),
                is_sensitive: false,
            }),
            action: Action::FileRead,
            verdict,
            metadata: meta(),
        }
    }

    fn prefixes(rules: &[BehaviorRule]) -> Vec<String> {
        rules
            .iter()
            .filter_map(|r| match &r.object {
                Object::File(fo) => match &fo.pattern {
                    FilePattern::Prefix(p) => Some(p.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn count_exact(rules: &[BehaviorRule]) -> usize {
        rules
            .iter()
            .filter(|r| matches!(&r.object, Object::File(fo) if matches!(fo.pattern, FilePattern::ExactPath(_))))
            .count()
    }

    #[test]
    fn collapses_wal_segment_cluster() {
        let dir = "/var/lib/postgresql/data/pg_wal/";
        let rules: Vec<_> = (0..8)
            .map(|i| exact(&format!("{dir}00000001000000050000{:04X}", 0xC0 + i), Verdict::Allow))
            .collect();
        let out = PrefixGeneralizationPass::default().run(rules);
        assert_eq!(prefixes(&out), vec![dir.to_string()]);
        assert_eq!(count_exact(&out), 0);
    }

    #[test]
    fn refuses_etc_configs() {
        // Four distinct config files directly in /etc: the depth + denylist
        // guards must refuse this (the classic over-generalization disaster).
        let rules = vec![
            exact("/etc/passwd", Verdict::Allow),
            exact("/etc/hosts", Verdict::Allow),
            exact("/etc/resolv.conf", Verdict::Allow),
            exact("/etc/nsswitch.conf", Verdict::Allow),
        ];
        let out = PrefixGeneralizationPass::default().run(rules);
        assert!(prefixes(&out).is_empty());
        assert_eq!(count_exact(&out), 4);
    }

    #[test]
    fn refuses_small_cluster() {
        let dir = "/var/lib/app/sessions/";
        let rules: Vec<_> = (0..3)
            .map(|i| exact(&format!("{dir}sess_{:03}", i), Verdict::Allow))
            .collect();
        let out = PrefixGeneralizationPass::default().run(rules);
        assert!(prefixes(&out).is_empty());
        assert_eq!(count_exact(&out), 3);
    }

    #[test]
    fn refuses_unrelated_leaf_names_in_deep_dir() {
        // Passes depth, but the leaves are hand-picked words with no shared
        // template and are not hex/numeric, so guard 6 refuses.
        let dir = "/opt/myapp/config/";
        let rules = vec![
            exact(&format!("{dir}database"), Verdict::Allow),
            exact(&format!("{dir}logging"), Verdict::Allow),
            exact(&format!("{dir}auth"), Verdict::Allow),
            exact(&format!("{dir}cache"), Verdict::Allow),
        ];
        let out = PrefixGeneralizationPass::default().run(rules);
        assert!(prefixes(&out).is_empty(), "unrelated names should not generalize");
    }

    #[test]
    fn collapses_numeric_oid_cluster() {
        // PostgreSQL relation OIDs: short decimal names with little shared
        // affix, but the all-hex/numeric fallback recognizes them.
        let dir = "/var/lib/postgresql/data/base/5/";
        let rules: Vec<_> = [16401u32, 16385, 16402, 16390, 24576]
            .iter()
            .map(|oid| exact(&format!("{dir}{oid}"), Verdict::Allow))
            .collect();
        let out = PrefixGeneralizationPass::default().run(rules);
        assert_eq!(prefixes(&out), vec![dir.to_string()]);
    }

    #[test]
    fn opposing_deny_blocks_generalization() {
        let dir = "/var/lib/app/data/";
        let mut rules: Vec<_> = (0..6)
            .map(|i| exact(&format!("{dir}seg_{:04}", i), Verdict::Allow))
            .collect();
        rules.push(exact(&format!("{dir}seg_secret"), Verdict::Deny));
        let out = PrefixGeneralizationPass::default().run(rules);
        assert!(
            prefixes(&out).is_empty(),
            "an opposing deny under the dir must block the allow-prefix"
        );
    }

    #[test]
    fn pipeline_prefix_then_subsumes_deeper_stragglers() {
        // End-to-end: a WAL cluster collapses to a prefix, and a deeper file
        // under the same tree is then removed by subsumption.
        let dir = "/var/lib/postgresql/data/pg_wal/";
        let mut rules: Vec<_> = (0..8)
            .map(|i| exact(&format!("{dir}00000001000000050000{:04X}", i), Verdict::Allow))
            .collect();
        rules.push(exact(&format!("{dir}archive_status/000000010000000500000000.ready"), Verdict::Allow));

        let (out, _conflicts, stats) = run_pipeline_reported(rules);
        assert_eq!(prefixes(&out), vec![dir.to_string()]);
        assert_eq!(count_exact(&out), 0, "deeper straggler should be subsumed by the prefix");
        assert!(
            stats.iter().any(|s| s.name == "prefix-generalize" && s.removed() > 0),
            "prefix-generalize should report a rule-count reduction"
        );
    }
}
