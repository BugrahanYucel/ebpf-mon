use crate::fs::PathPattern;
use super::types::PolicyAction;

pub type RuleId = u64;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehaviorRule {
    pub id: RuleId,
    pub subject: Subject,
    pub object: Object,
    pub action: Action,
    pub verdict: Verdict,
    pub metadata: RuleMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Subject {
    pub container: Option<ContainerRef>,
    pub binary: Option<BinaryRef>,
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ContainerRef {
    Name(std::string::String),
    CgroupPath(std::string::String),
    CgroupId(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BinaryRef {
    Path(std::string::String),
    Comm([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Object {
    File(FileObject),
    Network(NetworkObject),
    Process(ProcessObject),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileObject {
    pub pattern: FilePattern,
    pub is_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FilePattern {
    Classified(PathPattern),
    ExactPath(std::string::String),
    Prefix(std::string::String),
}

/// How one file pattern's match-set relates to another's — the single
/// containment primitive shared by subsumption (which needs a sound `Superset`)
/// and the conflict/generalization guards (which need a sound `Disjoint`).
/// Mirrors the firewall policy-analysis taxonomy (Al-Shaer et al.): exact,
/// inclusive (super/subset), correlated (overlap), and disjoint.
///
/// Soundness contract, so both consumers stay safe when the relation is unknown:
///   * `Equal`/`Superset`/`Subset` are returned only when provably true, so
///     subsumption never drops a rule that isn't actually covered.
///   * `Disjoint` is returned only when the two sets provably cannot both match
///     any path, so conflict/overlap guards never miss a real interaction.
///   * Anything uncertain collapses to `Overlap` — safe for both directions (no
///     rule dropped, but still flagged as interacting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRelation {
    Equal,
    Superset,
    Subset,
    Overlap,
    Disjoint,
}

impl PathRelation {
    #[inline]
    fn swap(self) -> Self {
        match self {
            PathRelation::Superset => PathRelation::Subset,
            PathRelation::Subset => PathRelation::Superset,
            other => other,
        }
    }
}

impl FilePattern {
    /// Relation of `self`'s match-set to `other`'s (see [`PathRelation`]).
    pub fn relation_to(&self, other: &FilePattern) -> PathRelation {
        use FilePattern::*;
        match (self, other) {
            (ExactPath(a), ExactPath(b)) => {
                if a == b { PathRelation::Equal } else { PathRelation::Disjoint }
            }
            (Prefix(a), Prefix(b)) => {
                if a == b {
                    PathRelation::Equal
                } else if b.starts_with(a.as_str()) {
                    PathRelation::Superset
                } else if a.starts_with(b.as_str()) {
                    PathRelation::Subset
                } else {
                    PathRelation::Disjoint
                }
            }
            (Prefix(pre), ExactPath(p)) => {
                if p.starts_with(pre.as_str()) {
                    PathRelation::Superset
                } else {
                    PathRelation::Disjoint
                }
            }
            (Classified(a), Classified(b)) => {
                if a == b { PathRelation::Equal } else { classified_vs_classified(*a, *b) }
            }
            (Prefix(pre), Classified(c)) => prefix_vs_glob(pre, c.as_str()),
            (ExactPath(p), Classified(c)) => exact_vs_glob(p, c.as_str()),

            // Reverse directions delegate + swap, keeping the logic in one place.
            (ExactPath(_), Prefix(_))
            | (Classified(_), Prefix(_))
            | (Classified(_), ExactPath(_)) => other.relation_to(self).swap(),
        }
    }

    /// `self` covers everything `other` matches (broad ⊇ narrow). Thin wrapper
    /// over [`FilePattern::relation_to`] for call-site readability.
    pub fn subsumes(&self, other: &FilePattern) -> bool {
        matches!(self.relation_to(other), PathRelation::Superset | PathRelation::Equal)
    }
}

/// Literal head of a classified glob — the fixed bytes before the first wildcard
/// (`*`, `?`) or `<placeholder>`. Every path the glob can match begins with this
/// string, which is enough to prove containment/disjointness against a plain
/// prefix without a full glob engine.
fn glob_literal_root(glob: &str) -> &str {
    let end = glob.find(|c| c == '*' || c == '?' || c == '<').unwrap_or(glob.len());
    &glob[..end]
}

/// Prefix (always canonicalized to end in `/`) vs a classified glob.
fn prefix_vs_glob(pre: &str, glob: &str) -> PathRelation {
    let root = glob_literal_root(glob);
    if root.starts_with(pre) {
        // Every match of the glob starts with `root`, hence with `pre`.
        PathRelation::Superset
    } else if pre.starts_with(root) {
        // `pre` reaches into the glob's variable region — can't prove either way.
        PathRelation::Overlap
    } else {
        // Roots diverge before either ends → no path starts with both.
        PathRelation::Disjoint
    }
}

/// Exact path vs a classified glob. We never fully evaluate the glob, so we only
/// prove `Disjoint` (roots diverge); otherwise conservatively `Overlap`.
fn exact_vs_glob(path: &str, glob: &str) -> PathRelation {
    let root = glob_literal_root(glob);
    if path.starts_with(root) { PathRelation::Overlap } else { PathRelation::Disjoint }
}

/// Two distinct classified globs: `Disjoint` when their literal roots diverge,
/// else conservatively `Overlap` (several classified patterns are catch-alls).
fn classified_vs_classified(a: PathPattern, b: PathPattern) -> PathRelation {
    let (ra, rb) = (glob_literal_root(a.as_str()), glob_literal_root(b.as_str()));
    if ra.starts_with(rb) || rb.starts_with(ra) {
        PathRelation::Overlap
    } else {
        PathRelation::Disjoint
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NetworkObject {
    pub dst_ip: Option<u32>,
    pub dst_port: Option<u32>,
    pub protocol: Option<u8>,
    pub direction: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ProcessObject {
    pub binary: BinaryRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Action {
    FileOpen,
    FileRead,
    FileWrite,
    NetConnect,
    NetBind,
    ProcExec,
    ProcFork,
}

impl Action {
    pub fn to_policy_action(self) -> PolicyAction {
        match self {
            Action::FileOpen => PolicyAction::FileOpen,
            Action::FileRead => PolicyAction::FileRead,
            Action::FileWrite => PolicyAction::FileWrite,
            Action::NetConnect => PolicyAction::NetConnect,
            Action::NetBind => PolicyAction::NetBind,
            Action::ProcExec => PolicyAction::ProcExec,
            Action::ProcFork => PolicyAction::ProcFork,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    Allow,
    Deny,
    Audit,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleMetadata {
    pub source_module: SourceModule,
    pub observation_count: u64,
    pub confidence: f32,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SourceModule {
    Fs,
    Net,
    Proc,
}

impl BehaviorRule {
    pub fn signature(&self) -> (Subject, Object, Action) {
        (self.subject.clone(), self.object.clone(), self.action)
    }

    pub fn conflicts_with(&self, other: &BehaviorRule) -> bool {
        self.subject == other.subject
            && self.object == other.object
            && self.action == other.action
            && self.verdict != other.verdict
    }
}

#[cfg(test)]
mod path_relation_tests {
    use super::*;
    use crate::fs::PathPattern;

    fn exact(p: &str) -> FilePattern { FilePattern::ExactPath(p.to_string()) }
    fn prefix(p: &str) -> FilePattern { FilePattern::Prefix(p.to_string()) }
    fn cls(p: PathPattern) -> FilePattern { FilePattern::Classified(p) }

    #[test]
    fn exact_equal_or_disjoint() {
        assert_eq!(exact("/a/b").relation_to(&exact("/a/b")), PathRelation::Equal);
        assert_eq!(exact("/a/b").relation_to(&exact("/a/c")), PathRelation::Disjoint);
    }

    #[test]
    fn prefix_contains_exact_and_prefix() {
        assert_eq!(prefix("/a/b/").relation_to(&exact("/a/b/c")), PathRelation::Superset);
        assert_eq!(exact("/a/b/c").relation_to(&prefix("/a/b/")), PathRelation::Subset);
        assert_eq!(prefix("/a/").relation_to(&prefix("/a/b/")), PathRelation::Superset);
        assert_eq!(prefix("/a/b/").relation_to(&prefix("/a/")), PathRelation::Subset);
        // Sibling prefixes never touch (both canonicalized with trailing '/').
        assert_eq!(prefix("/a/").relation_to(&prefix("/b/")), PathRelation::Disjoint);
        assert_eq!(prefix("/a/").relation_to(&exact("/b/x")), PathRelation::Disjoint);
    }

    #[test]
    fn prefix_vs_classified_glob() {
        // /proc/ subsumes /proc/*/status (every match lives under /proc/).
        assert_eq!(
            prefix("/proc/").relation_to(&cls(PathPattern::ProcPidStatus)),
            PathRelation::Superset
        );
        // A prefix diving into the variable region can't be proven either way.
        assert_eq!(
            prefix("/proc/1/").relation_to(&cls(PathPattern::ProcPidStatus)),
            PathRelation::Overlap
        );
        // Unrelated roots are provably disjoint.
        assert_eq!(
            prefix("/dev/").relation_to(&cls(PathPattern::ProcPidStatus)),
            PathRelation::Disjoint
        );
    }

    #[test]
    fn subsumes_matches_relation() {
        assert!(prefix("/a/b/").subsumes(&exact("/a/b/c")));
        assert!(prefix("/proc/").subsumes(&cls(PathPattern::ProcPidStatus)));
        assert!(!exact("/a/b/c").subsumes(&prefix("/a/b/")));
        assert!(!cls(PathPattern::ProcPidStatus).subsumes(&exact("/proc/1/status")));
    }
}
