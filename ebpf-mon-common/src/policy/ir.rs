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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiled_inode: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FilePattern {
    Classified(PathPattern),
    ExactPath(std::string::String),
    Prefix(std::string::String),
}

impl FilePattern {
    pub fn subsumes(&self, other: &FilePattern) -> bool {
        match (self, other) {
            (FilePattern::Classified(a), FilePattern::Classified(b)) => a == b,
            (FilePattern::Prefix(prefix), FilePattern::ExactPath(path)) => path.starts_with(prefix.as_str()),
            (FilePattern::Prefix(a), FilePattern::Prefix(b)) => b.starts_with(a.as_str()),
            _ => false,
        }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiled_inode: Option<u64>,
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
