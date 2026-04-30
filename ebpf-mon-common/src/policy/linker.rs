use super::ir::*;

/// Resolve implicit cross-category dependencies.
///
/// A ProcExec rule for binary P implies that the enforcement engine must also
/// allow FileOpen + FileRead for that same path, otherwise the default-deny
/// file policy will block the exec before the bprm hook even fires.
pub fn link_cross_category(mut rules: Vec<BehaviorRule>) -> Vec<BehaviorRule> {
    let mut next_id = rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
    let mut synthetic = Vec::new();

    for rule in &rules {
        if rule.action != Action::ProcExec {
            continue;
        }
        let binary_path = match &rule.object {
            Object::Process(proc_obj) => match &proc_obj.binary {
                BinaryRef::Path(p) => p.clone(),
                BinaryRef::Comm(_) => continue,
            },
            _ => continue,
        };

        let proc_inode = match &rule.object {
            Object::Process(proc_obj) => proc_obj.profiled_inode,
            _ => None,
        };

        let file_obj = Object::File(FileObject {
            pattern: FilePattern::ExactPath(binary_path),
            is_sensitive: false,
            profiled_inode: proc_inode,
        });

        for action in [Action::FileOpen, Action::FileRead] {
            let already_exists = rules.iter().chain(synthetic.iter()).any(|r| {
                r.subject == rule.subject && r.object == file_obj && r.action == action
            });
            if already_exists {
                continue;
            }
            synthetic.push(BehaviorRule {
                id: next_id,
                subject: rule.subject.clone(),
                object: file_obj.clone(),
                action,
                verdict: rule.verdict,
                metadata: RuleMetadata {
                    source_module: SourceModule::Fs,
                    observation_count: 0,
                    confidence: 1.0,
                    first_seen: rule.metadata.first_seen,
                    last_seen: rule.metadata.last_seen,
                },
            });
            next_id += 1;
        }
    }

    if !synthetic.is_empty() {
        log::info!("Linker: synthesized {} implicit file rules from exec rules", synthetic.len());
        rules.extend(synthetic);
    }

    rules
}
