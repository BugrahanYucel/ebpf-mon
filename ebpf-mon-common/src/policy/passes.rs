use std::collections::HashMap;
use super::ir::*;

pub trait OptimizationPass {
    fn name(&self) -> &'static str;
    fn run(&self, rules: Vec<BehaviorRule>) -> Vec<BehaviorRule>;
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
            (Object::File(n), Object::File(b)) => {
                b.pattern.subsumes(&n.pattern) && n.pattern != b.pattern
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

pub fn run_pipeline(rules: Vec<BehaviorRule>) -> (Vec<BehaviorRule>, Vec<PolicyConflict>) {
    let passes: Vec<Box<dyn OptimizationPass>> = vec![
        Box::new(DeduplicationPass),
        Box::new(GeneralizationPass),
        Box::new(SubsumptionPass),
    ];

    let mut optimized = rules;
    for pass in &passes {
        optimized = pass.run(optimized);
    }

    let conflicts = ConflictDetectionPass::detect(&optimized);
    (optimized, conflicts)
}
