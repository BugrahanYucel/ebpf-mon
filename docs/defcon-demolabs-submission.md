====================================================================
ABSTRACT (1337 characters max, Current: ~1272 chars)
====================================================================

Container security tools observe behavior (eBPF) and enforce policy (BPF-LSM, AppArmor, Seccomp). But the translation between observation and enforcement is manual and incomplete. We present the first tool that treats this translation as a compilation problem. Built in Rust with the Aya eBPF framework, three monitoring modules serve as compiler frontends feeding a normalized behavioral IR. Optimization passes operate on this IR: pattern classification, rule deduplication, dead rule elimination, conflict detection, and cross-category dependency linking. The backend compiles optimized IR into BPF-LSM enforcement rules across three LSM hooks: security_file_open, security_bprm_check_security, and security_socket_connect. Enforcement is default-deny: any operation not in the compiled profile is blocked. We demo end-to-end: a container is profiled, the profile compiled through the pipeline, and enforcement blocks unauthorized file access, process execution, and network connections at the kernel level. Zero manual policy writing. We document the friction points where monitoring context diverges from enforcement context. No existing tool, including vArmor and KubeArmor, implements this compilation architecture with a true IR, optimization passes, and multi-category LSM enforcement.

====================================================================
DETAILED OUTLINE
====================================================================

I. THE PROBLEM: WHY CONTAINERS NEED COMPILED SECURITY POLICIES
--------------------------------------------------------------------

Containers ship with broad default permissions. Most production containers can read, write, and execute far more than their workload requires. The industry recognizes this. Tools like Seccomp, AppArmor, and BPF-LSM exist to restrict container behavior. But writing these policies by hand is impractical:

- A typical container image invokes dozens of syscalls, accesses hundreds of file paths, and makes multiple network connections during normal operation.
- Manual policy authoring is error-prone, brittle across image updates, and simply doesn't scale.
- Existing tools that auto-generate policies (Kubernetes Security Profiles Operator, oci-seccomp-bpf-hook, Inspektor Gadget) target Seccomp only. Seccomp operates at the syscall number level and cannot inspect resolved parameters like file paths, network endpoints, or process identity.

The deeper problem: we can observe container behavior via eBPF with rich context (full file paths, process identity, container association, network endpoints), but we cannot automatically translate those observations into BPF-LSM enforcement policies that operate at the resource level. The monitoring hooks and the enforcement hooks live at different kernel abstraction layers with different data structures and different contexts. This gap between what eBPF monitoring captures and what BPF-LSM enforcement hooks can check is what our tool bridges.


II. THE INSIGHT: THIS IS A COMPILATION PROBLEM
--------------------------------------------------------------------

The translation from monitoring to enforcement has the same structure as a compiler pipeline:

- Source Language: raw eBPF monitoring events from heterogeneous hooks (fentry/fexit, tracepoints, btf_tracepoints, cgroup_skb). Each hook type has different "syntax": different struct layouts, different available data.

- Frontend: each monitoring module parses its hook-specific events into structured, per-module event formats. We have three frontends: filesystem, network, and process execution.

- Semantic Analysis: raw event data is resolved into meaningful security context. PIDs are resolved to binary paths, cgroup IDs to container identities, file descriptors to canonical paths.

- Intermediate Representation (IR): resolved events are normalized into hook-agnostic, enforcer-agnostic behavioral rules. A rule captures WHO (subject: container + process + uid), WHAT (object: file path pattern / network endpoint / binary), WHICH OPERATION (action: open, read, connect, exec), and WHAT TO DO (verdict: allow, deny, audit).

- Optimization Passes: transforms on the IR that preserve or narrow security semantics:

  * Pattern classification and merging: observed accesses to /proc/1234/cmdline, /proc/5678/cmdline, /proc/9012/cmdline are classified as instances of the /proc/*/cmdline PathPattern. The PID-specific paths are replaced with the classified pattern, and duplicate rules that share the same subject, action, and classified pattern are merged. This works across all monitored path categories: /proc, /sys, /dev, /run, /tmp, each with a predefined set of PathPattern variants that the system recognizes and classifies against.

  * Dead rule elimination: removing rules subsumed by broader rules (if /etc/** is allowed, /etc/hostname is a dead rule).

  * Rule merging: combining rules that differ only in action or access mode.

  * Conflict detection: flagging contradictions like allow /etc/** + deny /etc/shadow.

- Cross-Category Linker: a post-optimization pass that resolves implicit dependencies across rule categories. A ProcExec rule for binary P implies FileOpen + FileRead for the same path, since the kernel must open and read the binary before exec. The linker synthesizes these implicit file rules automatically, preventing the default-deny file policy from blocking operations that are prerequisites for permitted exec rules.

- Backend (Code Generation): the optimized IR is lowered to target-specific enforcement artifacts: BPF map entries populated from userspace, consumed by eBPF programs attached to LSM hooks. Three enforcement backends target three LSM hooks: security_file_open for file access, security_bprm_check_security for process execution, and security_socket_connect for network connections.

- Runtime/Loader: enforcement programs are attached, maps are populated, and audit-only mode can be enabled as a safe first step before switching to active enforcement.

This is not a metaphor. The architectural separation (frontends that are source-specific, an IR that is source and target-independent, and backends that are target-specific) has concrete engineering consequences. It means the same IR can target different enforcement mechanisms (BPF-LSM today, AppArmor or seccomp as future backends). It means that the optimization passes are composable, orderable, and independently testable. And it means frontends for other monitoring tools (Falco alerts, audit logs, Tetragon events) can be written without touching the backend.


III. THE HARD PART: LOWERING IR TO ENFORCEABLE RULES
--------------------------------------------------------------------

The most technically challenging aspect, and the core of this demo, is the "lowering" stage, where abstract IR rules must be translated into something a BPF-LSM enforcement hook can actually check at runtime.

Our IR might express a rule like:
  Subject: container("web-frontend") + process("/usr/bin/nginx")
  Object:  file(pattern: /proc/*/fd/*)
  Action:  FileOpen
  Verdict: Allow

But inside the security_file_open LSM hook, the eBPF program receives a struct file*, not a string path. The program must perform these "lowerings":

1. Lowering of Identities: Determine "who is doing this" by reading the cgroup ID via CO-RE task_struct traversal (task->sched_task_group->css->cgroup->kn->id) for container identity and bpf_get_current_comm() for process name. The container name is resolved to a cgroup ID at map-population time. Process identity via comm is limited to 16 characters and spoofable. A documented tradeoff.

2. Lowering of Resources: The enforcement program performs a multi-tier lookup to resolve resource identity. The strategy varies by enforcement category:

   File enforcement (security_file_open): Three-tier lookup. Tier 1 is the inode fast path: for ExactPath rules, the userspace loader resolves each path to its inode number at policy-load time, and the LSM hook reads the file's inode directly from struct file via CO-RE (file->f_inode->i_ino) for an O(1) hash map lookup. Tier 2 is pattern classification: the hook resolves the full path from the file's dentry chain, walks the dentry tree upward (dentry->d_parent, dentry->d_name) bounded to a fixed depth for verifier safety, then passes the resolved path through classify_path() to match against the same PathPattern categories used by the monitoring modules. Tier 2.5 is prefix matching: if classification yields no match, the hook iterates prefix entries for the cgroup and performs bounded byte-by-byte comparison against the resolved path, enabling directory-scoped allowlisting rules like /etc/nginx/conf.d/.

   Process enforcement (security_bprm_check_security): Inode-based exact-match lookup against the binary being exec'd, reading linux_binprm->file->f_inode->i_ino via CO-RE. Pattern classification fallback is architecturally supported in the hook but not currently populated by the loader; exec coverage relies on inode entries plus the cross-category linker synthesizing file-open rules for permitted binaries.

   Network enforcement (security_socket_connect): The hook reads sockaddr_in from the LSM context via CO-RE, extracts dst_ip and dst_port, and performs hash map lookups against the NET_CONNECT_POLICY map keyed by (cgroup_id, dst_ip, dst_port, protocol). Wildcard port entries (port=0) match any port to a given IP.

3. Lowering of Actions: A static mapping table connects IR actions to LSM hooks. FileOpen maps to security_file_open. NetConnect maps to security_socket_connect. ProcExec maps to security_bprm_check_security. This table is manually defined and is a core artifact of the system.

4. Lowering of Verdicts: The enforcement operates as a default-deny allowlist. If a rule matches with Verdict::Allow, return 0 (allow). If no rule matches for a container with an active policy, return -EPERM (deny). Audit-only mode overrides this: deny decisions are logged via perf events but the hook still returns 0 (allow), enabling safe policy validation before active enforcement.


IV. IMPLEMENTATION
--------------------------------------------------------------------

The tool is implemented entirely in Rust:

- Userspace: Rust, using the Aya framework for eBPF program management, map population, and lifecycle control.
- Kernel (eBPF): Rust via aya-ebpf, compiled to BPF bytecode. Monitoring programs attach to fentry/fexit hooks (filesystem VFS functions), tracepoints and btf_tracepoints (process events), and cgroup_skb hooks (network events). Enforcement programs attach to BPF-LSM hooks: security_file_open, security_bprm_check_security, and security_socket_connect.
- All kernel struct access uses CO-RE (Compile Once, Run Everywhere) via C shim functions with __attribute__((preserve_access_index)), ensuring portability across kernel versions without recompilation.
- Infrastructure: deployed on cloud VMs with BPF-LSM-enabled kernels.
- The monitoring pipeline has been running in production for several months, profiling containerized workloads and producing optimized behavioral profiles with classified path patterns.

The CLI integrates the full pipeline via two flags: --enforce <profile.json> loads a monitoring profile and compiles it through the translation, optimization, linking, and code generation stages, then attaches enforcement programs alongside the monitoring modules. --audit-only enables safe policy validation by logging deny decisions without blocking. Monitoring and enforcement coexist: the tool continues profiling even while enforcing, allowing operators to observe how the workload's behavior evolves under enforcement.


V. LIVE DEMO PLAN
--------------------------------------------------------------------

The demo shows the full compilation pipeline across all three enforcement categories:

1. Start: Launch a test container (e.g., nginx) on a BPF-LSM-enabled kernel.

2. Monitor: Show the monitoring modules collecting filesystem, network, and process events in real time: file opens, reads, network connections, process executions.

3. Profile: Show the raw events being normalized into the behavioral IR, and the optimization passes running: pattern classification producing PathPattern-based rules, duplicate rules being merged, subsumed rules being eliminated, the cross-category linker synthesizing implicit file rules from exec rules, the final optimized profile.

4. Compile: Show the IR being lowered into BPF map entries (the "code generation" step). Walk through what a map entry looks like: InodeKey entries for exact file paths, PatternKey entries for classified patterns, PrefixEntry entries for directory-scoped rules, NetPolicyKey entries for network endpoints, and PolicyConfig entries for per-container settings.

5. Enforce: Load the enforcement policy. Attach all three LSM programs. First enable audit-only mode to validate the policy without blocking, then switch to active enforcement.

6. Test: Attempt unauthorized operations from within the container. Access a file path not in the behavioral profile and show it being blocked. Execute a binary not in the profile and show it being denied. Attempt a network connection to an endpoint not in the profile and show it being rejected. Show the enforcement decisions in the audit log.

7. Friction: Walk through a concrete example where the monitoring captured something that the enforcement hook cannot fully replicate. Show the gap and how the system handles it (the rule falls through to the default-deny policy, or is logged in audit-only mode for manual review).


VI. PRIOR ART AND POSITIONING
--------------------------------------------------------------------

We surveyed the ecosystem extensively and found no existing tool that implements this formalized compilation architecture:

- vArmor (ByteDance, Apache 2.0): The closest existing tool. As of v0.9.0 (November 2025), vArmor implements eBPF behavioral profiling, an ArmorProfileModel CRD as intermediate storage, and BPF-LSM policy generation. However: their intermediate representation is a flat Kubernetes CRD storing raw behavioral data, not a normalized IR with formal properties. There are no optimization passes, no pattern classification, no dead rule elimination, no conflict detection. Mode transitions are manual. The BPF-LSM behavioral modeling support is experimental.

- KubeArmor + AccuKnox Discovery Engine (CNCF Sandbox): KubeArmor was the first engine to operationalize BPF-LSM enforcement from user-specified policies. The Discovery Engine auto-generates policies from eBPF telemetry, but discovered policies are created with Inactive status and require explicit human approval before enforcement.

- Seccomp auto-generation ecosystem (SPO, oci-seccomp-bpf-hook, Inspektor Gadget): Mature pipeline for eBPF-traced syscalls to seccomp profiles. But seccomp operates at the syscall number level only, it cannot inspect resolved parameters like file paths or network endpoints.

- Academic: bpfbox and BPFContain (Findlay et al.) pioneered eBPF-LSM process confinement but require manually authored policies. Confine and SPEAKER auto-generate from profiling but target seccomp only. No academic publication describes the compiler pipeline architecture for this domain.


VII. THE FRICTION INVENTORY (NOVEL CONTRIBUTION)
--------------------------------------------------------------------

A unique output of this work is a documented inventory of every point where monitoring context diverges from enforcement context:

- Path representation: monitoring captures resolved string paths; LSM hooks provide struct file requiring dentry chain traversal with bounded depth.
- Path classification: monitoring classifies paths in the resolved string domain; enforcement must re-classify by walking dentries and re-resolving, introducing potential divergence for mount overlays and bind mounts.
- Process identity: monitoring resolves full binary paths via CO-RE mm->exe_file traversal; enforcement gets 16-char truncated comm or must dereference current->mm->exe_file (verifier-fragile and restricted in some program types like cgroup_skb, where bpf_probe_read is unavailable).
- Container identity: cgroup IDs are stable within a session but change across container restarts; map entries need refresh. The monitoring tool includes a container watcher that detects restarts and updates the eBPF cgroup filter automatically.
- Inode namespacing: monitoring captures inodes from the container's overlay filesystem, which differ from host inodes for the same paths. The enforcement loader must use the profiled inodes directly rather than resolving paths on the host, since container-internal paths (e.g., /bin/busybox) may not exist on the host at all. We solved this by propagating profiled inodes through the IR and using them at policy-load time.
- Helper restrictions: different eBPF program types have different helper availability. cgroup_skb programs cannot use bpf_probe_read (helper #4), only bpf_probe_read_kernel. LSM programs support both. This constrains what context can be collected in each hook type.
- Exec inode timing: at sys_enter_execve, mm->exe_file still points to the calling binary, not the new one. The profiler captures the correct inode by reading exe_file in the exit tracepoint (after exec succeeds), when mm->exe_file has been updated to the new binary. This is a subtle timing issue that causes inode: 0 if captured at the wrong point.
- Coverage gaps: some monitored behaviors (e.g., certain tracepoint-observed events) have no LSM hook equivalent.
- TOCTOU: tracepoint monitoring observes user-space pointers that could be modified between observation and use; LSM hooks operate post-resolution, partially mitigating this.

This inventory has not been published elsewhere and represents practical knowledge valuable to anyone building eBPF-based security tooling.


VIII. LIMITATIONS AND HONEST ASSESSMENT
--------------------------------------------------------------------

- BEHAVIORAL COVERAGE GAP: Profiling only captures behaviors exercised during the observation window. Rare code paths (error handlers, periodic jobs, seasonal workflows) may go unobserved, causing false-positive blocks. We mitigate this with audit-only mode and configurable observation windows, but the fundamental limitation remains.

- TRAINING-PHASE INTEGRITY: An attacker who compromises a container during profiling embeds their techniques in the baseline. We do not currently detect this.

- CLASSIFICATION GRANULARITY: The path classification engine uses ~30 predefined categories. Paths that don't match any category are classified as Regular and handled by the default-deny policy. Prefix matching extends coverage to directory-scoped rules. Full per-component wildcard matching for arbitrary user-defined patterns (e.g., /etc/nginx/conf.d/*.conf) is under development.

- VERIFIER CONSTRAINTS: eBPF path matching is bounded to a fixed depth and fixed buffer sizes. Deeply nested paths or very long path components may be truncated.

- IPv4 ONLY: Network enforcement currently supports IPv4 only (AF_INET). IPv6 support requires extending the NetPolicyKey type and adding sockaddr_in6 CO-RE bindings.


IX. FUTURE WORK
--------------------------------------------------------------------

- Per-component wildcard matching: extending the dentry-walk enforcement to match each path component against user-defined pattern components, enabling rules like /etc/nginx/conf.d/*.conf without predefined PathPattern variants.
- Progressive rollout state machine: formal shadow -> audit -> enforce mode transitions with automated graduation criteria.
- Multi-target compilation: same IR compiling to AppArmor profiles and seccomp filters as alternative backends.
- Confidence scoring: weighting rules by observation count and temporal distribution to handle the coverage gap.
- Integration with container orchestration (Kubernetes CRDs) for policy lifecycle management.
- Frontends for other monitoring tools (Falco alerts, audit logs, Tetragon events) without modifying the backend.


X. REFERENCES
--------------------------------------------------------------------

Publishable:
- Aya eBPF framework: https://aya-rs.dev/
- vArmor (ByteDance): https://github.com/bytedance/vArmor
- KubeArmor: https://github.com/kubearmor/KubeArmor
- AccuKnox Discovery Engine:
    https://github.com/accuknox/discovery-engine
- Kubernetes Security Profiles Operator:
    https://github.com/kubernetes-sigs/security-profiles-operator
- bpfbox (Findlay, Somayaji, Barrera, ACM CCSW 2020):
    https://dl.acm.org/doi/10.1145/3411495.3421358
- BPFContain (Findlay et al., 2021):
    https://arxiv.org/pdf/2102.06972
- Confine (Ghavamnia et al., USENIX RAID 2020):
    https://www.usenix.org/system/files/raid20-ghavamnia.pdf
- SPEAKER (Lei et al., DIMVA 2017): split-phase container
    profiling with per-phase seccomp filters
- Linux kernel lsm_hook_defs.h:
    https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h

Confidential:
- [Link to your private repository -- for review board only]

====================================================================
END OF SUBMISSION
====================================================================
