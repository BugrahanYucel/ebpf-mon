# Backend Coverage Truth Table (IR → enforcement targets)

What each backend can express from the neutral IR. Generated/verified against
`ebpf-mon-common/src/policy/friction.rs` and live `--friction-report` runs on
`docs/demo/example-events.json`.

Legend: **OK** = expressed exactly · **APPROX** = emitted but widened/coarsened ·
**DROP** = cannot represent, rule is lost.

## Files (`Object::File`)

| IR construct | action | BPF-LSM | AppArmor | Why |
|---|---|---|---|---|
| `ExactPath` | Open | **OK** | **OK** | path hash / literal path |
| `ExactPath` | Read | **APPROX** | **OK** | BPF: `security_file_open` is open-granularity (no R/W); AA: `r,` |
| `ExactPath` | Write | **APPROX** | **OK** | BPF: open-granularity; AA: `w,` |
| `Prefix("/d/")` | Read/Write | **APPROX** | **OK** | BPF: open-granularity + prefix map; AA: `/d/** r\|w` |
| `Prefix` (> `PREFIX_MAX_LEN`) | any | **DROP** | **OK** | BPF: exceeds kernel prefix cap |
| `Classified(ProcPidStatus, …)` | Read | **APPROX** | **OK** | AA glob `/proc/*/status`; BPF open-granularity |
| `Classified(ProcPidOther/ProcGlobal)` | Read | **APPROX** | **APPROX** | AA widens `<other>`→`*`; BPF open-granularity |
| `Classified(Regular)` | any | **DROP** | **DROP** | no concrete key / not an AARE glob |

## Processes (`Object::Process`)

| IR construct | action | BPF-LSM | AppArmor | Why |
|---|---|---|---|---|
| `BinaryRef::Path` | ProcExec | **OK** | **OK** | BPF: path-hash exec map; AA: `ix,` |
| `BinaryRef::Comm` | ProcExec | **DROP** | **DROP** | no path to hash / to emit |
| any | ProcFork (or other) | **DROP** | **DROP** | no fork-enforcement hook / rule form |

## Network (`Object::Network`)

| IR construct | action | BPF-LSM | AppArmor | Why |
|---|---|---|---|---|
| `dst_ip=Some, dst_port=Some` | NetConnect | **APPROX** | **APPROX** | BPF: key omits protocol; AA: ip/port is ABI-gated |
| `dst_ip=Some, dst_port=None` | NetConnect | **OK*** | **APPROX** | BPF: `(ip,0)` wildcard-port key; AA ABI-gated |
| `dst_ip=None` (any peer) | NetConnect | **DROP** | **OK** | BPF loader drops ip-less rules; AA: coarse `network inet <type>` |
| any | NetBind | **DROP** | **OK** | BPF: no bind hook; AA: bind form |

`*` protocol still not enforced (non-discriminating).

## Verdicts

| verdict | BPF-LSM | AppArmor |
|---|---|---|
| Allow | **OK** | **OK** |
| Deny | **OK** (verdict byte 0) | **OK** (`deny …`) |
| Audit | **OK** (global audit-only mode) | **APPROX** (no native per-rule audit) |

## The one-sentence takeaways for the slide

- **Files:** AppArmor keeps read/write; BPF-LSM is **open-granularity** (its
  `security_file_open` hook can't see R/W). Neither loses *which paths* — only the
  R/W distinction, and only on BPF-LSM.
- **Network:** BPF-LSM pins a concrete IP and ignores protocol; AppArmor keeps
  protocol (stream/dgram) but ip/port is ABI-gated. **IP-wildcard is the sharp
  edge**: expressible in AppArmor, dropped by BPF-LSM.
- **Every one of these is emitted by `--friction-report`, per rule, with the
  reason** — the tool documents its own envelope.
