# AppArmor profile format — working reference

Distilled from the authoritative `apparmor.d(5)` man page (apparmor.net 5.0 / Arch /
Debian / Ubuntu editions agree). This is the reference the AppArmor frontend
(`policy/frontends/apparmor.rs`) and backend (`policy/backends/apparmor.rs`) are
implemented against. When in doubt, the real source of truth is
`apparmor_parser -Q <profile>` (parse + validate, do **not** load into kernel).

---

## 1. File layout

```
PROFILE FILE = ( [ PREAMBLE ] [ PROFILE ] )*
PROFILE      = PROFILE-HEAD [ ATTACHMENT ] [ FLAGS ] '{' RULES* '}'
```

- **Line-oriented.** `#` starts a comment. `#include` splices a file inline (cpp-style).
- **Every rule ends with a comma `,`** (this is the single most common syntax error).
- **Preamble** (before/outside the `profile { }` block) may contain:
  - `abi <abi/4.0>,` — declares the feature ABI the policy was written for. Optional
    but recommended for modern policy; controls whether fine-grained features (e.g.
    network ip/port) are honored or silently downgraded.
  - `#include <tunables/global>` — pulls in variable definitions (`@{HOME}` etc.).
  - `@{VAR} = value` — variable assignment.
  - `alias /from/ -> /to/,` — path remapping.

### Profile head

```
profile <name> [<attachment glob>] [flags=(<flag>,<flag>)] {
    ...
}
```

- `<name>` is an identifier (short name recommended, e.g. `docker-default`). If it is
  an absolute path it can double as the exec attachment; discouraged.
- Quote the name if it contains spaces.
- **Flags** are comma-separated inside parens, e.g.
  `flags=(attach_disconnected,mediate_deleted)` (this matches Docker's real
  `docker-default` profile). Notable flags:
  - Mode: `enforce` (default), `complain` (log-but-allow), `kill`, `default_allow`.
  - `attach_disconnected` — give a path to files opened before the profile attached.
  - `mediate_deleted` — keep mediating files after unlink.

---

## 2. File rules

```
FILE RULE = [ QUALIFIERS ] [ 'owner' ] ( [ 'file' ] ( FILEGLOB ACCESS | ACCESS FILEGLOB ) [ '->' EXEC-TARGET ] )
```

- Path (FILEGLOB) and permissions can be in **either order**: `/etc/foo r,` or `r /etc/foo,`.
- Path **must be absolute** (start with `/` after variable expansion).
- **Quote** the path if it contains spaces/tabs: `"/etc/my file" r,`.
- A **trailing `/`** means the rule matches *directories only*
  (`/var/log/` matches the dir, not files in it).

### ACCESS permission letters

```
ACCESS = ( 'r' | 'w' | 'a' | 'l' | 'k' | 'm' | EXEC-TRANSITION )+
```

| letter | meaning                                    |
|--------|--------------------------------------------|
| `r`    | read                                       |
| `w`    | write (implies append; conflicts with `a`) |
| `a`    | append only                                |
| `l`    | link                                       |
| `k`    | file locking                               |
| `m`    | mmap with PROT_EXEC (executable memory map)|

Not all combinations are legal (`w` + `a` conflict).

### Exec transitions (the `x` family)

```
EXEC-TRANSITION = ix | ux | Ux | px | Px | cx | Cx | pix | Pix | cix | Cix | pux | PUx | cux | CUx | x
```

- `ix` — **inherit**: executed program keeps running under the *current* profile.
- `px`/`Px` — transition to the **discrete profile** named by the executable
  (uppercase `P` scrubs the environment = safer).
- `cx`/`Cx` — transition to a **child/subprofile** defined inside this profile.
- `ux`/`Ux` — run **unconfined** (uppercase scrubs env). Dangerous.
- `pix`/`cix`/... — try p/c transition, fall back to `ix` if no match.
- A **bare `x` is only valid with the `deny` qualifier.**
- A bare transition (e.g. `/usr/bin/foo ix,`) is valid — read (`r`) is *not*
  syntactically required, though real profiles often add `r`/`m` so the loader and
  mmap succeed at runtime.
- `-> target` names the destination profile (only with `px`/`cx` families):
  `/usr/bin/helper cx -> sandbox,`.

---

## 3. Network rules

```
NETWORK RULE = [ QUALIFIERS ] 'network' [ ACCESS ] [ DOMAIN ] [ TYPE | PROTOCOL ] [ LOCAL EXPR ] [ PEER EXPR ]
```

Rules are **broad by default and narrow as you add conditionals**. Permissions
accumulate (union) across all matching network rules.

- **DOMAIN** (address family): `inet`, `inet6`, `unix`, `netlink`, `packet`, ... (long list).
- **TYPE**: `stream`, `dgram`, `seqpacket`, `raw`, ...
- **PROTOCOL**: `tcp`, `udp`, `icmp`.

Coarse examples:

```
network,               # all networking
network tcp,           # tcp only
network inet stream,   # ipv4 stream (tcp) sockets
network inet6 tcp,     # ipv6 tcp
```

### Fine-grained inet/inet6 mediation (IMPORTANT — corrects an earlier assumption)

Modern AppArmor **can** mediate on IP and port with `ip=` / `port=` conditionals and
a `peer=(...)` block for the remote endpoint:

```
network ip=127.0.0.1 port=8080,                          # local bind
network peer=(ip=10.139.15.23 port=8081),                # remote (connect dst)
network ip=127.0.0.1 port=8080 peer=(ip=10.139.15.23 port=8081),
network ip=127.0.0.1 port=8080-8084,                     # port ranges
```

- `ip=` accepts IPv4 (`a.b.c.d`) and IPv6. `none` = unbound/unknown address.
- Omitting `ip=` means "any IP" (v4, v6, and none).
- **This is ABI-gated.** On kernels/parsers/ABIs without fine-grained support, the
  rule is *downgraded* to the coarse form (`network inet stream`) — it does not error,
  it silently widens. So emitting `peer=(ip=..,port=..)` is correct *and* safe: it is
  as precise as the target allows and degrades gracefully.

**Mapping to our IR:** a `NetConnect` with a destination is the **peer**; a `NetBind`
with a local address/port is the **local** expr.

---

## 4. Globbing (AARE)

AppArmor path globs ("AARE" = AppArmor Regular Expression):

| token      | matches                                              |
|------------|------------------------------------------------------|
| `*`        | any number of chars **except** `/`                   |
| `**`       | any number of chars **including** `/`                |
| `?`        | any single char except `/`                           |
| `[abc]`    | one of `a`,`b`,`c`                                    |
| `[a-c]`    | one char in range                                    |
| `[^a-c]`   | one char not in range                                |
| `{ab,cd}`  | alternation (expands to multiple rules)              |
| `@{var}`   | variable expansion                                   |

Directory-matching examples:

```
/tmp/*      files directly in /tmp
/tmp/*/     directories directly in /tmp
/tmp/**     files and dirs anywhere under /tmp
/tmp/**/    directories anywhere under /tmp
```

> Our `PathPattern::as_str()` values are *already* valid AARE globs
> (`/proc/*/status`, `/sys/fs/cgroup/**`, `/tmp/**`, ...). The only non-AARE tokens
> are the internal placeholders `<regular>`, `<other>`, `<global>`, which the backend
> must translate (`<other>`→`*`/`**`, `<global>`→`*`) or drop (`<regular>` is not
> emittable and is reported as a lowering warning).

---

## 5. Rule qualifiers

```
[ priority=N ] [ audit ] ( allow | deny ) [ owner ] <rule>,
```

- `allow` — default; may be omitted.
- `deny` — deny without logging (combine with `audit` to log).
- `audit` — log matches.
- `owner` — only when task euid/fsuid == object owner.
- `priority=N` (-1000..1000) — higher priority fully overrides lower on overlap.

Qualifier blocks apply a qualifier to many rules:

```
deny {
    /etc/shadow r,
    network,
}
```

---

## 6. What our IR maps to (expressibility envelope)

| IR construct                              | AppArmor rule                              | lossy? |
|-------------------------------------------|--------------------------------------------|--------|
| `File{ExactPath(p)}` + FileRead           | `p r,`                                     | no     |
| `File{ExactPath(p)}` + FileWrite          | `p w,`                                     | no     |
| `File{Prefix(pre)}`                       | `pre** <perm>,`                            | no     |
| `File{Classified(pat)}` (AARE glob)       | `<glob> <perm>,`                           | no     |
| `File{Classified(<other>/<global>)}`      | widened `*` / `**`                         | yes    |
| `File{Classified(Regular)}`               | (not emittable)                            | drop+warn |
| `Process{Path(p)}` + ProcExec             | `p ix,`                                    | no*    |
| `Network{NetConnect, ip, port}`           | `network inet <type> peer=(ip=,port=),`    | ABI-gated |
| `Network{NetBind, ip, port}`              | `network inet <type> ip=,port=,`           | ABI-gated |
| `Network` (no ip/port)                    | `network inet <type>,`                     | no     |

`*` `ix` is exact for "inherit current profile"; if we later synthesize per-binary
profiles we would emit `Px -> <profile>` instead.

**Not representable in our IR (dropped by the frontend, never emitted by the backend):**
capabilities, mount/pivot_root, dbus, signal, ptrace, unix-socket fine grain, link
rules, rlimits, change_profile, subprofiles/hats, xattr attachments. The frontend
skips these lines rather than erroring; the backend never produces them. This is the
"expressibility envelope" — it is *bounded and documented*, not silent.

---

## 7. Verifying correctness (do this, don't trust memory)

1. **Syntactic gate:** `apparmor_parser -Q <profile>` parses + validates without
   loading. Nonzero exit = malformed. Wire into CI/tests.
2. **Round-trip:** IR → backend → `apparmor_parser -Q` (valid?) → frontend → IR′,
   assert IR ≈ IR′ modulo the documented lossy rows above.
3. **Reference ingestion:** run the frontend on real profiles in `/etc/apparmor.d/`
   and Docker's `docker-default`; measure coverage and log skipped lines.
4. **Semantic check:** load in `complain` mode on a throwaway host, exercise the
   workload, inspect `dmesg`/audit for unexpected `ALLOWED`/`DENIED`.
