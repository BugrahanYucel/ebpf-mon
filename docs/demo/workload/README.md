# Workload generator

A self-contained container that continuously produces a **rich, non-repeating**
stream of activity so `ebpf-mon` captures every field it knows about. Use it to
demo monitoring, profiling, and the compiler pipeline against realistic data.

## What it exercises

| Module | Activity | Fields populated |
|--------|----------|------------------|
| **Filesystem** | random-named writes, reads, copies (fresh inodes) | `path`, `inode`, `r_w`, `owner_uid`, `freq` |
| | symlinks + reads through them | `is_symlink`, `sym_path` |
| | `/etc/shadow`, `/etc/gshadow` reads | `is_sensitive` |
| | `/proc/self/{cmdline,environ,maps,status,...}` | `path_pattern` (special classifications) |
| | reads of `/proc/1/...` and random neighbours | `is_cross_process` |
| **Network** | HTTP/HTTPS to a rotating host list (curl/wget) | `dst_ip`, `dst_port`, `protocol=TCP`, `direction` |
| | DNS lookups with rotating names | `protocol=UDP`, port 53 |
| | raw TCP/UDP to rotating IPs + random ports (`netgen.py`) | varied `dst_ip`/`dst_port` |
| **Process** | rotating real binaries (`ls`, `grep`, `awk`, `find`, ...) | `exec_path`, `inode`, `comm`, `capabilities`, `is_root` |
| | a freshly generated script each round, exec'd with a rich argv | `argv`, `argc`, `filename`, `ps_type=execve` |

### Why it avoids deduplication

The monitor collapses identical events. This generator deliberately defeats
that so events keep flowing:

- **fs** dedup key is `path + inode + r_w` → every round uses a unique
  `file_<token>.dat` (and `cp` creates brand-new inodes).
- **net** dedup key is `src_ip + dst_ip + dst_port` → hosts rotate and
  `netgen.py` fires at random high ports.
- **process** dedup key is `inode + ps_type + cgroup_id` → a fresh script
  (new inode) is generated and exec'd each round, alongside a rotating set of
  system binaries.

## Run it

```bash
# build + run detached, then print the monitor-attach command
./run.sh

# faster stream / no outbound network
SLEEP_SECONDS=1 ./run.sh
EXTERNAL_NET=0 ./run.sh
```

Then, from the repo root, attach the monitor to the container it prints:

```bash
./run-ebpf.sh --container <container-id>
```

Watch the raw activity with `docker logs -f ebpf-mon-workload`.

## Knobs

| Env | Default | Meaning |
|-----|---------|---------|
| `SLEEP_SECONDS` | `2` | base delay between rounds (jittered up to 2x) |
| `EXTERNAL_NET` | `1` | set `0` to skip all outbound network (air-gapped) |

## Files

- `Dockerfile` — `debian:bookworm-slim` + the tools above
- `workload.sh` — the main event-generation loop
- `netgen.py` — raw TCP/UDP socket generator
- `run.sh` — build + run helper
