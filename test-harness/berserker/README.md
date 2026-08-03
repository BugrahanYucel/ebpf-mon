# Dockerized Berserker (load generator for ebpf-mon)

A ready-to-use, containerized build of [stackrox/berserker](https://github.com/stackrox/berserker)
— a workload generator originally built to benchmark security *collectors*. We
use it to drive `ebpf-mon`'s monitoring/enforcement under realistic **volume**
and to produce process / file / network events on demand.

Upstream ships a `Containerfile`, but it isn't turn-key: the build runs
`cargo fmt --check`, `clippy -D warnings`, and `cargo test` (fragile across
toolchains), it only runs the default workload, and there's no compose/runner.
This wrapper fixes all three.

## What it's good for (and not)

- **Good for:** overhead/latency benchmarking under load — process spawn storms,
  many listening ports, high-rate `open(2)`, outbound connection floods. Pair it
  with `../bpf_bench.sh` and `../ftrace_bench.sh`.
- **Not for:** exercising the optimization *passes*. Berserker generates
  repetitive/synthetic events (e.g. the same `stub` binary, one path), so after
  dedup there's little rule *diversity* and nothing that trips prefix
  generalization. Use the dedicated showcase workload for that.

## Quick start

```bash
cd test-harness/berserker

# Easiest: build + run a named container
./run.sh processes          # process spawn storm  (no privileges)
./run.sh endpoints          # many listening ports (no privileges)
./run.sh syscalls-open      # high-rate open(2)    (no privileges)
./run.sh network            # outbound connects    (NET_ADMIN + /dev/net/tun)
./run.sh --script files.ber # files + exec via the .ber DSL (experimental)

# Then, from the repo root, point ebpf-mon at the container:
sudo ./ebpf-mon --container berserker-processes
```

Or with compose:

```bash
docker compose up --build                    # processes (default)
WORKLOAD=endpoints docker compose up --build  # any TOML workload
docker compose --profile privileged up --build berserker-network
```

## Workloads

| Name (`WORKLOAD=`) | Type | Privileges | ebpf-mon path exercised |
|---|---|---|---|
| `processes` | fork + exec `stub` | none | process exec/fork monitoring |
| `endpoints` | open N listening ports (Zipf) | none | network listen |
| `syscalls-open` | high-rate `open(2)` | none | filesystem vfs open |
| `network` | outbound client connects (TUN) | `NET_ADMIN`, `/dev/net/tun` | `security_socket_connect` |
| `files.ber` (`SCRIPT=`) | files + exec via DSL | none | vfs open + exec (experimental) |

Tune any field without rebuilding via env vars, e.g.
`-e BERSERKER__WORKLOAD__ARRIVAL_RATE=200`.

## Notes

- The image pins upstream berserker at commit `ec43ada` and builds on
  `fedora:43` (matching upstream CI). The first build pulls Fedora and compiles
  berserker + LLVM bindings, so it takes a few minutes; subsequent runs are
  instant.
- If the LLVM version on the base image ever drifts from what `llvm-sys`
  expects and the build fails, override the base or the pinned ref via the
  `BERSERKER_REF` / `RUST_VERSION` build args.
- Config precedence inside the container: `/etc/berserker/workload.toml`
  (unused here) → `-c /workloads/<name>.toml` → `BERSERKER__*` env vars.
