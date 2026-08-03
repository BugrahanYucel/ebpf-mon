# Ready-to-use Berserker workload generator for driving ebpf-mon under load.
#
# Mirrors stackrox/berserker's upstream Containerfile (which their CI validates
# on fedora:43) but:
#   * pins a known-good upstream commit,
#   * strips the `cargo fmt --check` / `clippy -D warnings` / `cargo test` gates
#     that make the upstream build brittle across toolchains,
#   * bakes in our curated workload configs and a flexible entrypoint so you can
#     switch workloads without rebuilding.
#
# Build:  docker build -t ebpf-mon/berserker:latest .
# Run:    docker run -d --name berserker -e WORKLOAD=processes ebpf-mon/berserker:latest

ARG BERSERKER_REF=ec43ada75683f4be61da21ebf3f0ced36eaeb525

FROM registry.fedoraproject.org/fedora:43 AS builder
ARG BERSERKER_REF
ARG RUST_VERSION=stable

RUN dnf install -y \
      git \
      nasm \
      llvm-devel zlib-devel libxml2-devel libstdc++-static \
      clang kernel-devel libbpf-devel && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
      sh -s -- -y --default-toolchain "$RUST_VERSION" --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone https://github.com/stackrox/berserker /berserker && \
    cd /berserker && git checkout "$BERSERKER_REF"

WORKDIR /berserker
# `stub` is the tiny exec target used by the processes / script workloads.
RUN nasm -f elf64 -o stub.o stub.asm && ld -o stub stub.o
# Release build only -- intentionally no fmt/clippy/test gates.
RUN cargo build --release

FROM registry.fedoraproject.org/fedora:43
# Runtime libs for the (dynamically linkable) JIT + bpf features.
RUN dnf install -y llvm-libs libbpf && dnf clean all

COPY --from=builder /berserker/target/release/berserker /usr/local/bin/berserker
COPY --from=builder /berserker/stub /usr/local/bin/stub
COPY workloads/ /workloads/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RUST_LOG=info
ENV WORKLOAD=processes
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
