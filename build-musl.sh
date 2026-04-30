#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR/ebpf-mon-ebpf"
cargo build --release
cd "$SCRIPT_DIR/ebpf-mon"
cargo rustc --release --target=x86_64-unknown-linux-musl -- -C target-feature=+crt-static -C link-self-contained=yes -lc
