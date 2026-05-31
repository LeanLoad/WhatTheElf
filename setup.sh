#!/bin/sh
set -eu

cd "$(dirname "$0")"

sudo apt-get update
sudo apt-get install -y \
    curl \
    python3 \
    qemu-user \
    musl \
    musl-tools \
    binutils \
    llvm \
    elfutils \
    file \
    pax-utils \
    patchelf

if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        sh -s -- -y --profile minimal
fi

. "$HOME/.cargo/env"
rustup default stable
cargo build --bin kernel-execve

mkdir -p tools/bin
cargo build \
    --manifest-path ../third_party/impl-lib/gimli-object/Cargo.toml \
    --target-dir tools/object-target \
    -p object-examples \
    --features 'read names' \
    --bin readobj
cp tools/object-target/debug/readobj tools/bin/object-readobj
