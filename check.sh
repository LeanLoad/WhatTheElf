#!/usr/bin/env bash
set -o pipefail
cd "$(dirname "$0")"

args=("$@")
has_color=0
for arg in "${args[@]}"; do
    case "$arg" in
        --color|--color=*) has_color=1 ;;
    esac
done

if [[ $has_color -eq 0 && -t 1 && -z "${NO_COLOR:-}" ]]; then
    args=(--color always "${args[@]}")
fi

cargo build --quiet --bin kernel-execve
cargo run --quiet --bin check -- "${args[@]}" 2>&1 | tee check.out
