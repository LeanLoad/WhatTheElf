#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

LD_SO=${LD_SO:-tools/glibc-afl-build/elf/ld.so}
OUT=${OUT:-fuzz-out/ld-verify}
AFL_FUZZ=${AFL_FUZZ:-tools/aflplusplus/afl-fuzz}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    cat <<'EOF'
Usage: ./fuzz.sh [afl-fuzz-args...]

Environment:
  LD_SO     instrumented loader target (default: tools/glibc-afl-build/elf/ld.so)
  OUT       AFL++ output directory (default: fuzz-out/ld-verify)
  AFL_FUZZ  afl-fuzz binary (default: tools/aflplusplus/afl-fuzz)
EOF
    exit 0
fi

if ! command -v "$AFL_FUZZ" >/dev/null 2>&1; then
    echo "missing program: $AFL_FUZZ; run ./setup.sh" >&2
    exit 1
fi

if [[ ! -f "$LD_SO" ]]; then
    echo "missing instrumented loader: $LD_SO" >&2
    echo "run ./scripts/setup_fuzz.sh first" >&2
    exit 1
fi

./gen.sh >/dev/null
mkdir -p "$OUT"

# The loader carries a custom freestanding coverage runtime (native sancov
# trace-pc-guard), not afl-clang-fast's signature, so AFL's static
# instrumentation check must be skipped; coverage still flows via shared memory.
export AFL_SKIP_BIN_CHECK=1

exec "$AFL_FUZZ" \
    -i fixtures \
    -o "$OUT" \
    -m none \
    -t 1000+ \
    "$@" \
    -- "$LD_SO" --verify @@
