#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD

GLIBC_URL=${GLIBC_URL:-https://sourceware.org/git/glibc.git}
GLIBC_COMMIT=${GLIBC_COMMIT:-79dbb41f159a4defe75f59a8f491d136236d1f7a}
GLIBC_SRC=${GLIBC_SRC:-tools/glibc-src}
BUILD_DIR=${BUILD_DIR:-tools/glibc-afl-build}
PREFIX=${PREFIX:-tools/glibc-afl-install}
AFLPP_URL=${AFLPP_URL:-https://github.com/AFLplusplus/AFLplusplus.git}
AFLPP_COMMIT=${AFLPP_COMMIT:-a918a9ab647d86824d289f36014b9ca99f077984}
AFLPP_SRC=${AFLPP_SRC:-tools/aflplusplus}
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config-18}
HOST_CC=${HOST_CC:-clang}
HOST_CXX=${HOST_CXX:-clang++}
JOBS=${JOBS:-$(nproc)}

if [[ $# -ne 0 ]]; then
    echo "usage: ./scripts/setup_fuzz.sh" >&2
    echo "override defaults with GLIBC_SRC, BUILD_DIR, AFLPP_SRC, LLVM_CONFIG, HOST_CC, HOST_CXX, or JOBS" >&2
    exit 2
fi

abs_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$ROOT" "$1" ;;
    esac
}

require_program() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing program: $1; run ./setup.sh" >&2
        exit 1
    fi
}

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

require_program git
require_program make
require_program "$LLVM_CONFIG"
require_program "$HOST_CC"
require_program "$HOST_CXX"

GLIBC_SRC_ABS=$(abs_path "$GLIBC_SRC")
BUILD_DIR_ABS=$(abs_path "$BUILD_DIR")
PREFIX_ABS=$(abs_path "$PREFIX")
AFLPP_SRC_ABS=$(abs_path "$AFLPP_SRC")

if [[ ! -d "$AFLPP_SRC_ABS/.git" ]]; then
    if [[ -e "$AFLPP_SRC_ABS" ]] && [[ -n "$(find "$AFLPP_SRC_ABS" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        echo "$AFLPP_SRC exists but does not look like an AFL++ checkout" >&2
        exit 1
    fi

    run mkdir -p "$(dirname "$AFLPP_SRC_ABS")"
    run git clone --filter=blob:none --no-checkout "$AFLPP_URL" "$AFLPP_SRC_ABS"
fi

if [[ ! -f "$AFLPP_SRC_ABS/afl-fuzz" || ! -f "$AFLPP_SRC_ABS/SanitizerCoveragePCGUARD.so" ]]; then
    if ! run git -C "$AFLPP_SRC_ABS" fetch --filter=blob:none --depth 1 origin "$AFLPP_COMMIT"; then
        run git -C "$AFLPP_SRC_ABS" fetch --filter=blob:none origin "$AFLPP_COMMIT"
    fi
    run git -C "$AFLPP_SRC_ABS" checkout --detach "$AFLPP_COMMIT"
    run make -C "$AFLPP_SRC_ABS" "-j$JOBS" all \
        LLVM_CONFIG="$LLVM_CONFIG" \
        CC="$HOST_CC" \
        CXX="$HOST_CXX" \
        NO_NYX=1
fi

CC="$AFLPP_SRC_ABS/afl-clang-fast"
CXX="$AFLPP_SRC_ABS/afl-clang-fast++"
AFL_CC="$HOST_CC"
AFL_CXX="$HOST_CXX"

if [[ ! -f "$GLIBC_SRC_ABS/configure" ]]; then
    if [[ -e "$GLIBC_SRC_ABS" && ! -d "$GLIBC_SRC_ABS/.git" ]] && [[ -n "$(find "$GLIBC_SRC_ABS" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        echo "$GLIBC_SRC exists but does not look like a full glibc checkout" >&2
        exit 1
    fi

    if [[ ! -d "$GLIBC_SRC_ABS/.git" ]]; then
        run mkdir -p "$(dirname "$GLIBC_SRC_ABS")"
        run git clone --filter=blob:none --no-checkout "$GLIBC_URL" "$GLIBC_SRC_ABS"
    fi
    if ! run git -C "$GLIBC_SRC_ABS" fetch --filter=blob:none --depth 1 origin "$GLIBC_COMMIT"; then
        run git -C "$GLIBC_SRC_ABS" fetch --filter=blob:none origin "$GLIBC_COMMIT"
    fi
    run git -C "$GLIBC_SRC_ABS" checkout --detach "$GLIBC_COMMIT"
fi

run mkdir -p "$BUILD_DIR_ABS"

if [[ ! -f "$BUILD_DIR_ABS/config.make" ]]; then
    (
        cd "$BUILD_DIR_ABS"
        run env \
            AFL_PATH="$AFLPP_SRC_ABS" \
            AFL_NOOPT=1 \
            CC="$CC" \
            CXX="$CXX" \
            AFL_CC="$AFL_CC" \
            AFL_CXX="$AFL_CXX" \
            CFLAGS="-O2 -g -fno-omit-frame-pointer" \
            CXXFLAGS="-O2 -g -fno-omit-frame-pointer" \
            "$GLIBC_SRC_ABS/configure" \
            "--prefix=$PREFIX_ABS" \
            --disable-werror \
            --enable-stack-protector=no
    )
fi

# Build the loader and its dependencies UNINSTRUMENTED first, capturing the
# verbose compile commands. AFL's PCGUARD pass inlines the coverage map update
# and relies on a module constructor to number guards / attach the map, but the
# loader never runs its own .init_array in the modes we fuzz, so that never
# fires. We therefore keep the base build clean and re-instrument the loader in
# the next step with native trace-pc-guard callbacks + our freestanding runtime.
#
# An allowlist that matches nothing keeps afl-clang-fast from instrumenting the
# base build (so libc.so/ld.so link without an AFL runtime).
NULL_ALLOWLIST="$BUILD_DIR_ABS/afl-nothing.allowlist"
printf 'fun:__afl_never_match__\n' > "$NULL_ALLOWLIST"
BUILD_LOG="$BUILD_DIR_ABS/glibc-build.log"

run env \
    AFL_PATH="$AFLPP_SRC_ABS" \
    AFL_CC="$AFL_CC" \
    AFL_CXX="$AFL_CXX" \
    AFL_LLVM_ALLOWLIST="$NULL_ALLOWLIST" \
    make -C "$BUILD_DIR_ABS" "-j$JOBS" 2>&1 | tee "$BUILD_LOG" | tail -3 || true

# Re-instrument the loader (everything but rtld.os) with trace-pc-guard and link
# the runtime, then build the instrumented musl loader.
run env LOG="$BUILD_LOG" "$ROOT/scripts/instrument_loader.sh"

if [[ ! -f "$BUILD_DIR_ABS/elf/ld.so" ]]; then
    echo "expected built loader at $BUILD_DIR/elf/ld.so" >&2
    exit 1
fi
echo "instrumented glibc loader: $BUILD_DIR/elf/ld.so"

run "$ROOT/scripts/build_musl.sh" || echo "warning: musl loader build failed (glibc fuzzing still usable)"
