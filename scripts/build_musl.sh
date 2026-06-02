#!/usr/bin/env bash
# Build an AFL-instrumented musl dynamic loader.
#
# musl's entire dynamic linker lives in ldso/dynlink.c, so we instrument just
# that file with native -fsanitize-coverage=trace-pc-guard (via a clang sancov
# allowlist) and link our freestanding runtime (aflrt.c) into libc.so, which IS
# the loader (ld-musl-x86_64.so.1).
#
# Unlike glibc, musl relocates itself from inside dynlink.c (__dls2), reusing
# the same do_relocs/decode_dyn/reloc_all that later process the app. So we
# cannot bring up the forkserver from the first edge (it would read libc's
# __environ through a not-yet-relocated GOT). Instead the runtime is compiled
# with -DAFLRT_MANUAL_START + hidden visibility (PC-relative map access, safe
# during early relocation) and a one-line hook in __dls3 starts the forkserver
# once __environ is set and relocations are complete.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
MUSL_VER=${MUSL_VER:-1.2.5}
SRC=${MUSL_SRC:-tools/musl-src}
RT=tools/musl-aflrt.o
ALLOW=$ROOT/scripts/musl-allowlist.txt
JOBS=${JOBS:-$(nproc)}

require() { command -v "$1" >/dev/null || { echo "missing $1; run ./setup.sh" >&2; exit 1; }; }
require clang
require curl

if [[ ! -f $SRC/ldso/dynlink.c ]]; then
    mkdir -p tools
    curl -fsSL "https://musl.libc.org/releases/musl-$MUSL_VER.tar.gz" -o tools/musl.tar.gz
    tar -C tools -xzf tools/musl.tar.gz
    mv "tools/musl-$MUSL_VER" "$SRC"
    rm -f tools/musl.tar.gz
fi

# Insert the forkserver-start hook right after `__environ = envp;` in __dls3.
if ! grep -q __afl_manual_start "$SRC/ldso/dynlink.c"; then
    python3 - "$SRC/ldso/dynlink.c" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
needle = "\t__environ = envp;\n"
hook = ("\t__environ = envp;\n"
        "\t{ extern void __afl_manual_start(void) __attribute__((__weak__));\n"
        "\t  if (__afl_manual_start) __afl_manual_start(); }\n")
assert needle in s, "could not find __environ assignment in __dls3"
open(p, "w").write(s.replace(needle, hook, 1))
PY
fi

printf 'src:*dynlink.c\nfun:*\n' > "$ALLOW"

# Freestanding runtime: hidden visibility + manual start (see header comment).
clang -O2 -fno-stack-protector -fno-builtin -ffreestanding -fPIC -fcf-protection=none \
    -fvisibility=hidden -DAFLRT_MANUAL_START -c scripts/aflrt.c -o "$RT"

if [[ ! -f $SRC/config.mak ]]; then
    ( cd "$SRC" && CC=clang \
        CFLAGS="-O2 -g -fsanitize-coverage=trace-pc-guard -fsanitize-coverage-allowlist=$ALLOW" \
        ./configure --prefix="$ROOT/tools/musl-install" )
fi

rm -f "$SRC/obj/ldso/dynlink.lo" "$SRC/lib/libc.so"
make -C "$SRC" -j"$JOBS" lib/libc.so LDFLAGS="$ROOT/$RT"

LOADER=$SRC/lib/libc.so
[[ -x $LOADER ]] || { echo "musl loader not built" >&2; exit 1; }
echo "instrumented musl loader: $LOADER"
