#!/usr/bin/env bash
# Re-instrument the glibc dynamic loader for AFL fuzzing.
#
# ld.so relocates itself before it can touch the coverage map, so the only unit
# that must stay uninstrumented is rtld.c (its _dl_start does the self-reloc).
# Everything else in the loader runs after self-relocation and is safe to
# instrument, which is what gives us coverage of the parsing / validation /
# symbol-resolution / relocation / TLS code.
#
# We compile each loader object with plain clang + native
# -fsanitize-coverage=trace-pc-guard (per-edge callbacks). AFL's own PCGUARD
# pass inlines the map update and relies on a module constructor to number the
# guards and attach the map, but the loader never runs its own .init_array in
# the modes we fuzz, so the constructor never fires. The callback form lets our
# freestanding runtime (aflrt.c) number guards and start the forkserver lazily
# on the first edge instead.
set -euo pipefail

ROOT=/users/szhong/LeanLoad/WhatTheElf
BUILD=$ROOT/tools/glibc-afl-build
SRC=$ROOT/tools/glibc-src
LOG=${LOG:-/tmp/glibc_build.log}
AFLCC=$ROOT/tools/aflplusplus/afl-clang-fast
RT=$BUILD/elf/aflrt.o

# Objects that run during or before self-relocation; leave them uninstrumented.
EXCLUDE_RE='^(rtld)\.os$'

cd "$SRC/elf"

# Compile the freestanding runtime (no markers).
clang -O2 -fno-stack-protector -fno-builtin -ffreestanding -fPIC -fcf-protection=none \
  -c "$ROOT/scripts/aflrt.c" -o "$RT"

objs=$(grep 'DMODULE_NAME=rtld' "$LOG" \
  | grep -oE "/elf/[a-zA-Z0-9_-]+\.os" | sort -u | sed 's#/elf/##')

instrument_one() {
  local obj=$1
  local cmd
  # last compile command that produced this object
  cmd=$(grep "DMODULE_NAME=rtld" "$LOG" | grep -- "-o $BUILD/elf/$obj " | tail -1)
  [ -z "$cmd" ] && { echo "no cmd: $obj"; return 0; }
  # only C sources carry edges; .S assembly is skipped
  case "$cmd" in
    "$AFLCC "*.c\ *) : ;;
    *) echo "skip non-C: $obj"; return 0 ;;
  esac
  local newcmd=${cmd/$AFLCC/clang -fsanitize-coverage=trace-pc-guard}
  eval "$newcmd"
  echo "instrumented: $obj"
}
export -f instrument_one
export LOG BUILD AFLCC

count=0
for obj in $objs; do
  if [[ $obj =~ $EXCLUDE_RE ]]; then echo "excluded: $obj"; continue; fi
  instrument_one "$obj" &
  count=$((count+1))
  # cap parallelism
  if (( count % 16 == 0 )); then wait; fi
done
wait
echo "recompiled $count loader objects with trace-pc-guard"

# Relink ld.so with the runtime, rebuilding dl-allobjs.os -> librtld.os -> ld.so.
cd "$BUILD"
rm -f elf/ld.so elf/ld.so.new elf/librtld.os elf/dl-allobjs.os
AFL_PATH=$ROOT/tools/aflplusplus AFL_CC=clang AFL_CXX=clang++ \
  make -r -j"$(nproc)" elf/subdir_lib \
  LDFLAGS-rtld="-Wl,-z,relro -Wl,-z,nomark-plt $RT" 2>&1 | tail -4

echo "=== ld.so undefined-symbol check ==="
readelf -s elf/ld.so | gawk '($7 ~ /^UND/ && $1!="0:" && $4!="REGISTER"){print $8}' | sort -u
ls -la elf/ld.so
