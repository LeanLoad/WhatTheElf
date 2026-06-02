#!/usr/bin/env bash
# Launch a multi-core AFL++ campaign against the instrumented glibc loader.
#
# Harnesses share one corpus via AFL's -M/-S sync. They must not run the loaded
# program's entry or constructors, or we would be fuzzing the (garbage) program
# rather than the loader.
#   * glibc `ld.so --verify @@`                  - ELF header / phdr parse + map
#   * glibc `ld.so --preload exitfirst.so @@`    - full map + dependency / symbol
#                                                  resolution + relocation; the
#                                                  preloaded exitfirst.so's
#                                                  constructor _exit()s before the
#                                                  target's constructors / main run
#   * musl  `ld-musl --list @@`                  - map + relocation (rejects IFUNC;
#                                                  does not run the program)
# Two things NOT used: `LD_TRACE_PRELINKING=1` (it actually executes the target —
# IFUNC resolvers, constructors, and main all run) and the env vars
# `LD_TRACE_LOADED_OBJECTS=1` / `LD_PRELOAD=...` (set in the environment they also
# affect afl-fuzz itself). `--preload` is a loader *argument*, so it scopes to the
# target only. IFUNC resolvers still run during relocation; that is inherent to
# exercising relocation and is acceptable for fuzzing.
#
# The loader carries our freestanding runtime (aflrt.c), so AFL talks to a real
# forkserver and reads coverage from shared memory; AFL_SKIP_BIN_CHECK is
# required because the instrumentation is native sancov rather than afl-clang-fast.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
LD=${LD:-$ROOT/tools/glibc-afl-build/elf/ld.so}
MUSL_LD=${MUSL_LD:-$ROOT/tools/musl-src/lib/libc.so}
AFL=$ROOT/tools/aflplusplus/afl-fuzz
OUT=${OUT:-$ROOT/fuzz-out/ld}
MUSL_OUT=${MUSL_OUT:-$ROOT/fuzz-out/musl}
SEEDS=${SEEDS:-$ROOT/fixtures}
VERIFY_JOBS=${VERIFY_JOBS:-2}
RELOC_JOBS=${RELOC_JOBS:-2}
MUSL_JOBS=${MUSL_JOBS:-2}

export AFL_PATH=$ROOT/tools/aflplusplus
export AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_NO_UI=1 AFL_SKIP_BIN_CHECK=1 AFL_AUTORESUME=1

[ -x "$LD" ] || { echo "missing loader: $LD (run setup_fuzz.sh)" >&2; exit 1; }
[ -x "$AFL" ] || { echo "missing afl-fuzz: $AFL (run setup_fuzz.sh)" >&2; exit 1; }

# Build the preload exit-lib if needed (constructor _exit()s before the target's
# own constructors/main run; passed as `ld.so --preload` so it never touches the
# fuzzer's own environment). Lets the reloc harness relocate the input fully
# without executing it.
EXITLIB=$ROOT/tools/exitfirst.so
[ -f "$EXITLIB" ] || gcc -shared -fPIC -nostdlib -o "$EXITLIB" "$ROOT/scripts/exitfirst.c"

./gen.sh >/dev/null
mkdir -p "$OUT" logs

echo "launching campaign in $OUT"
first=1
n=0
for i in $(seq 1 "$VERIFY_JOBS"); do
  if [ $first = 1 ]; then flag="-M main"; first=0; else flag="-S verify$i"; fi
  setsid nohup "$AFL" -i "$SEEDS" -o "$OUT" $flag -m none -t 1000+ \
    -- "$LD" --verify @@ >"logs/afl_verify$i.log" 2>&1 &
  echo "  verify$i (pid $!) [$flag]"
  n=$((n+1))
done
for i in $(seq 1 "$RELOC_JOBS"); do
  setsid nohup "$AFL" -i "$SEEDS" -o "$OUT" -S reloc$i -m none -t 1000+ \
    -- "$LD" --preload "$EXITLIB" @@ >"logs/afl_reloc$i.log" 2>&1 &
  echo "  reloc$i (pid $!) [-S reloc$i]"
  n=$((n+1))
done

# musl loader: `ld-musl --list @@` maps + resolves + relocates without executing.
if [ -x "$MUSL_LD" ]; then
  mkdir -p "$MUSL_OUT"
  for i in $(seq 1 "$MUSL_JOBS"); do
    if [ "$i" = 1 ]; then flag="-M musl_main"; else flag="-S musl$i"; fi
    setsid nohup "$AFL" -i "$SEEDS" -o "$MUSL_OUT" $flag -m none -t 1000+ \
      -- "$MUSL_LD" --list @@ >"logs/afl_musl$i.log" 2>&1 &
    echo "  musl$i (pid $!) [$flag]"
    n=$((n+1))
  done
else
  echo "  (musl loader $MUSL_LD not built; skipping - run scripts/build_musl.sh)"
fi

# llvm-objdump: binary-only (FRIDA) fuzzing of the installed tool — no LLVM
# rebuild. Seeds are valid object files (+ a few small malformed ones), kept
# separate because objdump wants loadable inputs.
OBJDUMP=${OBJDUMP:-$(command -v llvm-objdump || true)}
OBJDUMP_JOBS=${OBJDUMP_JOBS:-1}
OBJDUMP_SEEDS=${OBJDUMP_SEEDS:-$ROOT/fuzz-out/objdump-seeds}
if [ -f "$AFL_PATH/afl-frida-trace.so" ] && [ -n "$OBJDUMP" ] && [ -d "$OBJDUMP_SEEDS" ]; then
  for i in $(seq 1 "$OBJDUMP_JOBS"); do
    if [ "$i" = 1 ]; then flag="-M odump"; else flag="-S odump$i"; fi
    setsid nohup "$AFL" -O -i "$OBJDUMP_SEEDS" -o "$ROOT/fuzz-out/objdump" $flag -m none -t 3000+ \
      -- "$OBJDUMP" -p @@ >"logs/afl_objdump$i.log" 2>&1 &
    echo "  objdump$i (pid $!) [$flag, FRIDA]"
    n=$((n+1))
  done
else
  echo "  (FRIDA mode or llvm-objdump unavailable; skipping objdump - build tools/aflplusplus/frida_mode)"
fi
echo "launched $n fuzzers"
