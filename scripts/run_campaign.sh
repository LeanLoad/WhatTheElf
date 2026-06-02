#!/usr/bin/env bash
# Launch a multi-core AFL++ campaign against the instrumented glibc loader.
#
# Two complementary harnesses share one corpus via AFL's -M/-S sync:
#   * `ld.so --verify @@`              - ELF header / phdr parsing & validation
#   * `LD_TRACE_PRELINKING=1 ld.so @@` - full map + symbol resolution +
#                                        relocation (without executing the entry)
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
PRELINK_JOBS=${PRELINK_JOBS:-2}
MUSL_JOBS=${MUSL_JOBS:-2}

export AFL_PATH=$ROOT/tools/aflplusplus
export AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_NO_UI=1 AFL_SKIP_BIN_CHECK=1 AFL_AUTORESUME=1

[ -x "$LD" ] || { echo "missing loader: $LD (run setup_fuzz.sh)" >&2; exit 1; }
[ -x "$AFL" ] || { echo "missing afl-fuzz: $AFL (run setup_fuzz.sh)" >&2; exit 1; }
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
for i in $(seq 1 "$PRELINK_JOBS"); do
  setsid nohup env LD_TRACE_PRELINKING=1 "$AFL" -i "$SEEDS" -o "$OUT" -S prelink$i -m none -t 1000+ \
    -- "$LD" @@ >"logs/afl_prelink$i.log" 2>&1 &
  echo "  prelink$i (pid $!) [-S prelink$i]"
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
echo "launched $n fuzzers"
