#!/usr/bin/env python3
"""
Random byte-mutation fuzzer for the `whattheelf` parser.

Starts from a real, known-good ELF (`/bin/true`) and repeatedly applies
small byte-level mutations, feeding each variant through our parser.
Goals:

  * Confirm the parser never crashes (Lean is pure; a crash here would
    indicate a foreign-function or runtime bug — none expected).
  * Catch infinite loops (each parse is bounded to 5 seconds).
  * Catalog the distribution of error categories — a wide-and-flat
    histogram is healthy; a histogram dominated by one error suggests
    weak validation upstream of it.

Usage:
  python3 tests/fuzz.py [N=1000] [seed=42]

This isn't a coverage-guided fuzzer (no AFL/libfuzzer feedback) — just
uniform random mutations on a real seed. For deeper coverage, increase N
or run multiple shards with different seeds.
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OURS = REPO / ".lake" / "build" / "bin" / "whattheelf"
SEED_PATH = Path("/bin/true")


def mutate(data: bytes, rng: random.Random, n_ops: int) -> bytes:
    """Apply `n_ops` random byte-level mutations. Each mutation is one of:

      - flip   xor a random byte with a random mask
      - set    overwrite with a random byte
      - zero   overwrite with 0
      - splat  overwrite with 0xFF (often a "stress" value)

    Targets are uniform over the whole file. A slightly smarter mutator
    would weight the ehdr (0..64) and phdr table (64..64+N*56) more
    heavily; for now uniform is fine — most mutations there will hit
    fields we validate.
    """
    arr = bytearray(data)
    for _ in range(n_ops):
        op = rng.choice(("flip", "set", "zero", "splat"))
        i = rng.randrange(len(arr))
        if op == "flip":
            arr[i] ^= rng.randrange(1, 256)
        elif op == "set":
            arr[i] = rng.randrange(256)
        elif op == "zero":
            arr[i] = 0
        else:
            arr[i] = 0xFF
    return bytes(arr)


def categorize(err: str) -> str:
    """Bucket an error message by the first "noun-phrase" so similar errors
    aggregate. We split on `:` and take the first segment, capped at 50
    chars to keep the histogram readable."""
    head = err.split(":", 1)[0].strip()
    return head[:60] if head else "<empty>"


def run_one(data: bytes, timeout: float = 5.0) -> tuple[int, bytes, bytes]:
    p = subprocess.run([str(OURS)], input=data, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("n", nargs="?", type=int, default=1000)
    ap.add_argument("seed", nargs="?", type=int, default=42)
    ap.add_argument("--max-mutations", type=int, default=5,
                    help="upper bound on mutations per iteration")
    ap.add_argument("--save-crashes", type=Path, default=None,
                    help="directory to dump crashing/hanging inputs into")
    args = ap.parse_args()

    if not OURS.exists():
        print(f"ERROR: binary not found at {OURS}\nRun `lake build` first.",
              file=sys.stderr)
        return 2
    if not SEED_PATH.exists():
        print(f"ERROR: seed {SEED_PATH} not found", file=sys.stderr)
        return 2

    seed_bytes = SEED_PATH.read_bytes()
    rng = random.Random(args.seed)
    if args.save_crashes:
        args.save_crashes.mkdir(parents=True, exist_ok=True)

    print(f"seed file = {SEED_PATH} ({len(seed_bytes)} bytes)")
    print(f"iterations = {args.n}  rng seed = {args.seed}  max mutations/iter = {args.max_mutations}")
    print()

    accepts = 0
    crashes: list[tuple[int, int]] = []
    timeouts: list[int] = []
    invalid_json: list[int] = []
    errors: Counter[str] = Counter()
    t0 = time.time()

    for i in range(args.n):
        k = rng.randint(1, args.max_mutations)
        variant = mutate(seed_bytes, rng, k)
        try:
            rc, stdout, stderr = run_one(variant)
        except subprocess.TimeoutExpired:
            timeouts.append(i)
            if args.save_crashes:
                (args.save_crashes / f"timeout_{i:05d}.elf").write_bytes(variant)
            continue
        if rc < 0:
            crashes.append((i, rc))
            if args.save_crashes:
                (args.save_crashes / f"crash_{i:05d}_sig{-rc}.elf").write_bytes(variant)
            continue
        try:
            d = json.loads(stdout)
        except json.JSONDecodeError:
            invalid_json.append(i)
            if args.save_crashes:
                (args.save_crashes / f"bad_json_{i:05d}.elf").write_bytes(variant)
            continue
        if d.get("ok"):
            accepts += 1
        else:
            errors[categorize(d.get("error", ""))] += 1

    elapsed = time.time() - t0
    print(f"completed in {elapsed:.1f}s  ({args.n / elapsed:.0f} iter/s)")
    print(f"  accepts:       {accepts}")
    print(f"  crashes:       {len(crashes)}{' '.join('iter='+str(i)+'/sig='+str(-s) for i,s in crashes[:3])}")
    print(f"  timeouts:      {len(timeouts)}")
    print(f"  invalid_json:  {len(invalid_json)}")
    print(f"  rejected:      {sum(errors.values())}")
    print()
    print("Error-category histogram (top 20):")
    width = max((len(k) for k in errors), default=0)
    for cat, count in errors.most_common(20):
        bar = "█" * min(40, count * 40 // max(errors.values()))
        print(f"  {count:6d}  {cat:<{width}}  {bar}")

    # Fail the run if any crashes / timeouts / unparseable outputs.
    if crashes or timeouts or invalid_json:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
