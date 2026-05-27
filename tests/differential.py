#!/usr/bin/env python3
"""
Differential test for our ELF parser.

Reads the manifest emitted by `./.lake/build/bin/emit_fixtures` and feeds
each fixture to every other ELF parser available on the system. Prints a
comparison table.

Usage:
  lake build emit_fixtures
  ./.lake/build/bin/emit_fixtures fixtures_out
  python3 tests/differential.py fixtures_out

Verdicts:
  ACCEPT  parser thinks the file is a well-formed ELF
  REJECT  parser refuses (non-zero exit, or for `file`: no "ELF" magic)
  N/A     parser tool not installed on this host

The "ours" column is OUR parser, "expect" is what was encoded in the
manifest (sanity-check that the harness matches the spec). All other
columns are independent re-implementations. Disagreements vs. ours
are flagged with `≠` — they're not bugs per se, they're spec-policy
differences worth investigating.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OURS = REPO / ".lake" / "build" / "bin" / "whattheelf"
LD_LINUX = "/lib64/ld-linux-x86-64.so.2"
LD_MUSL = "/lib/ld-musl-x86_64.so.1"


def run(argv, *, stdin=None, timeout=5):
    try:
        return subprocess.run(argv, stdin=stdin, capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


# ── Parser adapters ────────────────────────────────────────────────────
# Each returns "ACCEPT" / "REJECT" / "N/A".

def v_ours(path: Path) -> str:
    with open(path, "rb") as fh:
        r = run([str(OURS)], stdin=fh)
    if r is None:
        return "N/A"
    return "ACCEPT" if b'"ok":true' in r.stdout else "REJECT"


def _verify_ld(loader: str):
    def go(path: Path) -> str:
        if not os.path.exists(loader):
            return "N/A"
        r = run([loader, "--verify", str(path)])
        if r is None:
            return "N/A"
        # Negative return code = killed by signal. We've observed glibc's
        # `--verify` SIGSEGV on certain malformed-but-structurally-valid
        # inputs — surface as CRASH rather than collapsing into REJECT, so
        # disagreements aren't silently hidden.
        if r.returncode < 0:
            return "CRASH"
        return "ACCEPT" if r.returncode == 0 else "REJECT"
    return go


def _exec0(*argv):
    """Tool that uses exit codes properly: 0 = accept, !0 = reject."""
    def go(path: Path) -> str:
        if not shutil.which(argv[0]):
            return "N/A"
        r = run([*argv, str(path)])
        if r is None:
            return "N/A"
        if r.returncode < 0:
            return "CRASH"
        return "ACCEPT" if r.returncode == 0 else "REJECT"
    return go


def _strip_check(path: Path) -> str:
    """`strip -o /dev/null` is a destructive operation; we send the output
    to /dev/null so the input file is untouched. Strip parses every
    section header to figure out what to drop, so malformed shdrs surface
    as REJECT — a different validation path from `nm`/`readelf`."""
    if not shutil.which("strip"):
        return "N/A"
    r = run(["strip", "-o", "/dev/null", str(path)])
    if r is None:
        return "N/A"
    if r.returncode < 0:
        return "CRASH"
    return "ACCEPT" if r.returncode == 0 else "REJECT"


def _exec_stderr(*argv, error_markers=("not recognized", "Error", "not an ELF",
                                       "wrong magic", "Invalid")):
    """Tool that always exits 0 but signals errors via stderr text (e.g.
    binutils `nm`, `size`). We pattern-match stderr against `error_markers`."""
    def go(path: Path) -> str:
        if not shutil.which(argv[0]):
            return "N/A"
        r = run([*argv, str(path)])
        if r is None:
            return "N/A"
        if r.returncode < 0:
            return "CRASH"
        stderr = r.stderr.decode("utf-8", "replace")
        # Some tools also write errors to stdout (`size` is one).
        stdout = r.stdout.decode("utf-8", "replace")
        combined = stderr + "\n" + stdout
        if any(m in combined for m in error_markers):
            return "REJECT"
        return "ACCEPT" if r.returncode == 0 else "REJECT"
    return go


def v_pyelftools(path: Path) -> str:
    """pyelftools — pure-Python independent implementation. Walks the
    full file (headers, sections, symbols) so deeper malformations
    surface as exceptions, not as silent acceptance. Mirrors what most
    Python ELF analysis tooling actually sees."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
    except ImportError:
        return "N/A"
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            # Touch the headers + segments + sections + symbol tables —
            # a real consumer would.
            _ = elf.header
            for _ in elf.iter_segments():
                pass
            for sec in elf.iter_sections():
                _ = sec.name
                if hasattr(sec, "iter_symbols"):
                    for _ in sec.iter_symbols():
                        pass
        return "ACCEPT"
    except (ELFError, ValueError, AssertionError, KeyError, IndexError, struct_error()):
        return "REJECT"
    except Exception:
        # Defensive: pyelftools raises a mix of exception types depending
        # on which deserializer trips; treat unknown failures as REJECT
        # rather than letting them crash the runner.
        return "REJECT"


def struct_error():
    """Late lookup of struct.error so missing `struct` doesn't break import."""
    import struct
    return struct.error


PARSERS: dict[str, callable] = {
    "ours":     v_ours,
    "glibc":    _verify_ld(LD_LINUX),
    # `eu-readelf` (elfutils) is an entirely separate implementation from
    # `readelf` (binutils) — useful as a third C codebase data point.
    "eu-rd":    _exec0("eu-readelf", "-h"),
    "eu-rd-a":  _exec_stderr("eu-readelf", "-a"),  # deeper validation
    # `eu-elflint` is purpose-built for spec validation — every warning/
    # error is by design a deviation from gabi/glibc expectations.
    "eu-lint":  _exec0("eu-elflint", "--quiet"),
    # `eu-elfclassify --elf` returns 0 iff this is a parseable ELF (in
    # elfutils' permissive sense). Useful liveness check.
    "eu-class": _exec0("eu-elfclassify", "--elf"),
    "readelf":  _exec0("readelf", "-h"),
    "readelf-a": _exec_stderr("readelf", "-a"),    # deeper validation
    "llvm-rd":  _exec0("llvm-readelf", "-h"),
    "objdump":  _exec0("objdump", "-p"),
    "llvm-od":  _exec0("llvm-objdump", "-p"),
    "nm":       _exec_stderr("nm", "-D"),          # binutils: dynamic syms
    "strip":    _strip_check,                       # binutils: shdr walker
    "pyelf":    v_pyelftools,                      # independent Python codebase
}


def main() -> int:
    if len(sys.argv) > 1:
        fixture_dir = Path(sys.argv[1])
    else:
        fixture_dir = REPO / "fixtures_out"
    manifest = json.loads((fixture_dir / "manifest.json").read_text())

    name_w = max(len(f["name"]) for f in manifest)
    cat_w = max(len(f.get("category", "?")) for f in manifest) + 1
    col_w = max(10, max(len(c) for c in PARSERS) + 1)
    cols = list(PARSERS.keys())
    header = (f"{'fixture':<{name_w}}  {'category':<{cat_w}}  {'expect':<{col_w}}"
              + "".join(f"{c:<{col_w}}" for c in cols))
    print(header)
    print("-" * len(header))

    # Per-category bookkeeping. We only call "real" disagreements those in
    # `structural` (others-accept-our-reject is expected for policy/dynamic).
    n_agree_ours = 0
    cat_disagree: dict[str, int] = {}
    cat_total: dict[str, int] = {}

    for fixture in manifest:
        cat = fixture.get("category", "?")
        cat_total[cat] = cat_total.get(cat, 0) + 1
        path = fixture_dir / f"{fixture['name']}.elf"
        verdicts = {c: PARSERS[c](path) for c in cols}
        ours = verdicts["ours"]
        if ours == fixture["ourVerdict"]:
            n_agree_ours += 1
        annotated = []
        for c in cols:
            v = verdicts[c]
            mark = ""
            if c != "ours" and v not in ("N/A",) and v != ours:
                mark = "≠"
                if cat == "structural":
                    cat_disagree[cat] = cat_disagree.get(cat, 0) + 1
            annotated.append(f"{v + mark:<{col_w}}")
        print(f"{fixture['name']:<{name_w}}  {cat:<{cat_w}}  {fixture['ourVerdict']:<{col_w}}"
              + "".join(annotated))

    print()
    print(f"emit-vs-ours agreement: {n_agree_ours}/{len(manifest)} "
          f"({'OK' if n_agree_ours == len(manifest) else 'MISMATCH'})")
    print()
    print("Per-category fixture counts:")
    for cat in sorted(cat_total):
        print(f"  {cat:<11} {cat_total[cat]:>2}")
    print()
    structural_dis = cat_disagree.get("structural", 0)
    if structural_dis == 0:
        print("All structural fixtures: full agreement across parsers.")
    else:
        print(f"Note: {structural_dis} `≠` cell(s) in `structural` rows. These usually")
        print("mean the *other* parser is more lenient (e.g. `file` only checks magic;")
        print("`llvm-readelf` dumps malformed files with warnings instead of erroring).")
        print("Investigate only if multiple tools accept what we reject as structural.")
    print()
    print("Disagreements in `decode` / `policy` / `dynamic` rows are expected: our parser")
    print("enforces a stricter acceptance policy than general-purpose ELF tools, and the")
    print("dynamic-section walker validates invariants other tools don't check.")
    print()
    print("Disagreements on `positive` controls vs. glibc reflect that `ld.so --verify`")
    print("requires loadability (PT_INTERP, entry point, DT_HASH/GNU_HASH), not just")
    print("byte-level validity. Our minimal positive ELFs are well-formed but not loadable.")
    return 0 if n_agree_ours == len(manifest) else 1


if __name__ == "__main__":
    sys.exit(main())
