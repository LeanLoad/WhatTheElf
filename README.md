# WhatTheElf

Malformed ELF generator and crash checker.

The original Lean parser/spec moved to `ELFine` as `ELFine.WhatTheElf`. This
repo now focuses on producing malformed ELF files and running them through
external loaders/tools to see whether they accept, reject, hang, or crash.

## Usage

```sh
./setup.sh
./gen.sh
./check.sh
./check.sh qemu-x86_64
./check.sh llvm-readelf eu-readelf ld-glibc
./scripts/setup_fuzz.sh
./fuzz.sh
```

`gen` builds the Rust-defined cases from `src/cases/` into ignored local ELF
files under `fixtures/`.

Case metadata lives beside each case in `src/cases/`. Invariant tags are defined
by the `Tag` enum in `src/case.rs`. The low-level ELF writer lives in
`src/elf.rs`; it intentionally permits inconsistent headers, counts, offsets,
and links.

`setup.sh` installs the packaged backend tools on Ubuntu, including glibc,
musl, QEMU, binutils, LLVM, elfutils, pax-utils, and patchelf. It also installs
Rust through `rustup` and builds the vendored `object` crate `readobj` frontend
into `tools/bin/object-readobj`. The `kernel-execve` backend directly exercises
Linux `execve(2)` through a small Rust helper.

`check` runs every built-in backend by default, or accepts one or more backend
names. Built-in backend definitions are grouped by family under `src/backends/`,
with shared runner machinery in `src/backend.rs`. Each backend is one program,
not one flag combination; byte scanners like `strings` are intentionally not
included as structural ELF backends. Fixture runs for a backend are executed in
parallel, but reported in stable fixture order. Full stdout/stderr for every
backend/case run is written under ignored `results/`, with a tab-separated
`results/summary.tsv` and one JSON record per backend/case pair; terminal output
is only a compact summary and is also saved to ignored `check.out`. `check.sh`
preserves color through `tee` when writing to a terminal unless `NO_COLOR` or an
explicit `--color` option is set. Use `--list` to show built-ins. For ad-hoc
implementations, pass `name=command`. If a command contains `{}`, the fixture
path is substituted there. Otherwise the fixture path is appended.

```sh
./check.sh --list
./check.sh "qemu-alt=qemu-x86_64 {}"
```

## Fuzzing the dynamic loaders

AFL++ fuzzes instrumented builds of the **glibc** and **musl** dynamic loaders,
using the WhatTheElf fixtures as the seed corpus.

```sh
./scripts/setup_fuzz.sh     # build AFL++, instrumented glibc ld.so, instrumented musl loader
./fuzz.sh                   # single glibc `ld.so --verify` instance
./scripts/run_campaign.sh   # multi-core campaign: glibc verify + prelink + musl
```

### Instrumentation approach

A dynamic loader cannot be instrumented the usual way: it relocates *itself*
before it can touch a coverage map, so AFL's inlined PCGUARD (which also needs a
module constructor to number guards and attach the map — the loader never runs
its own `.init_array` in these modes) crashes during bootstrap. Instead:

* The loader's ELF-handling code is compiled with **native
  `-fsanitize-coverage=trace-pc-guard`** (per-edge callbacks).
* A tiny freestanding runtime, `scripts/aflrt.c`, is linked into the loader. It
  defines the sancov hooks using only raw syscalls (plus libc-internal
  `__environ`), numbers guards lazily, maps AFL's shared coverage region, and
  drives the old-style forkserver. No external libc dependency, so it survives
  inside a `-nostdlib` loader.
* Bootstrap/self-relocation code is left uninstrumented: for glibc only
  `rtld.os` is excluded (everything after self-reloc — parsing, validation,
  symbol resolution, relocation, TLS — is fair game, see
  `scripts/instrument_loader.sh`); for musl the whole loader is one file
  (`ldso/dynlink.c`), instrumented via a clang sancov allowlist, with the
  forkserver started from a one-line hook in `__dls3` once relocation is done
  (`scripts/build_musl.sh`).

Because the runtime is custom (not afl-clang-fast's signature), the fuzz scripts
set `AFL_SKIP_BIN_CHECK=1`; coverage still flows through shared memory.

### Harnesses

The harnesses must not run the loaded program's entry or constructors, or we
would be fuzzing the garbage program rather than the loader.

* glibc `ld.so --verify @@` — ELF header / program-header parsing + mapping.
* glibc `ld.so --preload scripts/exitfirst.so @@` — full map + dependency /
  symbol resolution + relocation. The preloaded `exitfirst.so` (a freestanding
  lib whose constructor `_exit()`s) stops execution after relocation but before
  the target's own constructors / `main`.
* musl `ld-musl-x86_64.so.1 --list @@` — map + relocation; rejects IFUNC and
  does not run the program.

Two things are deliberately **avoided**: `LD_TRACE_PRELINKING=1` (despite the
name it executes the target — IFUNC resolvers, constructors, and `main` all
run), and the `LD_TRACE_LOADED_OBJECTS=1` / `LD_PRELOAD=` *environment* variables
(set in the environment they also hit `afl-fuzz` itself, which then just
`ldd`-lists and exits). `--preload` is a loader argument, so it scopes to the
target only. IFUNC resolvers still run during relocation — inherent to
exercising it, and acceptable for fuzzing.

### Binary-only: llvm-objdump

`llvm-objdump` is fuzzed without rebuilding LLVM, using AFL++'s **FRIDA mode**
(`afl-fuzz -O`) on the installed binary: `llvm-objdump -p @@`. Seeds are valid
object files (plus a few small malformed ones), kept separate from the loader
corpus because objdump wants loadable inputs. `run_campaign.sh` adds this job
when `frida_mode` is built (`setup_fuzz.sh` builds it).

## Current fixtures

See `src/cases/` for the case list, summaries, and invariant tags.

The structural cases (`src/cases/`) are tiny synthetic malformations, each
tagged with the invariant it violates. Fuzzer-found crashes are modelled
separately as [`Crash`](src/crash.rs) (`src/crashes/`, registered in
`crashes::ALL`): a `Crash` records the **loader**, **signal**, **fault site**,
whether it is a structured reproducer or a kept-raw artifact (`repro`), and a
long-form `details` analysis — all as typed data, so it can be rendered.

* `src/crashes/glibc.rs` — glibc `ld.so --verify`. Understood mechanisms are
  *structured reproducers* (`LOAD_MEMSZ_PAST_EOF` — SIGBUS zero-filling `.bss`
  past EOF in `_dl_map_segments`; `LOAD_WILD_VADDR_PHDR` — fault in the post-map
  program-header rescan); ones that depend on the loader walking into garbage are
  kept raw with the path in `details` (`DYN_LSONAME_OOB`, `RTLD_STARTUP_STRCMP`,
  `WILD_VADDR_ASLR`).
* `src/crashes/musl.rs` — 11 musl `ld-musl --list` crashes, one per distinct
  `dynlink.c` fault site (segment mapping, `do_relocs`/`do_relr_relocs`/
  `reloc_all`, symbol lookup, `load_direct_deps`, `__dls3`, `__copy_tls`).

Both `cases::ALL` and `crashes::ALL` flow through `gen` → `fixtures/` → `check`.
All crash inputs reproduce on the stock system loaders; raw bytes live under
tracked `crashes/`.

## Report

`./report.sh [OUT_DIR]` (default `gh-pages/`, the published-site worktree)
renders a self-contained `index.html`:

* the crash catalogue (grouped by loader, with signal / site / details),
* an **Unexpected outcomes** section — every backend×case that crashed, hung, or
  errored (vs a clean accept/reject), which surfaces findings beyond the curated
  `crashes::ALL` (e.g. `llvm-objdump` crashing, or a structural case that also
  crashes a loader),
* the structural cases, and the full backend×case matrix when `check` has run —
  hover a cell for the backend's message, click it to load that run's full
  captured `stdout`/`stderr` (copied verbatim into `results/` beside the page).

It also writes machine-readable `crashes.json` (the curated catalogue) and
`findings.json` (all unexpected outcomes). The Rust definitions are the single
source of truth; the report just projects them.

### Publishing to GitHub Pages

The published site lives on an orphan `gh-pages` branch that contains **only**
the generated files (`index.html`, `crashes.json`, `findings.json`,
`.nojekyll`), checked out as a git worktree at `./gh-pages` (ignored on the main
branch). `./deploy.sh` does the whole thing — creates the worktree if needed,
regenerates the report into it, commits, and pushes:

```sh
./gen.sh && ./check.sh   # refresh fixtures + results first
./deploy.sh
```

Enable Pages once in the repo settings (Source: `gh-pages` branch, `/` root);
the site is then served at `https://<owner>.github.io/WhatTheElf/`.
