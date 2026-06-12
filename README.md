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

`llvm-objdump` and `qemu-x86_64` are fuzzed without rebuilding them, using
AFL++'s **FRIDA mode** (`afl-fuzz -O`) on the installed binaries:
`llvm-objdump -p @@` and `qemu-x86_64 @@`. Seeds are valid object files / a small
static binary (plus a few malformed ones), kept separate from the loader corpus.
`run_campaign.sh` adds these jobs when `frida_mode` is built (`setup_fuzz.sh`
builds it).

qemu-user *executes* the guest, so **some** of its crashes are guest faults
(`qemu: uncaught target signal`) — the guest running garbage at a bogus entry
point, not a qemu bug. (On the fixture corpus that's a minority — 5 of 90; e.g.
an all-zero entry decodes as `add [rax],al` and SIGSEGVs the guest.) The real
findings are qemu's *own* loader crashing before the guest runs (38: host
SIGSEGV/SIGBUS mapping wild addresses, a `pgb_dynamic` assertion, a GLib
over-allocation abort). Triage on the `uncaught target signal` stderr marker —
that's exactly what the `check` classifier does.

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

## Prior art / references

The malformed-ELF technique these cases formalize is older than this repo. The
articles below are the canonical write-ups; each abuses the same loader-vs-tool
divergence the corpus probes — the kernel `execve` path reads almost nothing,
while parsers, debuggers, and the dynamic loaders read far more and can be made
to choke. See the umbrella [`CONFORMANCE.md`](../CONFORMANCE.md) for the
implementation-by-implementation view of who reads which fields.

- **"Analyzing ELF Binaries with Malformed Headers — Part 1: Emulating Tiny
  Programs"** — *binaryresearch.github.io*, 2019.
  <https://binaryresearch.github.io/2019/09/17/Analyzing-ELF-Binaries-with-Malformed-Headers-Part-1-Emulating-Tiny-Programs.html>
  Only `e_ident` magic, `e_type`, `e_machine`, `e_entry`, `e_phoff`, `e_phnum`
  must be correct to `execve`; `e_ehsize` and `e_phentsize` are essentially
  unread on the load path. "Tiny" binaries overlap the program-header table with
  the ELF header and put the entry point *inside* the header, so a structural
  parser walks into garbage while the kernel runs the file. The article's method
  is to emulate (Unicorn) rather than parse.
  - Covered: [`phdr_overlaps_ehdr`](src/cases/program_headers.rs),
    [`bad_ehsize_short`](src/cases/headers.rs),
    [`bad_phentsize_short` / `bad_phentsize_large`](src/cases/headers.rs),
    [`phnum_zero`](src/cases/program_headers.rs).
  - Gap → new case **`entry_inside_ehdr`**: a minimal `ET_EXEC` whose `e_entry`
    and `PT_LOAD` cover the ELF header itself (the canonical tiny-binary shape),
    tagged `Containment` + `NonOverlap`. Confirms the loaders run it while
    structural backends disagree.

- **"Screwing with the ELF header for fun and profit"** — *dustri.org*.
  <https://dustri.org/b/screwing-elf-header-for-fun-and-profit.html>
  Setting the section-table fields (`e_shoff`, `e_shnum`, `e_shstrndx`) to
  `0xffff` (or zeroing them) leaves the binary runnable but makes `gdb`
  ("File truncated"), `objdump`, `ltrace`/`strace`, `elfsh`, and `hte` fail;
  `radare2` survives. The author stresses it is trivially repaired — friction,
  not protection.
  - Covered individually: [`shoff_oob`](src/cases/section_headers.rs),
    [`shnum_huge_oob`](src/cases/section_headers.rs),
    [`shstrndx_oob`](src/cases/section_headers.rs),
    [`shdr_table_truncated`](src/cases/section_headers.rs).
  - Gap → new case **`shdr_fields_all_ffff`**: the exact POC, setting all three
    section-table fields to `0xffff` at once (rather than one field per case),
    tagged `Bounds` + `Consistency`. Verifies the kernel/`ld.so` accept it while
    the parser/debugger backends crash or bail.

- **"Striking Back at GDB and IDA Debuggers Through Malformed ELF
  Executables"** — *IOActive* (Alejandro Hernández).
  <https://www.ioactive.com/striking-back-gdb-and-ida-debuggers-through-malformed-elf-executables/>
  The kernel trusts program headers; debuggers trust section headers + DWARF.
  `e_shstrndx > e_shnum` reads past the section table and kills IDA 6.3; a
  `.debug_line` entry with `dir_index > 0` while `include_dirs` is `NULL`
  NULL-derefs gdb 7.5.1. The binary executes throughout.
  - Covered: the `e_shstrndx`-past-table case is
    [`shstrndx_oob`](src/cases/section_headers.rs).
  - Gap → new case **`debug_line_bad_dir_index`** (a new `src/cases/debug.rs`
    module): a `.debug_line` program whose file entry references a
    nonexistent include-directory index, tagged `Bounds` + `Conjugate`. This is
    the corpus's first DWARF-level malformation and targets the debugger
    backends specifically.

The three proposed cases are not yet implemented; they are tracked here so the
generator stays aligned with the documented techniques. The fuzzers
(`./fuzz.sh`, FRIDA-mode `llvm-objdump`/`qemu`) cover the same surface
stochastically; these are the curated, named counterparts.

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
