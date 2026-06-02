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
./check.sh llvm-readelf eu-readelf ld-linux
./scripts/setup_fuzz.sh
./fuzz.sh
```

`gen` builds the Rust-defined cases from `src/cases/` into ignored local ELF
files under `fixtures/`.

Case metadata lives beside each case in `src/cases/`. Invariant-tag definitions
live in `manifest.yaml`. The low-level ELF writer lives in `src/elf.rs`; it
intentionally permits inconsistent headers, counts, offsets, and links.

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

* glibc `ld.so --verify @@` — ELF header / program-header parsing & validation.
* glibc `LD_TRACE_PRELINKING=1 ld.so @@` — full map + symbol resolution +
  relocation, without executing the entry point (roughly doubles edge coverage).
* musl `ld-musl-x86_64.so.1 --list @@` — map + resolve + relocate, no execute.

## Current fixtures

See `src/cases/` for the case list, summaries, and invariant tags.

Most fixtures are tiny synthetic structural malformations. Two groups come from
the fuzzer, and every crash case carries a long-form `Case.details` string (fault
site, triggering field, root cause) as data — not just a doc comment — so it can
be rendered elsewhere:

* `src/cases/glibc_crashes.rs` — crashes in glibc `ld.so --verify`. Where the
  mechanism is fully understood it is an *understandable structured reproducer*
  built from the ELF builders (`LOAD_MEMSZ_PAST_EOF` — SIGBUS zero-filling `.bss`
  past EOF in `_dl_map_segments`; `LOAD_WILD_VADDR_PHDR` — fault in the post-map
  program-header rescan). Where the crash depends on the loader walking off into
  garbage memory (no clean structural form) the raw artifact is kept for
  reference with the path explained in `details` (`DYN_LSONAME_OOB`,
  `RTLD_STARTUP_STRCMP`, `WILD_VADDR_ASLR`).
* `src/cases/musl_crashes.rs` — 11 musl `ld-musl --list` crashes, one per distinct
  fault site from the 8-hour run (segment mapping, `do_relocs`/`do_relr_relocs`/
  `reloc_all`, symbol lookup, `load_direct_deps`, `__dls3`, `__copy_tls`), kept as
  raw artifacts since the malformations are dynamic-table corruptions.

All crash cases reproduce on the stock system loaders. Raw bytes live under
tracked `crashes/` and `crashes-musl/`. These are regression inputs for loader
robustness, not examples of valid ELF.
