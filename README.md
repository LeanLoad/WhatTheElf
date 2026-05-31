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

## Current fixtures

See `src/cases/` for the case list, summaries, and invariant tags.

These fixtures are intentionally tiny and synthetic. They are regression inputs
for loader robustness, not examples of valid ELF files.
