# WhatTheElf

Malformed ELF generator and crash checker.

The original Lean parser/spec moved to `ELFine` as `ELFine.WhatTheElf`. This
repo now focuses on producing malformed ELF files and running them through
external loaders/tools to see whether they accept, reject, hang, or crash.

## Usage

```sh
python3 whattheelf.py generate fixtures
python3 whattheelf.py check fixtures -- qemu-x86_64
python3 whattheelf.py check fixtures -- /lib64/ld-linux-x86-64.so.2 --verify
```

If the command contains `{}`, the fixture path is substituted there. Otherwise
the fixture path is appended to the command.

```sh
python3 whattheelf.py check fixtures -- sh -c 'qemu-x86_64 "$1"' sh {}
```

## Current fixtures

- `control_exit42`: valid tiny x86-64 ET_EXEC that exits 42.
- `qemu_phnum0`: ELF header with `e_phnum = 0`.
- `qemu_interp_filesz0`: `PT_INTERP` with `p_filesz = 0`.
- `qemu_filesz_gt_memsz`: `PT_LOAD` with `p_filesz > p_memsz`.
- `qemu_symtab_bad_shlink`: `SHT_SYMTAB.sh_link` points outside the section table.

These fixtures are intentionally tiny and synthetic. They are regression inputs
for loader robustness, not examples of valid ELF files.
