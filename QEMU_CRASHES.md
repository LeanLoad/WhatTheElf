# QEMU linux-user crash cases

These x86-64 ELF fixtures target QEMU's `linux-user/elfload.c` loader. They
were observed to crash local `qemu-x86_64` 8.2.2 with host segfault status 139.

- `qemu_phnum0`: ELF header sets `e_phnum = 0`; QEMU reaches a zero-length
  program-header table path instead of rejecting cleanly.
- `qemu_interp_filesz0`: `PT_INTERP` has `p_filesz = 0`; QEMU checks
  `interp_name[p_filesz - 1]`, so zero underflows.
- `qemu_symtab_bad_shlink`: `SHT_SYMTAB.sh_link` points outside the section
  table; QEMU's symbol-loading path indexes that section without a bounds check.

Controls:

- `control_exit42`: valid tiny executable that exits with status 42.
- `qemu_filesz_gt_memsz`: malformed `PT_LOAD` with `p_filesz > p_memsz`; this
  did not crash the local QEMU build, but remains a useful regression input.
