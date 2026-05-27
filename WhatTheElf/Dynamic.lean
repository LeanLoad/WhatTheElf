/-
ELF64 `Elf64_Dyn` — entries of the `.dynamic` segment.

Spec: gabi 08 § Dynamic Linking. Each entry is 16 bytes:

  ``d_tag``  Elf64_Sxword  (we use `UInt64` — bit pattern is the same; gabi
                             reserves negative tags for psABI use, none defined)
  ``d_un``   union { Elf64_Xword d_val; Elf64_Addr d_ptr; }

The union's interpretation depends on `d_tag` (gabi tables in 08-dynamic.rst
indicate per-tag which member is used). We keep `d_un` as a raw `UInt64`;
downstream consumers dispatch on the tag.

The dynamic table is located by the `PT_DYNAMIC` program header, with byte
size given by `p_filesz`. Since each entry is exactly 16 bytes, the entry
count is `p_filesz / 16` — no terminator scan needed. (gabi requires the
last entry to be `DT_NULL`; we don't enforce that here yet.)
-/

import WhatTheElf.Basic
import WhatTheElf.ElfHeader
import WhatTheElf.ProgramHeader
import WhatTheElf.Macro

namespace WhatTheElf

elf_record Elf64_Dyn where
  d_tag : UInt64 { dt_null = 0, dt_needed = 1, dt_pltrelsz = 2, dt_pltgot = 3,
                   dt_hash = 4, dt_strtab = 5, dt_symtab = 6, dt_rela = 7,
                   dt_relasz = 8, dt_relaent = 9, dt_strsz = 10, dt_syment = 11,
                   dt_init = 12, dt_fini = 13, dt_soname = 14, dt_rpath = 15,
                   dt_symbolic = 16, dt_rel = 17, dt_relsz = 18, dt_relent = 19,
                   dt_pltrel = 20, dt_debug = 21, dt_textrel = 22, dt_jmprel = 23,
                   dt_bind_now = 24, dt_init_array = 25, dt_fini_array = 26,
                   dt_init_arraysz = 27, dt_fini_arraysz = 28, dt_runpath = 29,
                   dt_flags = 30, dt_preinit_array = 32, dt_preinit_arraysz = 33,
                   dt_symtab_shndx = 34,
                   dt_relrsz = 35, dt_relr = 36, dt_relrent = 37,
                   osSpecific   = 0x6000000d..0x6ffff000,
                   procSpecific = 0x70000000..0x7fffffff,
                   other = _ }
  d_un  : UInt64

/-- Look up the `d_un` value for a given tag in a dynamic table, if present.
    Returns the first match per gabi's convention that each tag appears at
    most once (except `DT_NEEDED`). -/
def lookupDtag (dyn : Array Elf64_Dyn) (tag : Elf64_Dyn.DTag) : Option UInt64 :=
  dyn.findSome? fun e => if e.d_tag == tag then some e.d_un else none

/-- Parse the `.dynamic` segment if a `PT_DYNAMIC` phdr is present.
    Returns `none` for static binaries (no `PT_DYNAMIC`). -/
def parseDynamic (file : ByteArray) (phdrs : Array Elf64_Phdr) :
    Except String (Option (Array Elf64_Dyn)) :=
  parsePhdrTable Elf64_Dyn file phdrs
    fun p => match p.p_type with | .pt_dynamic => true | _ => false

end WhatTheElf
