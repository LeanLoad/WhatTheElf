/-
ELF relocation table (`.rela.dyn` / `.rela.plt`).

Located via `DT_RELA` (vaddr), `DT_RELASZ` (total bytes), `DT_RELAENT`
(stride; gabi requires 24) in the dynamic table — and `DT_JMPREL` for the
PLT-specific relocations (same entry shape, separate table).

Each entry is 24 bytes (gabi 06 § Relocation):

  Elf64_Addr   r_offset;  // 8 — vaddr to apply the relocation to
  Elf64_Xword  r_info;    // 8 — packed: high 32 bits = symbol index,
                          //             low 32 bits = relocation type
  Elf64_Sxword r_addend;  // 8 — constant added to the symbol value

The relocation `type` field is processor-specific (R_X86_64_*, R_AARCH64_*,
etc.); we keep it as a raw UInt32 and expose `Rela.sym`/`Rela.type` helpers
to unpack `r_info`.
-/

import WhatTheElf.Basic
import WhatTheElf.ProgramHeader
import WhatTheElf.Dynamic
import WhatTheElf.Macro

namespace WhatTheElf

elf_record Elf64_Rela where
  r_offset : Addr
  r_info   : UInt64
  r_addend : UInt64    -- gabi says Elf64_Sxword (signed); same wire shape

/-- Symbol index from packed `r_info` — `ELF64_R_SYM(info) = info >> 32`. -/
def Elf64_Rela.sym (r : Elf64_Rela) : UInt32 := (r.r_info >>> 32).toUInt32

/-- Relocation type from packed `r_info` — `ELF64_R_TYPE(info) = info & 0xffffffff`. -/
def Elf64_Rela.type (r : Elf64_Rela) : UInt32 := (r.r_info &&& 0xffffffff).toUInt32

/-- Read a `.rela` table identified by `(addrTag, sizeTag, entTag)` — i.e.
    `(DT_RELA, DT_RELASZ, DT_RELAENT)` for `.rela.dyn` or
    `(DT_JMPREL, DT_PLTRELSZ, DT_RELAENT)` for `.rela.plt`. -/
private def parseRelaWith
    (addrTag sizeTag : Elf64_Dyn.DTag) (entSize : Nat)
    (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array Elf64_Rela)) := do
  let some addr := lookupDtag dyn addrTag
    | return none
  let some size := lookupDtag dyn sizeTag
    | throw "rela: address tag present but no companion size tag"
  let some off := Elf64_Phdr.virtualToFileOffset phdrs addr.toNat
    | throw s!"rela: vaddr={addr.toNat} not in any PT_LOAD segment"
  let layout : TableLayout :=
    { offset := off, stride := entSize, count := size.toNat / entSize }
  let arr ← parseTable (α := Elf64_Rela) file layout
  return some arr

/-- Parse `.rela.dyn` — the main relocation table, located via `DT_RELA`. -/
def parseRelaDyn (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array Elf64_Rela)) :=
  parseRelaWith .dt_rela .dt_relasz Elf64_Rela.size file phdrs dyn

/-- Parse `.rela.plt` — relocations for the PLT, located via `DT_JMPREL`.
    `DT_PLTREL` (val) says whether this table is `DT_REL` (= 17) or
    `DT_RELA` (= 7); we only support `DT_RELA` here. -/
def parseRelaPlt (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array Elf64_Rela)) := do
  -- Only attempt if DT_PLTREL says the table is DT_RELA (= 7).
  match lookupDtag dyn .dt_pltrel with
  | some 7 => parseRelaWith .dt_jmprel .dt_pltrelsz Elf64_Rela.size file phdrs dyn
  | _      => return none

end WhatTheElf
