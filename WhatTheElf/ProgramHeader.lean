/-
ELF64 `Elf64_Phdr` — DSL-defined layout + parser.

Spec: gabi 07 § Program Header. 56 bytes per entry. We model `p_type` as an
open enum with `osSpecific` / `procSpecific` ranges plus an `other` catch-all
for unassigned values. `p_flags` is a bitfield, not an enum (`PF_R`/`PF_W`/
`PF_X` plus `PF_MASKOS`/`PF_MASKPROC` mask regions) — left as raw `UInt32`.

The ehdr's witnessed fields are everything needed to slice the file into
phdr-table entries, so `CheckedElf64_Ehdr.phdrTable` and `parsePhdrs` live
here. `parsePhdrs` is a one-liner over the generic `parseTable`.
-/

import WhatTheElf.Basic
import WhatTheElf.ElfHeader
import WhatTheElf.Macro

namespace WhatTheElf

elf_record Elf64_Phdr where
  p_type   : UInt32 { pt_null = 0, pt_load = 1, pt_dynamic = 2, pt_interp = 3,
                      pt_note = 4, pt_shlib = 5, pt_phdr = 6, pt_tls = 7,
                      osSpecific   = 0x60000000..0x6fffffff,
                      procSpecific = 0x70000000..0x7fffffff,
                      other = _ }
  p_flags  : UInt32
  p_offset : Off
  p_vaddr  : Addr
  p_paddr  : Addr
  p_filesz : UInt64
  p_memsz  : UInt64
  p_align  : UInt64

/-- The phdr table's location, stride, and count — read straight off the ehdr. -/
def Elf64_Ehdr.phdrTable (h : Elf64_Ehdr) : TableLayout :=
  { offset := h.e_phoff.toNat
  , stride := h.e_phentsize.toNat
  , count  := h.e_phnum.toNat }

/-- Parse every program-header entry. The ehdr's witnessed `e_phentsize = 56`
    (via `phentsize_ok`) guarantees the stride covers the full entry; per
    entry, `Elf64_Phdr.parse` does its own read/decode/check. -/
def Elf64_Ehdr.parsePhdrs (h : Elf64_Ehdr) (file : ByteArray) :
    Except String (Array Elf64_Phdr) :=
  parseTable file h.phdrTable

-- ── Generic phdr-content helpers ────────────────────────────────────

/-- The byte slice this phdr covers in the file: `file[p_offset .. p_offset + p_filesz]`. -/
def Elf64_Phdr.segment (p : Elf64_Phdr) (file : ByteArray) : ByteArray :=
  file.extract p.p_offset.toNat (p.p_offset.toNat + p.p_filesz.toNat)

/-- Translate a virtual address to a file offset using the `PT_LOAD` segments
    as a translation table. Returns `none` if `vaddr` isn't covered by any
    loadable segment. Dynamic-linker-driven parsing (symtab/strtab via
    `DT_SYMTAB`/`DT_STRTAB`) needs this because the dynamic section stores
    addresses, not file offsets. -/
def Elf64_Phdr.virtualToFileOffset (phdrs : Array Elf64_Phdr) (vaddr : Nat) : Option Nat :=
  phdrs.findSome? fun p =>
    match p.p_type with
    | .pt_load =>
      let v := p.p_vaddr.toNat
      let s := p.p_filesz.toNat
      if v ≤ vaddr ∧ vaddr < v + s then
        some (p.p_offset.toNat + (vaddr - v))
      else none
    | _ => none

/-- Find the first phdr satisfying `which`; parse its segment as a fixed-size
    table of `α`. Stride = `Parser.size α`, count = `p_filesz / stride`.
    Returns `none` when no matching phdr exists. -/
def parsePhdrTable (α : Type) [Parser α] (file : ByteArray) (phdrs : Array Elf64_Phdr)
    (which : Elf64_Phdr → Bool) : Except String (Option (Array α)) :=
  match phdrs.find? which with
  | none   => .ok none
  | some p =>
    let entSize := Parser.size α
    let layout : TableLayout :=
      { offset := p.p_offset.toNat
      , stride := entSize
      , count  := p.p_filesz.toNat / entSize }
    (parseTable file layout).map some

/-- Parse the `PT_INTERP` segment as a UTF-8 string (the dynamic linker
    path, e.g. `"/lib64/ld-linux-x86-64.so.2"`). The segment is a
    null-terminated C string; we strip the trailing nul. -/
def parseInterp (file : ByteArray) (phdrs : Array Elf64_Phdr) :
    Except String (Option String) :=
  match phdrs.find? fun p => match p.p_type with | .pt_interp => true | _ => false with
  | none   => .ok none
  | some p =>
    let bs := p.segment file
    let trimmed :=
      if bs.size > 0 ∧ bs[bs.size - 1]! = 0
      then bs.extract 0 (bs.size - 1)
      else bs
    match String.fromUTF8? trimmed with
    | some s => .ok (some s)
    | none   => .error "PT_INTERP: invalid UTF-8"

end WhatTheElf
