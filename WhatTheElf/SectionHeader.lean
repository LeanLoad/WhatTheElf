/-
ELF64 `Elf64_Shdr` — DSL-defined layout + section-table parser.

Spec: gabi 04 § Sections. 64 bytes per entry. `sh_type` and `sh_flags` get
inline enum coverage for everything gabi names; the OS- and proc-specific
ranges fall through to `other` so we accept (and round-trip) unknown
types without losing the raw value.

Section headers are independent of program headers — phdrs describe the
*loadable* view (what ld.so consumes), shdrs describe the *linker* view
(what `ld`, `objcopy`, `readelf` consume). Stripped binaries can have
no shdrs at all (`e_shoff = 0` / `e_shnum = 0`), so the table is
optional.

Spec gotcha: when `e_shnum` overflows 16 bits (more than 0xffff sections),
gabi puts the real count in `sh_size` of `shdr[0]` and sets `e_shnum = 0`.
Likewise for `e_shstrndx` (escape via `SHN_XINDEX = 0xffff`, real value
in `sh_link` of `shdr[0]`). We implement that escape in `parseShdrs`.
-/

import WhatTheElf.Basic
import WhatTheElf.ElfHeader
import WhatTheElf.ProgramHeader
import WhatTheElf.Strtab
import WhatTheElf.Macro

namespace WhatTheElf

elf_record Elf64_Shdr where
  sh_name      : UInt32
  sh_type      : UInt32 { sht_null = 0, sht_progbits = 1, sht_symtab = 2,
                          sht_strtab = 3, sht_rela = 4, sht_hash = 5,
                          sht_dynamic = 6, sht_note = 7, sht_nobits = 8,
                          sht_rel = 9, sht_shlib = 10, sht_dynsym = 11,
                          sht_init_array = 14, sht_fini_array = 15,
                          sht_preinit_array = 16, sht_group = 17,
                          sht_symtab_shndx = 18, sht_relr = 19,
                          sht_gnu_attributes = 0x6ffffff5,
                          sht_gnu_hash       = 0x6ffffff6,
                          sht_gnu_liblist    = 0x6ffffff7,
                          sht_gnu_verdef     = 0x6ffffffd,
                          sht_gnu_verneed    = 0x6ffffffe,
                          sht_gnu_versym     = 0x6fffffff,
                          osSpecific   = 0x60000000..0x6ffffff4,
                          procSpecific = 0x70000000..0x7fffffff,
                          userSpecific = 0x80000000..0xffffffff,
                          other = _ }
  sh_flags     : UInt64
  sh_addr      : Addr
  sh_offset    : Off
  sh_size      : UInt64
  sh_link      : UInt32
  sh_info      : UInt32
  sh_addralign : UInt64
  sh_entsize   : UInt64

-- ── Shdr-table location and parser ──────────────────────────────────

/-- gabi escape: `SHN_UNDEF = 0` is the null section index (and the slot
    that stores escape values for huge sections). -/
def SHN_UNDEF : Nat := 0

/-- gabi escape: `SHN_XINDEX = 0xffff` in `e_shstrndx` means the real
    string-table index is stored in `shdr[0].sh_link`. -/
def SHN_XINDEX : Nat := 0xffff

/-- Where the shdr table lives + how many entries to read. Handles the
    `e_shnum = 0` escape: if there are shdrs at all (`e_shoff ≠ 0`), the
    real count is `shdr[0].sh_size`. We resolve that here by reading the
    zeroth entry first, so downstream sees a single canonical count. -/
def Elf64_Ehdr.shdrTable (h : Elf64_Ehdr) (file : ByteArray) :
    Except String (Option TableLayout) := do
  if h.e_shoff.toNat = 0 then return none
  let entSize := h.e_shentsize.toNat
  let baseCount := h.e_shnum.toNat
  let count ←
    if baseCount = 0 then do
      let zero := file.extract h.e_shoff.toNat (h.e_shoff.toNat + entSize)
      let shdr0 ← Elf64_Shdr.parse zero
      pure shdr0.sh_size.toNat
    else pure baseCount
  return some
    { offset := h.e_shoff.toNat
    , stride := entSize
    , count  := count }

/-- Parse every section-header entry. Returns `none` for stripped
    binaries (no shdr table). -/
def Elf64_Ehdr.parseShdrs (h : Elf64_Ehdr) (file : ByteArray) :
    Except String (Option (Array Elf64_Shdr)) := do
  let some layout ← h.shdrTable file
    | return none
  let shdrs ← parseTable file layout
  return some shdrs

-- ── Section-name lookups ────────────────────────────────────────────

/-- Resolve `e_shstrndx`, honouring the `SHN_XINDEX` escape: if it equals
    `0xffff`, the real index lives in `shdr[0].sh_link`. -/
def Elf64_Ehdr.shstrIndex (h : Elf64_Ehdr) (shdrs : Array Elf64_Shdr) : Nat :=
  let raw := h.e_shstrndx.toNat
  if raw = SHN_XINDEX then
    if h0 : 0 < shdrs.size then shdrs[0].sh_link.toNat else SHN_UNDEF
  else raw

/-- Extract the `.shstrtab` section's bytes — the string table that holds
    every section's `sh_name`. Returns `none` if the shdr table doesn't
    name one (e.g. fully stripped). -/
def parseShstrtab (file : ByteArray) (h : Elf64_Ehdr) (shdrs : Array Elf64_Shdr) :
    Except String (Option Strtab) := do
  let idx := h.shstrIndex shdrs
  if idx = SHN_UNDEF then return none
  let some s := shdrs[idx]?
    | throw s!"e_shstrndx={idx} out of range (have {shdrs.size} shdrs)"
  if s.sh_type ≠ .sht_strtab then
    throw s!"e_shstrndx={idx} points at sh_type={repr s.sh_type}, want SHT_STRTAB"
  let off := s.sh_offset.toNat
  return some { bytes := file.extract off (off + s.sh_size.toNat) }

/-- Resolve a single shdr's name through the `.shstrtab`. Returns `""`
    for `sh_name = 0` and `none` for out-of-range offsets / bad UTF-8. -/
def Elf64_Shdr.name (s : Elf64_Shdr) (shstr : Strtab) : Option String :=
  shstr.lookupAt s.sh_name.toNat

end WhatTheElf
