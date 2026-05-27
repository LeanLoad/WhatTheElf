/-
ELF symbol table (`.dynsym` / `.symtab`).

Each entry is 24 bytes (`DT_SYMENT` confirms this for `.dynsym`):

  Elf64_Word    st_name;    // 4 — offset into .dynstr
  unsigned char st_info;    // 1 — high 4 bits = STB_* binding, low 4 = STT_* type
  unsigned char st_other;   // 1 — low 2 bits = STV_* visibility
  Elf64_Half    st_shndx;   // 2 — section index (or SHN_UNDEF/SHN_ABS/…)
  Elf64_Addr    st_value;   // 8
  Elf64_Xword   st_size;    // 8

Located via `DT_SYMTAB` (address) + `DT_SYMENT` (stride, usually 24) in the
dynamic table. The dynamic section gives no count — that's recovered from
the hash table:

  * `DT_HASH` (gabi-standard, mandatory but skipped by modern Linux linkers)
    — second `UInt32` = `nchain` = symbol count.
  * `DT_GNU_HASH` (Linux extension, present in modern glibc-linked ELFs)
    — derive by finding the max bucket entry and walking its chain to the
      end-of-chain marker (low bit set).

`/bin/ls` ships only `DT_GNU_HASH`; static-linked things ship neither and
this function will refuse.
-/

import WhatTheElf.Basic
import WhatTheElf.ProgramHeader
import WhatTheElf.SectionHeader
import WhatTheElf.Strtab
import WhatTheElf.Dynamic
import WhatTheElf.Macro

namespace WhatTheElf

elf_record Elf64_Sym where
  st_name  : UInt32
  st_info  : UInt8
  st_other : UInt8
  st_shndx : UInt16
  st_value : Addr
  st_size  : UInt64

/-- High nibble of `st_info` — `STB_*` binding (local/global/weak/…). -/
def Elf64_Sym.bind (s : Elf64_Sym) : UInt8 := s.st_info >>> 4

/-- Low nibble of `st_info` — `STT_*` type (notype/object/func/section/…). -/
def Elf64_Sym.type (s : Elf64_Sym) : UInt8 := s.st_info &&& 0xf

-- ── Hash-table-driven symbol count ──────────────────────────────────

/-- The DT_GNU_HASH value as a `DTag`. Sits between `DT_HIOS` (0x6ffff000)
    and `DT_LOPROC` (0x70000000) so it falls into the open enum's `other`
    catch-all. -/
private def dtagGnuHash : Elf64_Dyn.DTag := .other 0x6ffffef5

/-- Read a little-endian `UInt32` from `bs` at absolute offset `off`,
    producing a useful error rather than the cryptic "u8: EOF at 0/0"
    that would surface from a sliced cursor read on an out-of-bounds offset. -/
private def readU32 (bs : ByteArray) (off : Nat) : Except String UInt32 :=
  if off + 4 > bs.size then
    .error s!"readU32: offset {off} + 4 > file size {bs.size}"
  else
    let c := WhatTheElf.Cursor.ofBytes (bs.extract off (off + 4))
    match c.u32le with
    | .ok (v, _) => .ok v
    | .error e   => .error e

/-- Walk the `chains[]` array of a GNU hash table from `i` until an entry
    with bit 0 set (the end-of-chain marker). Returns the chain index of
    that terminator entry. Bounded by `maxSteps` to guarantee termination
    on malformed inputs. -/
private def walkGnuHashChain
    (file : ByteArray) (chainsOffset start : Nat) (maxSteps : Nat) :
    Except String Nat := do
  let mut i := start
  let mut found := false
  for _ in [0:maxSteps] do
    if found then break
    let v ← readU32 file (chainsOffset + i * 4)
    if v &&& 1 = 1 then found := true
    else i := i + 1
  if found then return i
  else throw s!"DT_GNU_HASH: chain at {start} didn't terminate within {maxSteps} steps"

/-- Derive the symbol count from a `DT_GNU_HASH` table at file offset `off`. -/
private def gnuHashSymbolCount (file : ByteArray) (off : Nat) : Except String Nat := do
  let nbuckets    ← readU32 file (off + 0)
  let symoffset   ← readU32 file (off + 4)
  let bloom_size  ← readU32 file (off + 8)
  -- bloom_shift at off+12 is irrelevant for counting
  let bucketsOff := off + 16 + bloom_size.toNat * 8
  let chainsOff  := bucketsOff + nbuckets.toNat * 4
  -- Find the max bucket entry — highest *hashed* symbol index.
  let mut maxBucket : UInt32 := 0
  for i in [0:nbuckets.toNat] do
    let v ← readU32 file (bucketsOff + i * 4)
    if v > maxBucket then maxBucket := v
  if maxBucket < symoffset then
    -- No hashed symbols at all; total = symoffset.
    return symoffset.toNat
  -- Walk the chain starting at chain[maxBucket - symoffset] until end marker.
  let startChainIdx := maxBucket.toNat - symoffset.toNat
  let bound := (file.size - chainsOff) / 4
  let endIdx ← walkGnuHashChain file chainsOff startChainIdx bound
  -- endIdx is a chain index; the symbol it corresponds to is symoffset + endIdx.
  return symoffset.toNat + endIdx + 1

/-- Read `nchain` from a `DT_HASH` table (second `UInt32`). -/
private def dtHashSymbolCount (file : ByteArray) (off : Nat) : Except String Nat := do
  let nchain ← readU32 file (off + 4)
  return nchain.toNat

-- ── Symtab parser ───────────────────────────────────────────────────

/-- Locate `.dynsym` via the dynamic table:
    `DT_SYMTAB` (vaddr) + `DT_SYMENT` (stride) + hash table (count).
    Prefers `DT_HASH` (cheaper); falls back to `DT_GNU_HASH`. -/
def parseSymtab (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array Elf64_Sym)) := do
  let some symAddr := lookupDtag dyn .dt_symtab
    | return none
  let some symEnt := lookupDtag dyn .dt_syment
    | throw "DT_SYMTAB present but no DT_SYMENT"
  let count ← do
    if let some hashAddr := lookupDtag dyn .dt_hash then
      let some hashOff := Elf64_Phdr.virtualToFileOffset phdrs hashAddr.toNat
        | throw s!"DT_HASH vaddr={hashAddr.toNat} not in any PT_LOAD segment"
      dtHashSymbolCount file hashOff
    else if let some ghAddr := lookupDtag dyn dtagGnuHash then
      let some ghOff := Elf64_Phdr.virtualToFileOffset phdrs ghAddr.toNat
        | throw s!"DT_GNU_HASH vaddr={ghAddr.toNat} not in any PT_LOAD segment"
      gnuHashSymbolCount file ghOff
    else
      throw "no DT_HASH or DT_GNU_HASH found; cannot determine symbol count from dynamic alone"
  let some symOff := Elf64_Phdr.virtualToFileOffset phdrs symAddr.toNat
    | throw s!"DT_SYMTAB vaddr={symAddr.toNat} not in any PT_LOAD segment"
  let layout : TableLayout := { offset := symOff, stride := symEnt.toNat, count }
  let arr ← parseTable (α := Elf64_Sym) file layout
  return some arr

-- ── Shdr-driven symbol table parsing ────────────────────────────────

/-- Pair of (symbol table, its linked string table). The strtab is whatever
    section `sh_link` of the chosen symbol-table shdr points to — it must
    have `sh_type = SHT_STRTAB`, otherwise we reject the file. -/
structure SymtabFromShdrs where
  syms   : Array Elf64_Sym
  strtab : Strtab
  deriving Repr

instance : ToJsonStr SymtabFromShdrs where
  toJsonStr s :=
    "{\"syms\":" ++ toJsonStr s.syms ++
    ",\"strtab\":" ++ toJsonStr s.strtab ++ "}"

/-- Parse the symbol-table section of the given `wantType` (typically
    `SHT_SYMTAB` for the full linker symtab or `SHT_DYNSYM` for the
    dynamic loader's symtab). Returns `none` if no such section exists
    (e.g. stripped binaries for `SHT_SYMTAB`). The companion `.strtab`
    is located through the shdr's `sh_link`. -/
def parseSymtabFromShdrs (file : ByteArray) (shdrs : Array Elf64_Shdr)
    (wantType : Elf64_Shdr.ShType) :
    Except String (Option SymtabFromShdrs) := do
  let some symShdr := shdrs.find? (fun s => s.sh_type = wantType)
    | return none
  let entSize := symShdr.sh_entsize.toNat
  if entSize = 0 then
    throw s!"{repr wantType} section has sh_entsize=0; cannot determine stride"
  let count := symShdr.sh_size.toNat / entSize
  let layout : TableLayout :=
    { offset := symShdr.sh_offset.toNat, stride := entSize, count }
  let syms ← parseTable (α := Elf64_Sym) file layout
  -- Locate paired strtab via sh_link.
  let linkIdx := symShdr.sh_link.toNat
  let some strShdr := shdrs[linkIdx]?
    | throw s!"{repr wantType}.sh_link={linkIdx} out of range ({shdrs.size} shdrs)"
  if strShdr.sh_type ≠ .sht_strtab then
    throw s!"{repr wantType}.sh_link={linkIdx} points at sh_type={repr strShdr.sh_type}, want SHT_STRTAB"
  let strOff := strShdr.sh_offset.toNat
  let strtab : Strtab := { bytes := file.extract strOff (strOff + strShdr.sh_size.toNat) }
  return some { syms, strtab }

end WhatTheElf
