/-
ELF symbol versioning (gabi 12 § Versioning).

GNU-style symbol versioning lets a shared library export multiple versions
of the same symbol (e.g. `pthread_create@@GLIBC_2.34` alongside an older
`pthread_create@GLIBC_2.2.5`). On the consumer side, every dynamic symbol
in `.dynsym` gets a 2-byte version-index entry in `.gnu.version`
(`DT_VERSYM`), and the dependency-version requirements live in linked
chains under `.gnu.version_r` (`DT_VERNEED` + `DT_VERNEEDNUM`).

This module parses:

  * `.gnu.version`   — `Array UInt16`, one per `.dynsym` entry. Low 15 bits
    select a version index (into Verneed/Verdef); high bit is `VER_NDX_HIDDEN`.
    Special: 0 = `VER_NDX_LOCAL`, 1 = `VER_NDX_GLOBAL`.

  * `.gnu.version_r` — chain of `Elf64_Verneed`, each carrying a chain of
    `Elf64_Vernaux`. Both records are 16 bytes; the chains are walked via
    `*_next` offsets (0 = end), not via a count + stride.

  * `.gnu.version_d` — chain of `Elf64_Verdef` (20 bytes) carrying chains
    of `Elf64_Verdaux` (8 bytes). This is the *defining* side: libraries
    like `libc.so.6` list every version they export here. Located via
    `DT_VERDEF` (0x6ffffffc) + `DT_VERDEFNUM` (0x6ffffffd).
-/

import WhatTheElf.Basic
import WhatTheElf.ProgramHeader
import WhatTheElf.Dynamic
import WhatTheElf.Macro

namespace WhatTheElf

-- ── Versym: per-symbol version-index array ──────────────────────────

/-- `.gnu.version` — one `UInt16` per `.dynsym` entry. -/
def parseVersym (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn)
    (symbolCount : Nat) : Except String (Option (Array UInt16)) := do
  -- DT_VERSYM is OS-specific; falls into our open enum's `other` arm
  -- with raw value 0x6ffffff0.
  let some addr := lookupDtag dyn (.other 0x6ffffff0)
    | return none
  let some off := Elf64_Phdr.virtualToFileOffset phdrs addr.toNat
    | throw s!"DT_VERSYM vaddr={addr.toNat} not in any PT_LOAD segment"
  let need := symbolCount * 2
  if file.size < off + need then
    throw s!"DT_VERSYM: short read, want {need} bytes at off={off}, file size {file.size}"
  let mut out := Array.mkEmpty symbolCount
  for i in [0:symbolCount] do
    let lo := file[off + i * 2]!
    let hi := file[off + i * 2 + 1]!
    out := out.push (lo.toUInt16 ||| (hi.toUInt16 <<< 8))
  return some out

-- ── Versym semantic helpers ────────────────────────────────────────

/-- `VER_NDX_LOCAL` — symbol is local; not exported. -/
def VER_NDX_LOCAL  : UInt16 := 0
/-- `VER_NDX_GLOBAL` — symbol is global; no symbol-versioning info attached. -/
def VER_NDX_GLOBAL : UInt16 := 1
/-- High bit of a versym entry = `VER_NDX_HIDDEN`. The semantic version
    index is the low 15 bits. -/
def VER_NDX_MASK   : UInt16 := 0x7fff

/-- A symbol's version index — the low 15 bits of its versym entry. -/
def Versym.index (v : UInt16) : UInt16 := v &&& VER_NDX_MASK

-- ── Verneed + Vernaux: version-requirement chains ──────────────────

elf_record Elf64_Verneed where
  vn_version : UInt16
  vn_cnt     : UInt16
  vn_file    : UInt32
  vn_aux     : UInt32
  vn_next    : UInt32

elf_record Elf64_Vernaux where
  vna_hash  : UInt32
  vna_flags : UInt16
  vna_other : UInt16
  vna_name  : UInt32
  vna_next  : UInt32

/-- One dependency's version requirements: the `Verneed` header plus the
    chain of `Vernaux` entries it owns. -/
structure VerneedEntry where
  verneed : Elf64_Verneed
  auxes   : Array Elf64_Vernaux
  deriving Repr

instance : ToJsonStr VerneedEntry where
  toJsonStr e :=
    "{\"verneed\":" ++ toJsonStr e.verneed ++ ",\"auxes\":" ++ toJsonStr e.auxes ++ "}"

/-- Read one `Elf64_Verneed` at `off` and walk its `Vernaux` chain. -/
private def readOneVerneed (file : ByteArray) (off : Nat) : Except String VerneedEntry := do
  let verneed ← Elf64_Verneed.parse (file.extract off (off + Elf64_Verneed.size))
  let mut auxes := Array.mkEmpty verneed.vn_cnt.toNat
  let mut auxOff := off + verneed.vn_aux.toNat
  for _ in [0:verneed.vn_cnt.toNat] do
    let aux ← Elf64_Vernaux.parse (file.extract auxOff (auxOff + Elf64_Vernaux.size))
    auxes := auxes.push aux
    if aux.vna_next = 0 then break
    auxOff := auxOff + aux.vna_next.toNat
  return { verneed, auxes }

/-- `.gnu.version_r` — chain of Verneed entries via `DT_VERNEED` + `DT_VERNEEDNUM`. -/
def parseVerneeds (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array VerneedEntry)) := do
  -- Both tags are OS-specific (in the gap between DT_HIOS and DT_LOPROC),
  -- so they land in the open enum's `other` arm.
  let some addr := lookupDtag dyn (.other 0x6ffffffe)             -- DT_VERNEED
    | return none
  let some num := lookupDtag dyn (.other 0x6fffffff)              -- DT_VERNEEDNUM
    | throw "DT_VERNEED present but no DT_VERNEEDNUM"
  let some off := Elf64_Phdr.virtualToFileOffset phdrs addr.toNat
    | throw s!"DT_VERNEED vaddr={addr.toNat} not in any PT_LOAD segment"
  let mut entries := Array.mkEmpty num.toNat
  let mut cur := off
  for _ in [0:num.toNat] do
    let entry ← readOneVerneed file cur
    entries := entries.push entry
    if entry.verneed.vn_next = 0 then break
    cur := cur + entry.verneed.vn_next.toNat
  return some entries

-- ── Verdef + Verdaux: version-definition chains ────────────────────

elf_record Elf64_Verdef where
  vd_version : UInt16
  vd_flags   : UInt16
  vd_ndx     : UInt16
  vd_cnt     : UInt16
  vd_hash    : UInt32
  vd_aux     : UInt32
  vd_next    : UInt32

elf_record Elf64_Verdaux where
  vda_name : UInt32
  vda_next : UInt32

/-- One *exported* version: the `Verdef` header plus the chain of
    `Verdaux` entries (typically 1; the first is the version name, any
    rest are predecessor / parent versions). -/
structure VerdefEntry where
  verdef : Elf64_Verdef
  auxes  : Array Elf64_Verdaux
  deriving Repr

instance : ToJsonStr VerdefEntry where
  toJsonStr e :=
    "{\"verdef\":" ++ toJsonStr e.verdef ++ ",\"auxes\":" ++ toJsonStr e.auxes ++ "}"

/-- Read one `Elf64_Verdef` at `off` and walk its `Verdaux` chain. -/
private def readOneVerdef (file : ByteArray) (off : Nat) : Except String VerdefEntry := do
  let verdef ← Elf64_Verdef.parse (file.extract off (off + Elf64_Verdef.size))
  let mut auxes := Array.mkEmpty verdef.vd_cnt.toNat
  let mut auxOff := off + verdef.vd_aux.toNat
  for _ in [0:verdef.vd_cnt.toNat] do
    let aux ← Elf64_Verdaux.parse (file.extract auxOff (auxOff + Elf64_Verdaux.size))
    auxes := auxes.push aux
    if aux.vda_next = 0 then break
    auxOff := auxOff + aux.vda_next.toNat
  return { verdef, auxes }

/-- `.gnu.version_d` — chain of Verdef entries via `DT_VERDEF` + `DT_VERDEFNUM`. -/
def parseVerdefs (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array VerdefEntry)) := do
  let some addr := lookupDtag dyn (.other 0x6ffffffc)             -- DT_VERDEF
    | return none
  let some num := lookupDtag dyn (.other 0x6ffffffd)              -- DT_VERDEFNUM
    | throw "DT_VERDEF present but no DT_VERDEFNUM"
  let some off := Elf64_Phdr.virtualToFileOffset phdrs addr.toNat
    | throw s!"DT_VERDEF vaddr={addr.toNat} not in any PT_LOAD segment"
  let mut entries := Array.mkEmpty num.toNat
  let mut cur := off
  for _ in [0:num.toNat] do
    let entry ← readOneVerdef file cur
    entries := entries.push entry
    if entry.verdef.vd_next = 0 then break
    cur := cur + entry.verdef.vd_next.toNat
  return some entries

-- ── Versym ↔ Verneed/Verdef cross-validation ───────────────────────

/-- Collect every version-index a Verneed table provides (via its
    `Vernaux.vna_other` fields — that's the index Versym will reference). -/
def verneedIndices (entries : Array VerneedEntry) : Array UInt16 :=
  entries.flatMap fun e => e.auxes.map fun a => a.vna_other

/-- Collect every version-index a Verdef table provides (via the
    `Verdef.vd_ndx` field). -/
def verdefIndices (entries : Array VerdefEntry) : Array UInt16 :=
  entries.map fun e => e.verdef.vd_ndx

/-- Cross-check: every `versym[i]` (low 15 bits) must be `VER_NDX_LOCAL`,
    `VER_NDX_GLOBAL`, or appear in the Verneed/Verdef tables. Returns
    the (symIndex, badVersionIndex) pairs that fail to resolve. Empty
    array = all symbols' versions are accounted for. -/
def unresolvedVersyms
    (versym : Array UInt16)
    (verneed? : Option (Array VerneedEntry))
    (verdef? : Option (Array VerdefEntry)) :
    Array (Nat × UInt16) := Id.run do
  let needed := (verneed?.getD #[]).flatMap (·.auxes.map (·.vna_other))
  let defined := (verdef?.getD #[]).map (·.verdef.vd_ndx)
  let pool := needed ++ defined
  let mut bad : Array (Nat × UInt16) := #[]
  for i in [0:versym.size] do
    let v := Versym.index versym[i]!
    if v = VER_NDX_LOCAL ∨ v = VER_NDX_GLOBAL then continue
    if ¬ pool.contains v then
      bad := bad.push (i, v)
  return bad

end WhatTheElf
