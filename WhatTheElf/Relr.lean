/-
DT_RELR — compact relative relocations (glibc 2.36+, gabi addendum).

Standard DT_RELA entries are 24 bytes each. For PIE binaries, the vast
majority of relocations are R_X86_64_RELATIVE: same type, sequential
addresses, addend = load_base + symbol_value(0). That's 24 bytes/reloc
to encode "add load_base at this address". DT_RELR compresses this to
about 1 bit per reloc.

Encoding (8-byte entries, little-endian Elf64_Relr):

  * Even entry (low bit = 0): an absolute virtual address. The runtime
    applies one relative reloc there and remembers this as the base.
  * Odd entry (low bit = 1): a bitmap. Bits 1..63 each cover one 8-byte
    slot starting at `base + 8`. For each set bit, apply a relative reloc
    at that offset. Bit 1 = `base + 8`, bit 2 = `base + 16`, …, bit 63 =
    `base + 504`. After applying, advance base by 63 * 8 = 504 bytes —
    so a subsequent bitmap entry covers the next 504-byte window.

Located via `DT_RELR` (vaddr), `DT_RELRSZ` (size in bytes), and
`DT_RELRENT` (gabi-required to be 8).

Spec gotcha: there is no separate `r_type` field. Every reloc DT_RELR
emits is implicitly relative (the equivalent of R_X86_64_RELATIVE on
x86_64, R_AARCH64_RELATIVE on aarch64). The expansion is therefore
fully described by the address list.
-/

import WhatTheElf.Basic
import WhatTheElf.ProgramHeader
import WhatTheElf.Dynamic

namespace WhatTheElf

/-- One raw entry from a `DT_RELR` table — either an address (sets the
    base; emits one reloc there) or a bitmap (emits 0..63 relocs at
    offsets `base + 8`, `base + 16`, …). -/
inductive RelrEntry where
  | addr   (a : Addr)
  | bitmap (bits : UInt64)
  deriving Repr

instance : ToJsonStr RelrEntry where
  toJsonStr
    | .addr   a => "{\"kind\":\"addr\",\"value\":"   ++ toJsonStr a ++ "}"
    | .bitmap b => "{\"kind\":\"bitmap\",\"value\":" ++ toJsonStr b ++ "}"

/-- Classify a raw `UInt64` entry: low bit = 1 ⇒ bitmap, else address. -/
private def decodeRelrEntry (raw : UInt64) : RelrEntry :=
  if raw &&& 1 = 1 then .bitmap raw else .addr raw

private def readU64le (file : ByteArray) (off : Nat) : Except String UInt64 := do
  if off + 8 > file.size then
    throw s!"DT_RELR: short read, need 8 bytes at off={off}, file size {file.size}"
  let c := Cursor.ofBytes (file.extract off (off + 8))
  match c.u64le with
  | .ok (v, _) => .ok v
  | .error e   => .error e

/-- Read every `DT_RELR` entry into the typed sum form. `DT_RELRENT` is
    required to be 8 by gabi; we enforce that. -/
def parseRelr (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option (Array RelrEntry)) := do
  let some addr := lookupDtag dyn .dt_relr
    | return none
  let some size := lookupDtag dyn .dt_relrsz
    | throw "DT_RELR present but no DT_RELRSZ"
  let entSize := (lookupDtag dyn .dt_relrent).getD 8
  if entSize ≠ 8 then
    throw s!"DT_RELRENT={entSize.toNat}, gabi requires 8"
  let some off := Elf64_Phdr.virtualToFileOffset phdrs addr.toNat
    | throw s!"DT_RELR vaddr={addr.toNat} not in any PT_LOAD segment"
  let count := size.toNat / 8
  let mut out := Array.mkEmpty count
  for i in [0:count] do
    let raw ← readU64le file (off + i * 8)
    out := out.push (decodeRelrEntry raw)
  return some out

/-- Expand a parsed `DT_RELR` table to the full list of relative-reloc
    target addresses. Each `.addr a` emits `a`; each subsequent
    `.bitmap bits` walks bits 1..63 and emits `base + i*8` for each set
    bit, then advances `base` by `63 * 8 = 504`. Returns an error if the
    first entry is a bitmap (no base address established). -/
def expandRelr (entries : Array RelrEntry) : Except String (Array Addr) := do
  let mut out : Array Addr := #[]
  let mut base : Addr := 0
  let mut started := false
  for e in entries do
    match e with
    | .addr a =>
      out := out.push a
      base := a + 8
      started := true
    | .bitmap bits =>
      if ¬ started then
        throw "DT_RELR starts with a bitmap entry — no base address set"
      for i in [1:64] do
        if (bits >>> i.toUInt64) &&& 1 = 1 then
          out := out.push (base + (i.toUInt64 - 1) * 8)
      base := base + 63 * 8
  return out

end WhatTheElf
