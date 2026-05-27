/-
ELF notes (`.note.*` sections / `PT_NOTE` segments).

Per gabi 09 § Note Section, a note is a variable-length record:

  Elf64_Word n_namesz;  // 4 — length of name including null
  Elf64_Word n_descsz;  // 4 — length of descriptor
  Elf64_Word n_type;    // 4 — type tag (interpretation depends on name)
  char       n_name[];  // namesz bytes, then padded to 4-byte boundary
  char       n_desc[];  // descsz bytes, then padded to 4-byte boundary

A PT_NOTE segment can contain multiple notes concatenated. The type's
meaning depends on the name string:

  name = "GNU"   → NT_GNU_ABI_TAG (1), NT_GNU_HWCAP (2),
                   NT_GNU_BUILD_ID (3), NT_GNU_PROPERTY_TYPE_0 (5)
  name = "CORE"  → core-dump types (status, fpregs, …)
  name = "Linux" → linux-specific
  …

We don't interpret descriptors; we expose `(name, type, desc bytes)` triples
and let downstream code do per-name-and-type interpretation.
-/

import WhatTheElf.Basic
import WhatTheElf.ProgramHeader

namespace WhatTheElf

/-- One parsed note: name as UTF-8 string (with trailing null stripped),
    type tag, and raw descriptor bytes. -/
structure Note where
  name : String
  type : UInt32
  desc : ByteArray
  deriving Repr

instance : ToJsonStr Note where
  toJsonStr n :=
    "{\"name\":" ++ toJsonStr n.name ++
    ",\"type\":" ++ toJsonStr n.type ++
    ",\"desc\":" ++ toJsonStr n.desc ++ "}"

/-- Round `n` up to the next multiple of 4 (note alignment). -/
private def alignUp4 (n : Nat) : Nat := ((n + 3) / 4) * 4

/-- Is `b` a printable-ASCII byte (0x21..0x7e)? Note names are conventionally
    ASCII identifiers like `GNU`, `CORE`, `stapsdt`, `Linux`; nothing in
    gabi rules out other bytes but every name in the wild is printable
    ASCII. We enforce that and surface a structured error so a binary
    that smuggles raw bytes through a name field is rejected rather than
    decoded into mojibake. -/
private def isPrintableAscii (b : UInt8) : Bool :=
  0x21 ≤ b ∧ b ≤ 0x7e

/-- Parse a sequence of notes from a `PT_NOTE` segment's bytes. Each note's
    name and descriptor are 4-byte-aligned per gabi. Stops cleanly at the
    end of the buffer; errors on a truncated note in the middle. -/
def parseNotesInSegment (bytes : ByteArray) : Except String (Array Note) := do
  let mut out : Array Note := #[]
  let mut pos : Nat := 0
  -- A loop bound of `bytes.size` is loose-but-safe: each iteration consumes
  -- ≥ 12 bytes, so we can't iterate more than `bytes.size / 12` + 1 times.
  for _ in [0:bytes.size + 1] do
    if pos = bytes.size then break
    if pos + 12 > bytes.size then
      throw s!"note: truncated header at offset {pos} (have {bytes.size - pos}/12 bytes)"
    let cur := Cursor.ofBytes (bytes.extract pos bytes.size)
    let (namesz, cur) ← cur.u32le
    let (descsz, cur) ← cur.u32le
    let (type,   _  ) ← cur.u32le
    let nameStart := pos + 12
    let nameEnd   := nameStart + namesz.toNat
    let descStart := pos + 12 + alignUp4 namesz.toNat
    let descEnd   := descStart + descsz.toNat
    if descEnd > bytes.size then
      throw s!"note: truncated body at offset {pos} (claims {nameEnd - nameStart} name + {descEnd - descStart} desc bytes, only {bytes.size - nameStart} available)"
    -- Name: strip trailing null if present.
    let rawName := bytes.extract nameStart nameEnd
    let nameBytes :=
      if rawName.size > 0 ∧ rawName[rawName.size - 1]! = 0
      then rawName.extract 0 (rawName.size - 1)
      else rawName
    -- gabi convention: note names are printable ASCII identifiers
    -- (GNU, CORE, stapsdt, Linux, …). Reject anything else.
    for i in [0:nameBytes.size] do
      let b := nameBytes[i]!
      unless isPrintableAscii b do
        throw s!"note: name at offset {nameStart} has non-printable byte 0x{String.ofList (Nat.toDigits 16 b.toNat)} at index {i}"
    let some nameStr := String.fromUTF8? nameBytes
      | throw s!"note: name at offset {nameStart} is not valid UTF-8"
    let desc := bytes.extract descStart descEnd
    out := out.push { name := nameStr, type, desc }
    pos := descStart + alignUp4 descsz.toNat
  return out

/-- Parse every `PT_NOTE` segment in the file as a flat array of notes.
    Returns `none` if no `PT_NOTE` phdr exists. Multiple PT_NOTE segments
    are concatenated in phdr-table order. -/
def parseNotes (file : ByteArray) (phdrs : Array Elf64_Phdr) :
    Except String (Option (Array Note)) := do
  let noteSegments := phdrs.filter fun p =>
    match p.p_type with | .pt_note => true | _ => false
  if noteSegments.isEmpty then return none
  let mut all : Array Note := #[]
  for p in noteSegments do
    let segBytes := p.segment file
    let notes ← parseNotesInSegment segBytes
    all := all ++ notes
  return some all

end WhatTheElf
