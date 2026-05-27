/-
ELF string table (`.dynstr` / `.strtab`).

A string table is a flat byte buffer holding null-terminated UTF-8 strings,
indexed by byte offset. Index 0 always contains the empty string. Strings
may share storage (e.g. `"foo"` and `"oo"` can both live at offsets 0 and 1
of the bytes `"foo\0"`); the table doesn't enumerate "the strings", only
"a string at offset N".

Located via `DT_STRTAB` (address) + `DT_STRSZ` (size in bytes) in the
dynamic table — both gabi-mandatory for dynamically-linked objects.
-/

import WhatTheElf.Basic
import WhatTheElf.ProgramHeader
import WhatTheElf.Dynamic

namespace WhatTheElf

/-- A string table — opaque bytes plus the lookup operations on them. -/
structure Strtab where
  bytes : ByteArray
  deriving Repr

/-- The underlying byte buffer (alias for legibility at call sites). -/
abbrev Strtab.data (s : Strtab) : ByteArray := s.bytes

/-- Walk forward from `start` until the next null byte (or end-of-buffer);
    returns the index of that byte. -/
private partial def findNull (b : ByteArray) (start : Nat) : Nat :=
  if start ≥ b.size then start
  else if b[start]! = 0 then start
  else findNull b (start + 1)

/-- Read the null-terminated string at `offset`. Returns `none` if `offset`
    is past the end of the buffer or the bytes don't decode as UTF-8. -/
def Strtab.lookupAt (s : Strtab) (offset : Nat) : Option String :=
  if offset ≥ s.bytes.size then none
  else String.fromUTF8? (s.bytes.extract offset (findNull s.bytes offset))

/-- Enumerate every "maximal chunk" — the string starting after each null
    boundary up to the next null. Useful as a JSON-friendly summary of
    what's in the table.

    NOTE: per gabi, offsets may point *anywhere* into the table (suffix
    sharing is explicitly permitted: a chunk `"libfoo.so"` at offset 10
    can be aliased as `"foo.so"` at offset 13). This enumeration only
    returns the maximal chunks and so will MISS suffix-shared aliases.
    Callers holding an explicit offset (e.g. `st_name`, `DT_NEEDED`)
    should always use `lookupAt`. -/
def Strtab.strings (s : Strtab) : Array (Nat × String) := Id.run do
  let mut out : Array (Nat × String) := #[]
  let mut start : Nat := 0
  for i in [0:s.bytes.size] do
    if s.bytes[i]! = 0 then
      if let some str := String.fromUTF8? (s.bytes.extract start i) then
        out := out.push (start, str)
      start := i + 1
  return out

instance : ToJsonStr Strtab where
  toJsonStr s :=
    "[" ++ String.intercalate ","
      (s.strings.toList.map fun (off, str) =>
        "{\"offset\":" ++ toJsonStr off ++ ",\"value\":" ++ toJsonStr str ++ "}")
    ++ "]"

/-- Locate the `.dynstr` from a parsed dynamic table:
    `DT_STRTAB` (vaddr) + `DT_STRSZ` (size in bytes). Returns `none` if
    `DT_STRTAB` is absent; errors if it's present but `DT_STRSZ` is missing
    or the vaddr doesn't fall in any `PT_LOAD` segment. -/
def parseStrtab (file : ByteArray) (phdrs : Array Elf64_Phdr) (dyn : Array Elf64_Dyn) :
    Except String (Option Strtab) := do
  let some addr := lookupDtag dyn .dt_strtab
    | return none
  let some size := lookupDtag dyn .dt_strsz
    | throw "DT_STRTAB present but no DT_STRSZ"
  let some off := Elf64_Phdr.virtualToFileOffset phdrs addr.toNat
    | throw s!"DT_STRTAB vaddr={addr.toNat} not in any PT_LOAD segment"
  return some { bytes := file.extract off (off + size.toNat) }

end WhatTheElf
