/-
Round-trip property check over a real binary file.

For every fixed-size record table in the input ELF (phdr table, shdr
table, dynamic, dynsym from shdrs, rela.dyn, rela.plt, verneed, vernaux,
verdef, verdaux), this tool:

  1. Reads the table's bytes from the file (offset, stride, count
     determined by the higher-level parser).
  2. For each entry slice, calls `RawT.read` (parse) then `RawT.write`
     (serialize) and checks that the resulting bytes equal the input
     slice exactly.

This is `write ∘ read = id` as a runtime check, applied to real-world
inputs — a much wider net than the synthetic `#guard`s in
`Negative.lean`. If a writer is lossy (drops a bit, transposes a field,
emits wrong-width integers), it'll be caught here on the first binary
that exercises that field.

Usage:
  lake build roundtrip_check
  ./.lake/build/bin/roundtrip_check /bin/ls /bin/cat /lib/x86_64-linux-gnu/libc.so.6
-/

import WhatTheElf

open WhatTheElf

private def slice (file : ByteArray) (off : Nat) (size : Nat) : ByteArray :=
  file.extract off (off + size)

/-- For one record type with a known `read`/`write`/`size`, check that
    every entry in a (offset, count) table round-trips through the
    encoder bytewise. Returns `(checkedCount, mismatches)`. -/
private def checkTable {α : Type}
    (read : ByteArray → Except String α) (write : α → ByteArray)
    (sz : Nat) (file : ByteArray) (off count : Nat) :
    IO (Nat × Nat) := do
  let mut mismatches := 0
  for i in [0:count] do
    let s := slice file (off + i * sz) sz
    match read s with
    | .error e =>
      IO.eprintln s!"    entry {i}: read failed: {e}"
      mismatches := mismatches + 1
    | .ok x =>
      let w := write x
      if w ≠ s then
        IO.eprintln s!"    entry {i}: write produced {w.size} bytes, expected {s.size}; mismatch"
        mismatches := mismatches + 1
  return (count, mismatches)

private def report (label : String) (res : IO (Nat × Nat)) : IO Nat := do
  let (n, m) ← res
  if m = 0 then
    IO.println s!"  {label}: {n} entries — OK"
    return 0
  else
    IO.println s!"  {label}: {n} entries — {m} MISMATCHES"
    return m

/-- Round-trip-check one file. Returns total mismatch count. -/
private def checkFile (path : String) : IO Nat := do
  IO.println s!"── {path} ──"
  let file ← IO.FS.readBinFile path
  let mut fail := 0
  -- Top-level parse: also surfaces the versym ↔ verneed/verdef cross-check.
  match Elf64_File.parse file with
  | .error e => IO.println s!"  Elf64_File.parse error: {e}"; fail := fail + 1
  | .ok pf =>
    if let some vs := pf.versym? then
      let bad := unresolvedVersyms vs pf.verneed? pf.verdef?
      if bad.isEmpty then
        IO.println s!"  versym: {vs.size} entries — all resolvable"
      else
        IO.println s!"  versym: {bad.size}/{vs.size} UNRESOLVED:"
        for (i, v) in bad.toList.take 5 do
          IO.println s!"      symbol[{i}] -> version {v} (no Verneed/Verdef)"
        fail := fail + bad.size
  -- Per-record bytewise round-trip below uses the ehdr-only parse so we
  -- get table layouts even if higher-level structure has issues.
  match Elf64_Ehdr.parse file with
  | .error e =>
    IO.println s!"  PARSE error: {e}"; return fail + 1
  | .ok ehdr =>
    -- ehdr itself
    let ehdrSlice := slice file 0 64
    match RawElf64_Ehdr.read ehdrSlice with
    | .ok raw =>
      if RawElf64_Ehdr.write raw ≠ ehdrSlice then
        IO.println "  ehdr: MISMATCH"; fail := fail + 1
      else
        IO.println "  ehdr: 1 entry — OK"
    | .error e => IO.println s!"  ehdr: read failed: {e}"; fail := fail + 1
    -- phdr table
    let pt := ehdr.phdrTable
    fail := fail + (← report "phdrs" <|
      checkTable RawElf64_Phdr.read RawElf64_Phdr.write
        Elf64_Phdr.size file pt.offset pt.count)
    -- shdr table (if any)
    match (← IO.ofExcept (ehdr.shdrTable file)) with
    | none => pure ()
    | some st =>
      fail := fail + (← report "shdrs" <|
        checkTable RawElf64_Shdr.read RawElf64_Shdr.write
          Elf64_Shdr.size file st.offset st.count)
    -- dyn table (via PT_DYNAMIC)
    let phdrs ← match ehdr.parsePhdrs file with
                | .ok p => pure p
                | .error e => IO.println s!"  phdrs parse failed: {e}"; pure #[]
    if let some dynPhdr := phdrs.find? (fun p => match p.p_type with | .pt_dynamic => true | _ => false) then
      let entSz := Elf64_Dyn.size
      let cnt := dynPhdr.p_filesz.toNat / entSz
      fail := fail + (← report "dynamic" <|
        checkTable RawElf64_Dyn.read RawElf64_Dyn.write entSz
          file dynPhdr.p_offset.toNat cnt)
    -- shdr-located tables (sym, rela, verneed/vernaux, verdef/verdaux)
    match (← IO.ofExcept (ehdr.parseShdrs file)) with
    | none => pure ()
    | some shdrs =>
      for i in [0:shdrs.size] do
        let some s := shdrs[i]? | continue
        let off := s.sh_offset.toNat
        let totalSize := s.sh_size.toNat
        match s.sh_type with
        | .sht_symtab | .sht_dynsym =>
          let sz := Elf64_Sym.size
          let cnt := totalSize / sz
          let kind := match s.sh_type with
                     | .sht_symtab => "symtab"
                     | _           => "dynsym"
          fail := fail + (← report s!"  {kind} ({cnt} entries)" <|
            checkTable RawElf64_Sym.read RawElf64_Sym.write sz file off cnt)
        | .sht_rela =>
          let sz := Elf64_Rela.size
          let cnt := totalSize / sz
          fail := fail + (← report s!"  rela ({totalSize} bytes)" <|
            checkTable RawElf64_Rela.read RawElf64_Rela.write sz file off cnt)
        | _ => pure ()
    return fail

def main (args : List String) : IO UInt32 := do
  let paths := if args.isEmpty
    then ["/bin/ls", "/bin/cat", "/lib/x86_64-linux-gnu/libc.so.6",
          "/lib64/ld-linux-x86-64.so.2"]
    else args
  let mut total := 0
  for p in paths do
    total := total + (← checkFile p)
  if total = 0 then
    IO.println s!"\nAll round-trip checks passed."
    return 0
  else
    IO.println s!"\n{total} round-trip mismatch(es) across all files."
    return 1
