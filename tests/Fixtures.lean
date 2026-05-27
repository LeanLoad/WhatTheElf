/-
Fixtures for round-trip and negative testing.

We generate ELF bytes from typed values via the macro-emitted `Raw.write`
serializers. Both good and bad fixtures share one API:

  * `baselineRawEhdr` / `baselineRawPhdr` / `baselineRawDyn` — minimal
    *valid* Raw values (parse cleanly through our pipeline).
  * `Elf64Layout` — composite: ehdr + phdrs + arbitrary byte extras at
    chosen offsets. `serialize` lays them out into one `ByteArray`.
  * `Test.{expectOk, expectErr}` — assertions on `Elf64_File.parse`.

A negative test is just "baseline + one Raw field overridden + serialize":

    expectErr "EiClass"
      (RawElf64_Ehdr.write { baselineRawEhdr with ei_class := 99 })

A positive test is "serialize a baseline and assert ok":

    expectOk (RawElf64_Ehdr.write baselineRawEhdr)

Because field names + types are checked by Lean, mutations that wouldn't
even be expressible in a real ELF (e.g. wrong-width values, typo'd field
names) fail to compile rather than producing silently-wrong bytes.
-/

import WhatTheElf

namespace WhatTheElf.Test

-- ── Raw baselines (minimal *valid* values) ──────────────────────────

/-- An ehdr that satisfies every parser invariant: x86_64 dynamic exec,
    class64 + lsb, ev_current, e_phoff at 64 with e_phnum=0 (no phdrs). -/
def baselineRawEhdr : RawElf64_Ehdr := {
  ei_magic    := 0x464c457f
  ei_class    := 2
  ei_data     := 1
  ei_version  := 1
  ei_osabi    := 0
  ei_abiver   := 0
  ei_pad      := ByteArray.mk (Array.replicate 7 0)
  e_type      := 3        -- ET_DYN
  e_machine   := 62       -- EM_X86_64
  e_version   := 1
  e_entry     := 0
  e_phoff     := 64
  e_shoff     := 0
  e_flags     := 0
  e_ehsize    := 64
  e_phentsize := 56
  e_phnum     := 0
  e_shentsize := 0
  e_shnum     := 0
  e_shstrndx  := 0
}

/-- A PT_NULL phdr — meaningless but well-formed. -/
def baselineRawPhdr : RawElf64_Phdr := {
  p_type   := 0
  p_flags  := 0
  p_offset := 0
  p_vaddr  := 0
  p_paddr  := 0
  p_filesz := 0
  p_memsz  := 0
  p_align  := 0
}

/-- A dynamic-table entry from raw tag/value. -/
def baselineRawDyn (d_tag d_un : UInt64) : RawElf64_Dyn :=
  { d_tag := d_tag, d_un := d_un }

/-- A null (SHT_NULL) shdr — meaningless content but well-formed bytes. -/
def baselineRawShdr : RawElf64_Shdr := {
  sh_name      := 0
  sh_type      := 0
  sh_flags     := 0
  sh_addr      := 0
  sh_offset    := 0
  sh_size      := 0
  sh_link      := 0
  sh_info      := 0
  sh_addralign := 0
  sh_entsize   := 0
}

-- ── Composite layout ────────────────────────────────────────────────

/-- A pasted-together ELF: ehdr at offset 0, phdrs immediately after, then
    optional extra byte regions placed at given file offsets. The builder
    does NOT validate that `extras` offsets are consistent with phdr fields
    — that's the caller's job (and the point, for dynamic-section tests). -/
structure Elf64Layout where
  ehdr   : RawElf64_Ehdr           := baselineRawEhdr
  phdrs  : Array RawElf64_Phdr     := #[]
  extras : Array (Nat × ByteArray) := #[]

/-- Render the layout to bytes. ehdr at 0, phdrs concatenated at
    `ehdr.e_phoff`, and each `(off, bs)` extra spliced at `off` (zero-padded
    in between as needed). -/
def Elf64Layout.serialize (l : Elf64Layout) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  -- ehdr
  out := out ++ RawElf64_Ehdr.write l.ehdr
  -- pad to e_phoff if needed
  let phOff := l.ehdr.e_phoff.toNat
  while out.size < phOff do out := out.push 0
  -- phdrs
  for p in l.phdrs do
    out := out ++ RawElf64_Phdr.write p
  -- extras
  for (off, bs) in l.extras do
    while out.size < off do out := out.push 0
    out := out ++ bs
  return out

-- ── Assertion helpers ───────────────────────────────────────────────

/-- Substring check via `splitOn` (1 chunk = no occurrence, ≥2 = match). -/
private def String.containsSub (s sub : String) : Bool :=
  (s.splitOn sub).length > 1

/-- Did the file parse cleanly? -/
def expectOk (bs : ByteArray) : Bool :=
  match Elf64_File.parse bs with
  | .ok _    => true
  | .error _ => false

/-- Did the file fail with an error whose message contains `sub`? -/
def expectErr (sub : String) (bs : ByteArray) : Bool :=
  match Elf64_File.parse bs with
  | .error e => String.containsSub e sub
  | .ok _    => false

-- ── Dynamic-section composite builder ──────────────────────────────

/-- Build an ELF with `PT_LOAD` covering `[loadVaddr, loadVaddr+loadFilesz)`
    and a `PT_DYNAMIC` whose segment holds the given dynamic entries. The
    PT_LOAD's file image starts right after the phdr table; the dynamic
    bytes are placed inside that file image at `dynVaddr` (relative to the
    load segment), so `virtualToFileOffset` finds them. Optional `extras`
    place additional `(vaddr, bytes)` blobs inside the same load segment —
    useful for stitching a malformed hash table, dummy symtab, etc. -/
def withDynamic
    (dynEntries : Array RawElf64_Dyn)
    (extras : Array (Nat × ByteArray) := #[])
    (dynVaddr loadVaddr : Nat := default)
    (loadFilesz : Nat := 0x1000) : ByteArray :=
  let dynVaddr := if dynVaddr = 0 then 0x800 else dynVaddr
  let phdrsStart := 64
  let phdrsEnd := phdrsStart + 2 * 56
  let segOff := phdrsEnd
  let dynOffInFile := segOff + (dynVaddr - loadVaddr)
  let dynBytes := dynEntries.foldl (fun b e => b ++ RawElf64_Dyn.write e) ByteArray.empty
  let ptLoad := { baselineRawPhdr with
                  p_type := 1, p_flags := 4
                  p_offset := segOff.toUInt64, p_vaddr := loadVaddr.toUInt64
                  p_paddr := loadVaddr.toUInt64
                  p_filesz := loadFilesz.toUInt64, p_memsz := loadFilesz.toUInt64
                  p_align := 0x1000 }
  let ptDynamic := { baselineRawPhdr with
                     p_type := 2, p_flags := 6
                     p_offset := dynOffInFile.toUInt64, p_vaddr := dynVaddr.toUInt64
                     p_paddr := dynVaddr.toUInt64
                     p_filesz := dynBytes.size.toUInt64
                     p_memsz := dynBytes.size.toUInt64
                     p_align := 8 }
  let segBytes := Id.run do
    let mut seg := ByteArray.mk (Array.replicate loadFilesz 0)
    let inseg := dynVaddr - loadVaddr
    for i in [0:dynBytes.size] do
      seg := seg.set! (inseg + i) dynBytes[i]!
    for (vaddr, bs) in extras do
      let off := vaddr - loadVaddr
      for i in [0:bs.size] do
        seg := seg.set! (off + i) bs[i]!
    return seg
  ({ ehdr   := { baselineRawEhdr with e_phnum := 2 }
   , phdrs  := #[ptLoad, ptDynamic]
   , extras := #[(segOff, segBytes)] } : Elf64Layout).serialize

-- ── Hash-table byte builders ────────────────────────────────────────

/-- Serialize a SysV `DT_HASH` table (`nbucket | nchain | buckets[] | chains[]`). -/
def dtHashBytes (nbucket nchain : UInt32)
    (buckets chains : Array UInt32) : ByteArray := Id.run do
  let mut bs := ByteArray.empty
    |>.pushUInt32LE nbucket
    |>.pushUInt32LE nchain
  for b in buckets do bs := bs.pushUInt32LE b
  for c in chains  do bs := bs.pushUInt32LE c
  return bs

/-- Serialize a GNU hash table header + body. -/
def gnuHashBytes (nbuckets symoffset bloom_size bloom_shift : UInt32)
    (bloom : Array UInt64) (buckets chains : Array UInt32) : ByteArray := Id.run do
  let mut bs := ByteArray.empty
    |>.pushUInt32LE nbuckets
    |>.pushUInt32LE symoffset
    |>.pushUInt32LE bloom_size
    |>.pushUInt32LE bloom_shift
  for w in bloom   do bs := bs.pushUInt64LE w
  for b in buckets do bs := bs.pushUInt32LE b
  for c in chains  do bs := bs.pushUInt32LE c
  return bs

-- ── Note builders ───────────────────────────────────────────────────

/-- Pad `bs` with trailing zeros to a 4-byte boundary (note alignment). -/
private def padTo4 (bs : ByteArray) : ByteArray := Id.run do
  let mut out := bs
  while out.size % 4 ≠ 0 do out := out.push 0
  return out

/-- Serialize a single note: 12-byte Nhdr (namesz/descsz/type) then the
    name (NUL-terminated, padded to 4) then the descriptor (padded to 4). -/
def noteBytes (name : String) (noteType : UInt32) (desc : ByteArray) : ByteArray :=
  let nameZ := name.toUTF8.push 0
  let nameSize := nameZ.size
  let descSize := desc.size
  let nhdr := ByteArray.empty
    |>.pushUInt32LE nameSize.toUInt32
    |>.pushUInt32LE descSize.toUInt32
    |>.pushUInt32LE noteType
  nhdr ++ padTo4 nameZ ++ padTo4 desc

/-- Build an ELF whose only segment is a `PT_NOTE` containing the given
    notes (one after another). Useful for testing note parsing without
    dragging in the rest of the dynamic-linking machinery. -/
def withNotes (notes : Array ByteArray) : ByteArray :=
  let phdrsOff   : Nat := 64
  let segOff     : Nat := phdrsOff + 56
  let segBytes   : ByteArray := notes.foldl (· ++ ·) ByteArray.empty
  let ptNote := { baselineRawPhdr with
                  p_type := 4            -- PT_NOTE
                  p_flags := 4           -- PF_R
                  p_offset := segOff.toUInt64
                  p_vaddr := segOff.toUInt64
                  p_paddr := segOff.toUInt64
                  p_filesz := segBytes.size.toUInt64
                  p_memsz := segBytes.size.toUInt64
                  p_align := 4 }
  ({ ehdr  := { baselineRawEhdr with e_phnum := 1 }
   , phdrs := #[ptNote]
   , extras := #[(segOff, segBytes)]
   } : Elf64Layout).serialize

/-- Synthesize a minimal *loadable* ELF that satisfies what glibc's
    `ld.so --verify` checks: a PT_LOAD spanning the file, a PT_DYNAMIC
    pointing to a dynamic table with the mandatory tags (DT_STRTAB,
    DT_STRSZ, DT_SYMTAB, DT_SYMENT, DT_HASH, DT_NULL), plus a single-bucket
    hash table, a 1-byte strtab, and a 24-byte undef-symbol entry.

    Total file size ≈ 313 bytes. ET_DYN with PIC layout so vaddr == file
    offset across the whole file. -/
def loadableElf : ByteArray :=
  let phdrsOff   : Nat := 64
  let dynOff     : Nat := phdrsOff + 2 * 56          -- 0xB0
  let hashOff    : Nat := dynOff + 6 * 16             -- 0x110
  let strtabOff  : Nat := hashOff + 16                -- 0x120
  let symtabOff  : Nat := strtabOff + 1               -- 0x121
  let fileSize   : Nat := symtabOff + 24              -- 0x139
  let dynEntries : Array RawElf64_Dyn := #[
    baselineRawDyn  5 strtabOff.toUInt64,  -- DT_STRTAB
    baselineRawDyn 10 1,                   -- DT_STRSZ
    baselineRawDyn  6 symtabOff.toUInt64,  -- DT_SYMTAB
    baselineRawDyn 11 24,                  -- DT_SYMENT
    baselineRawDyn  4 hashOff.toUInt64,    -- DT_HASH
    baselineRawDyn  0 0                    -- DT_NULL
  ]
  let dynBytes := dynEntries.foldl
    (fun b e => b ++ RawElf64_Dyn.write e) ByteArray.empty
  -- Hash table: { nbucket=1, nchain=1, buckets=[0], chains=[0] } — 16 bytes
  let hashBytes := ByteArray.empty
    |>.pushUInt32LE 1 |>.pushUInt32LE 1
    |>.pushUInt32LE 0 |>.pushUInt32LE 0
  let strtabBytes := ByteArray.mk #[0]
  let symtabBytes := ByteArray.mk (Array.replicate 24 0)
  let ptLoad := { baselineRawPhdr with
    p_type := 1            -- PT_LOAD
    p_flags := 6           -- PF_R | PF_W  (dynamic table needs write perm at load time)
    p_offset := 0, p_vaddr := 0, p_paddr := 0
    p_filesz := fileSize.toUInt64, p_memsz := fileSize.toUInt64
    p_align := 0x1000 }
  let ptDynamic := { baselineRawPhdr with
    p_type := 2            -- PT_DYNAMIC
    p_flags := 6           -- PF_R | PF_W
    p_offset := dynOff.toUInt64, p_vaddr := dynOff.toUInt64
    p_paddr := dynOff.toUInt64
    p_filesz := dynBytes.size.toUInt64, p_memsz := dynBytes.size.toUInt64
    p_align := 8 }
  ({ ehdr  := { baselineRawEhdr with e_phnum := 2 }
   , phdrs := #[ptLoad, ptDynamic]
   , extras := #[(dynOff, dynBytes), (hashOff, hashBytes),
                 (strtabOff, strtabBytes), (symtabOff, symtabBytes)]
   } : Elf64Layout).serialize

end WhatTheElf.Test
