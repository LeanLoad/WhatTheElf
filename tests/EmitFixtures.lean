/-
Emit fixture ELFs to a directory plus a JSON manifest describing each
fixture's name and our parser's expected verdict. The companion
`tests/differential.py` runner feeds them to other ELF parsers (glibc
`ld.so --verify`, `readelf`, `llvm-readelf`, `file`, `objdump`) and
tabulates agreement.

  lake build emit_fixtures
  ./.lake/build/bin/emit_fixtures fixtures_out/
  python3 tests/differential.py fixtures_out/
-/

import Fixtures

open WhatTheElf
open WhatTheElf.Test

/-- A single test fixture: a stable name, the bytes (or `none` to mean
    "read this real binary at emit time"), our parser's expected verdict,
    and a category that classifies *why* it's malformed (or that it's a
    positive control). -/
structure Fixture where
  name       : String
  bytes      : Option ByteArray   -- `none` ⇒ read `realPath` at emit time
  realPath   : Option String      -- only used if `bytes := none`
  ourVerdict : Bool
  category   : String

private def synth (name : String) (bs : ByteArray)
    (ourVerdict : Bool := false) (category : String := "structural") : Fixture :=
  { name, bytes := some bs, realPath := none, ourVerdict, category }

private def real (name : String) (path : String) : Fixture :=
  { name, bytes := none, realPath := some path, ourVerdict := true,
    category := "real_binary" }

/-- Build a "decode-failure" fixture by setting one ehdr field to its
    macro-emitted `invalidRaw` value. The `bad?` argument is the enum's
    `Option <baseTy>` companion — `none` means the enum is open and we
    skip emitting (no value decodes-failure-causes for open enums).

    This is the one-thing-at-a-time pattern specialized to closed-enum
    decode failures: each fixture mutates exactly one field, to a value
    the macro guarantees the decoder will reject. -/
private def decodeOf {α : Type} (name : String) (bad? : Option α)
    (override : RawElf64_Ehdr → α → RawElf64_Ehdr) : Fixture :=
  match bad? with
  | none => { name := name ++ "_skipped_open_enum"
            , bytes := none, realPath := none
            , ourVerdict := true, category := "skipped" }
  | some bad =>
    { name, bytes := some (RawElf64_Ehdr.write (override baselineRawEhdr bad))
    , realPath := none, ourVerdict := false, category := "decode" }

/-- Policy fixtures: one per invariant in `Elf64_Ehdr.invariantViolators`
    (macro-emitted from the spec). Each is a one-field override that
    breaks exactly that invariant; the resulting error message contains
    `"constraint '<name>' violated"`. -/
private def policyFixtures : List Fixture :=
  Elf64_Ehdr.invariantViolators.mapIdx fun i p =>
    let (name, override) := p
    synth s!"{30 + i}_violate_{name}"
      (RawElf64_Ehdr.write (override baselineRawEhdr)) false "policy"

/-- Truncation fixtures: one per ehdr field, truncating the file to just
    before that field starts. Field offsets come from the macro-emitted
    `Elf64_Ehdr.fieldOffsets`. Each fixture exercises a different
    short-read site in `RawElf64_Ehdr.read`; all should error.
    `truncate_before_ei_magic` is byte-length 0 (the empty file). -/
private def truncationFixtures : List Fixture :=
  let baseBytes := RawElf64_Ehdr.write baselineRawEhdr
  Elf64_Ehdr.fieldOffsets.mapIdx fun i p =>
    let (fieldName, off) := p
    synth s!"{70 + i}_truncate_before_{fieldName}"
      (baseBytes.extract 0 off) false "truncation"

/-- Phdr-table truncation fixtures: ehdr declares 1 phdr (so the parser
    walks the table) but the file is truncated to `64 + off` bytes for
    each phdr-field offset `off`. Exercises `parseTable` short-read paths
    on `RawElf64_Phdr.read`. Field offsets come from `Elf64_Phdr.fieldOffsets`. -/
private def phdrTruncationFixtures : List Fixture :=
  let ehdrBytes := RawElf64_Ehdr.write { baselineRawEhdr with e_phnum := 1 }
  let phdrBytes := RawElf64_Phdr.write baselineRawPhdr
  let fullBytes := ehdrBytes ++ phdrBytes
  Elf64_Phdr.fieldOffsets.mapIdx fun i p =>
    let (fieldName, off) := p
    synth s!"{90 + i}_truncate_phdr_before_{fieldName}"
      (fullBytes.extract 0 (64 + off)) false "truncation"

/-- Shdr-table truncation fixtures: ehdr declares 1 shdr (so the parser
    reads the table) placed immediately after the ehdr; the file is
    truncated to `64 + off` bytes for each shdr-field offset `off`.
    Exercises `parseTable` short-read paths on `RawElf64_Shdr.read`.
    Field offsets come from `Elf64_Shdr.fieldOffsets`. -/
private def shdrTruncationFixtures : List Fixture :=
  let ehdr := { baselineRawEhdr with
                e_shoff := 64, e_shentsize := 64, e_shnum := 1 }
  let ehdrBytes := RawElf64_Ehdr.write ehdr
  let shdrBytes := RawElf64_Shdr.write baselineRawShdr
  let fullBytes := ehdrBytes ++ shdrBytes
  Elf64_Shdr.fieldOffsets.mapIdx fun i p =>
    let (fieldName, off) := p
    synth s!"{100 + i}_truncate_shdr_before_{fieldName}"
      (fullBytes.extract 0 (64 + off)) false "truncation"

/-- Representative subset of `tests/Negative.lean` — one fixture per error
    category, plus positive controls. Numeric prefix keeps the directory
    listing in a predictable order. -/
def fixtures : List Fixture :=
  let ehdr := baselineRawEhdr
  let head : List Fixture := [
    -- synthetic positive controls
    synth "01_valid_minimum"      (({} : Elf64Layout).serialize) true "positive"
  , synth "02_valid_with_phdr"
      (({ ehdr := { ehdr with e_phnum := 1 }
        , phdrs := #[baselineRawPhdr] } : Elf64Layout).serialize) true "positive"
  , synth "03_valid_dynamic_null" (withDynamic #[baselineRawDyn 0 0]) true "positive"
  -- Synthetic minimal "loadable" ELF (PT_LOAD R+W, PT_DYNAMIC with the
  -- mandatory tags + hash + strtab + symtab). Our parser accepts it.
  -- glibc's `ld.so --verify` curiously returns 2 here; we suspect it
  -- requires additional features (DT_GNU_HASH, version tables) that aren't
  -- listed as mandatory in gabi but are gated by glibc's loader.
  , synth "04_loadable_minimal"   loadableElf true "positive"
  -- A real, system-confirmed-loadable binary (glibc verifies it).
  , real  "05_real_bin_true"      "/bin/true"
  -- Larger real binaries — more varied positive controls.
  , real  "06_real_bin_cat"       "/bin/cat"
  , real  "07_real_ld_linux"      "/lib64/ld-linux-x86-64.so.2"

    -- structural: malformed at the byte level, everyone should reject.
    -- Truncation cases are auto-generated via `Elf64_Ehdr.fieldOffsets`
    -- (see `truncationFixtures` below); this block keeps the cases that
    -- aren't simple field-truncations.
  , synth "12_bad_magic"          (RawElf64_Ehdr.write { ehdr with ei_magic := 0 })
  , synth "13_phdr_offset_oob"
      (RawElf64_Ehdr.write { ehdr with e_phoff := 10000, e_phnum := 1 })
  -- e_phnum = MAX with default e_phoff=64: parseTable tries 65535 reads
  -- of 56 bytes each, exhausts the file after a few entries.
  , synth "14_e_phnum_max"
      (RawElf64_Ehdr.write { ehdr with e_phnum := 65535 })
  -- e_phoff = 0 with e_phnum=1 means phdrs OVERLAP the ehdr. gabi doesn't
  -- explicitly forbid this but glibc rejects (unloadable, phdr reads pull
  -- ehdr bytes). We added invariant `phdrs_after_ehdr` to enforce it,
  -- driven by this fixture's differential finding against glibc.
  , synth "15_phdr_overlaps_ehdr"
      (RawElf64_Ehdr.write { ehdr with e_phoff := 0, e_phnum := 1 })
      false "policy"
  -- e_shnum / e_shoff nonzero but shdr table is at offset 99999 (off the end).
  -- Our shdr parser reads the table and rejects on the out-of-range read.
  , synth "16_bogus_shnum"
      (RawElf64_Ehdr.write { ehdr with e_shoff := 99999, e_shnum := 99 })
      false "structural"
  -- e_shstrndx points to a shdr whose sh_type ≠ SHT_STRTAB. We reject
  -- with a specific error before any string-lookup; cf. parseShstrtab.
  -- Use two shdrs (so we can point past SHN_UNDEF=0); both SHT_NULL.
  , synth "19_shstrndx_not_strtab"
      ((ByteArray.empty
        ++ RawElf64_Ehdr.write
             { ehdr with e_shoff := 64, e_shentsize := 64, e_shnum := 2
                        , e_shstrndx := 1 })  -- index 1 is SHT_NULL ≠ STRTAB
        ++ RawElf64_Shdr.write baselineRawShdr
        ++ RawElf64_Shdr.write baselineRawShdr)
      false "structural"
  -- SHT_SYMTAB sh_link points to a non-strtab section. parseSymtabFromShdrs
  -- rejects with "sh_link=X points at sh_type=Y, want SHT_STRTAB".
  -- Layout: [0]=SHT_NULL, [1]=SHT_SYMTAB(entsize=24, link=0=NULL).
  , synth "1A_symtab_shlink_not_strtab"
      ((ByteArray.empty
        ++ RawElf64_Ehdr.write
             { ehdr with e_shoff := 64, e_shentsize := 64, e_shnum := 2 })
        ++ RawElf64_Shdr.write baselineRawShdr  -- [0] SHT_NULL
        ++ RawElf64_Shdr.write { baselineRawShdr with
             sh_type := 2     -- SHT_SYMTAB
             sh_entsize := 24
             sh_link := 0 })  -- points at SHT_NULL, not a strtab
      false "structural"
  -- shentsize_ok: e_shoff ≠ 0 but e_shentsize ≠ 64. gabi requires
  -- e_shentsize = sizeof(Elf64_Shdr) = 64 when shdrs are present.
  , synth "1B_violate_shentsize_ok"
      (RawElf64_Ehdr.write { ehdr with
          e_shoff := 64, e_shentsize := 99, e_shnum := 1 })
      false "policy"
  -- e_phoff = 32 (between 0 and 64). Phdr table overlaps ehdr partially.
  -- Same class of issue as 15 — invariant catches it.
  , synth "17_phdr_partial_overlap"
      (RawElf64_Ehdr.write { ehdr with e_phoff := 32, e_phnum := 1 })
      false "policy"
  -- e_phoff = 64 + 1 (off by one). Misaligned phdr table start — gabi
  -- doesn't require natural alignment but a real loader might. We accept.
  , synth "18_phdr_offset_misaligned"
      (RawElf64_Ehdr.write { ehdr with e_phoff := 65, e_phnum := 0 })
      true "structural"

    -- decode: well-positioned but unknown closed-enum values, auto-generated
    -- via `<EnumName>.invalidRaw`. New closed-enum fields get fixtures
    -- automatically; open enums (with `_` arm) are skipped.
  , decodeOf "20_decode_ei_magic"   Elf64_Ehdr.EiMagic.invalidRaw
              (fun ehdr bad => { ehdr with ei_magic   := bad })
  , decodeOf "21_decode_ei_class"   Elf64_Ehdr.EiClass.invalidRaw
              (fun ehdr bad => { ehdr with ei_class   := bad })
  , decodeOf "22_decode_ei_data"    Elf64_Ehdr.EiData.invalidRaw
              (fun ehdr bad => { ehdr with ei_data    := bad })
  , decodeOf "23_decode_ei_version" Elf64_Ehdr.EiVersion.invalidRaw
              (fun ehdr bad => { ehdr with ei_version := bad })
  , decodeOf "24_decode_e_type"     Elf64_Ehdr.EType.invalidRaw
              (fun ehdr bad => { ehdr with e_type     := bad })
  , decodeOf "25_decode_e_version"  Elf64_Ehdr.EVersion.invalidRaw
              (fun ehdr bad => { ehdr with e_version  := bad })
  ]
  let suffix : List Fixture := [
    -- dynamic-section: malformations only our dynamic-table walker catches
    synth "40_dt_strtab_no_strsz"
      (withDynamic #[baselineRawDyn 5 0x900, baselineRawDyn 0 0]) false "dynamic"
  , synth "41_dt_symtab_no_syment"
      (withDynamic #[baselineRawDyn 6 0x900, baselineRawDyn 0 0]) false "dynamic"
  , synth "42_dt_strtab_wild_vaddr"
      (withDynamic #[baselineRawDyn 5 0xDEADBEEF, baselineRawDyn 10 16, baselineRawDyn 0 0])
      false "dynamic"
  , synth "43_dt_symtab_no_hash"
      (withDynamic #[baselineRawDyn 6 0x900, baselineRawDyn 11 24, baselineRawDyn 0 0])
      false "dynamic"

    -- hash: targeted hash-table failures (DT_HASH / DT_GNU_HASH paths)
  -- DT_HASH vaddr outside any PT_LOAD.
  , synth "50_dt_hash_oob"
      (withDynamic #[baselineRawDyn 6 0x900,    -- DT_SYMTAB
                     baselineRawDyn 11 24,      -- DT_SYMENT
                     baselineRawDyn 4 0xDEADBEEF,  -- DT_HASH (wild)
                     baselineRawDyn 0 0])
      false "hash"
  -- DT_GNU_HASH vaddr outside any PT_LOAD.
  , synth "51_dt_gnu_hash_oob"
      (withDynamic #[baselineRawDyn 6 0x900,
                     baselineRawDyn 11 24,
                     baselineRawDyn 0x6ffffef5 0xDEADBEEF,  -- DT_GNU_HASH (wild)
                     baselineRawDyn 0 0])
      false "hash"
  -- DT_GNU_HASH points at a location with bloom_size so huge that
  -- buckets/chains compute past file end (truncated chain-walk read).
  , synth "52_dt_gnu_hash_giant_bloom"
      (withDynamic
        (extras := #[(0x900,
          gnuHashBytes (nbuckets := 1) (symoffset := 0)
            (bloom_size := 0xFFFF) (bloom_shift := 0)
            (bloom := #[]) (buckets := #[]) (chains := #[]))])
        #[baselineRawDyn 6 0x800,
          baselineRawDyn 11 24,
          baselineRawDyn 0x6ffffef5 0x900,
          baselineRawDyn 0 0])
      false "hash"
  -- DT_GNU_HASH whose chain never terminates: bucket points to symbol 10,
  -- but chains array contains all zero entries (low bit clear).
  , synth "53_dt_gnu_hash_runaway_chain"
      (withDynamic
        (extras := #[(0x900,
          gnuHashBytes (nbuckets := 1) (symoffset := 0)
            (bloom_size := 1) (bloom_shift := 0)
            (bloom := #[0xFFFFFFFFFFFFFFFF])
            (buckets := #[10])
            -- 50 chain entries, none with low bit set
            (chains := Array.replicate 50 0))])
        #[baselineRawDyn 6 0x800,
          baselineRawDyn 11 24,
          baselineRawDyn 0x6ffffef5 0x900,
          baselineRawDyn 0 0])
      false "hash"

    -- versioning: malformations the .gnu.version_r walker catches
  -- DT_VERNEED without DT_VERNEEDNUM.
  , synth "60_dt_verneed_no_num"
      (withDynamic #[baselineRawDyn 0x6ffffffe 0x800,  -- DT_VERNEED
                     baselineRawDyn 0 0])
      false "version"
  -- DT_VERNEED vaddr outside any PT_LOAD.
  , synth "61_dt_verneed_oob"
      (withDynamic #[baselineRawDyn 0x6ffffffe 0xDEADBEEF,
                     baselineRawDyn 0x6fffffff 1,
                     baselineRawDyn 0 0])
      false "version"

    -- notes: malformations the PT_NOTE parser catches
  -- Positive: two well-formed notes (build-id + ABI tag shapes).
  , synth "70_note_two_valid"
      (withNotes #[noteBytes "GNU" 3 (ByteArray.mk (Array.replicate 20 0xAB))
                  , noteBytes "GNU" 1 (ByteArray.mk #[0,0,0,0, 3,0,0,0, 2,0,0,0, 0,0,0,0])])
      true "note"
  -- Truncated note: just the 12-byte header, claims namesz=4 + descsz=8
  -- but the body is missing.
  , synth "71_note_truncated_body"
      (withNotes #[ByteArray.empty
                     |>.pushUInt32LE 4    -- namesz
                     |>.pushUInt32LE 8    -- descsz
                     |>.pushUInt32LE 1])  -- type, no body bytes follow
      false "note"
  -- namesz overflow: claim a 1MB name in a tiny segment.
  , synth "72_note_namesz_overflow"
      (withNotes #[ByteArray.empty
                     |>.pushUInt32LE 0x100000  -- namesz = 1 MiB
                     |>.pushUInt32LE 0
                     |>.pushUInt32LE 1])
      false "note"
  -- Non-ASCII bytes in the name (NUL-terminated 4-byte name with high
  -- bit set in the first byte). gabi convention is printable-ASCII.
  , synth "73_note_name_non_ascii"
      (withNotes #[ByteArray.empty
                     |>.pushUInt32LE 4  -- namesz (includes null)
                     |>.pushUInt32LE 0
                     |>.pushUInt32LE 1
                     |>.push 0xff |>.push 0x47 |>.push 0x4e |>.push 0])
      false "note"

    -- DT_RELR: malformations the relr parser catches
  -- DT_RELR present but no DT_RELRSZ.
  , synth "80_dt_relr_no_size"
      (withDynamic #[baselineRawDyn 36 0x900,  -- DT_RELR
                     baselineRawDyn 0 0])
      false "relr"
  -- DT_RELRENT != 8 (gabi requires 8).
  , synth "81_dt_relrent_wrong"
      (withDynamic #[baselineRawDyn 36 0x900,
                     baselineRawDyn 35 16,     -- DT_RELRSZ
                     baselineRawDyn 37 12,     -- DT_RELRENT = 12, illegal
                     baselineRawDyn 0 0])
      false "relr"
  -- DT_RELR vaddr outside any PT_LOAD.
  , synth "82_dt_relr_oob"
      (withDynamic #[baselineRawDyn 36 0xDEADBEEF,
                     baselineRawDyn 35 16,
                     baselineRawDyn 0 0])
      false "relr"

    -- Real-world positive controls — exercise DT_RELR + Verdef on libc /
    -- ld.so. These are 1.5 MB + 800 KB binaries; emit them so the
    -- differential covers the full feature surface.
  , real "08_real_libc"            "/lib/x86_64-linux-gnu/libc.so.6"
  , real "09_real_ld_linux_full"   "/lib64/ld-linux-x86-64.so.2"
  ]
  head ++ policyFixtures ++ truncationFixtures ++ phdrTruncationFixtures
       ++ shdrTruncationFixtures ++ suffix

/-- JSON-escape a string for the manifest. We only have ASCII names so this
    is trivial. -/
private def jsonStr (s : String) : String := "\"" ++ s ++ "\""

def main (args : List String) : IO UInt32 := do
  let outDir := args.headD "fixtures_out"
  IO.FS.createDirAll outDir
  let mut entries : Array String := #[]
  let mut written := 0
  for f in fixtures do
    let path := s!"{outDir}/{f.name}.elf"
    let mut size : Nat := 0
    let mut wrote := true
    match f.bytes, f.realPath with
    | some bs, _ =>
      IO.FS.writeBinFile path bs
      size := bs.size
    | _, some src =>
      match (← (IO.FS.readBinFile src).toBaseIO) with
      | .ok bs =>
        IO.FS.writeBinFile path bs
        size := bs.size
      | .error e =>
        IO.eprintln s!"skipping {f.name}: cannot read {src} ({e})"
        wrote := false
    | _, _ =>
      IO.eprintln s!"skipping {f.name}: no source"
      wrote := false
    if wrote then
      written := written + 1
      let _ ← IO.Process.spawn { cmd := "chmod", args := #["755", path] }
      entries := entries.push <|
        "  {\"name\":" ++ jsonStr f.name ++
        ",\"size\":" ++ toString size ++
        ",\"ourVerdict\":" ++ jsonStr (if f.ourVerdict then "ACCEPT" else "REJECT") ++
        ",\"category\":" ++ jsonStr f.category ++ "}"
  let manifest := "[\n" ++ String.intercalate ",\n" entries.toList ++ "\n]\n"
  IO.FS.writeFile s!"{outDir}/manifest.json" manifest
  IO.println s!"wrote {written} fixtures + manifest.json to {outDir}/"
  return 0
