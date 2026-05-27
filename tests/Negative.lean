/-
Negative + positive tests for `Elf64_File.parse`.

Each test is a `#guard` that fails at elaboration if the parser's behavior
doesn't match the expected error category (or doesn't accept a valid file).
Build with `lake build Tests`; failures show up as elaboration errors.

All fixtures are synthesized via the macro-emitted `Raw.write` serializers
(see `Fixtures.lean`) — no Python, no `gcc`, no checked-in binary blobs.
-/

import Fixtures

open WhatTheElf
open WhatTheElf.Test

-- ── Positive controls ──────────────────────────────────────────────

-- Minimum valid ELF: ehdr only, no phdrs.
#guard expectOk (({} : Elf64Layout).serialize)

-- ehdr + one PT_NULL phdr.
#guard expectOk
  (({ ehdr := { baselineRawEhdr with e_phnum := 1 }
    , phdrs := #[baselineRawPhdr] } : Elf64Layout).serialize)

-- ── Ehdr: short-read / read failures ───────────────────────────────

#guard expectErr "short read" ByteArray.empty
#guard expectErr "short read" (ByteArray.mk #[0x7f])
#guard expectErr "short read" ((RawElf64_Ehdr.write baselineRawEhdr).extract 0 63)

-- ── Ehdr: decode failures (closed enums) ───────────────────────────

#guard expectErr "EiMagic"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_magic := 0 })
#guard expectErr "EiMagic"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_magic := 0x00_4c_45_7f })

#guard expectErr "EiClass"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_class := 3 })
#guard expectErr "EiClass"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_class := 99 })

#guard expectErr "EiData"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_data := 3 })

#guard expectErr "EiVersion"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_version := 2 })

-- 5 < 7 < 0xfe00 — outside all e_type cases (no `other` wildcard there).
#guard expectErr "EType"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_type := 7 })

#guard expectErr "EVersion"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_version := 2 })

-- ── Ehdr: invariant (check) failures ───────────────────────────────

#guard expectErr "class_ok"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_class := 1 })

#guard expectErr "data_ok"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_data := 2 })

#guard expectErr "not_exec"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_type := 2 })

-- EM_RISCV = 243; valid enum but not in our policy allow-list.
#guard expectErr "machine_ok"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_machine := 243 })

#guard expectErr "ehsize_ok"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_ehsize := 63 })

#guard expectErr "phentsize_ok"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_phentsize := 57 })

-- ── Phdr: read failures (table extends past file) ──────────────────

-- Promise 2 phdrs in the ehdr but the layout only has 1.
#guard expectErr "short read"
  (({ ehdr := { baselineRawEhdr with e_phnum := 2 }
    , phdrs := #[baselineRawPhdr] } : Elf64Layout).serialize)

-- e_phoff points past the file.
#guard expectErr "short read"
  (RawElf64_Ehdr.write { baselineRawEhdr with e_phoff := 10000, e_phnum := 1 })

-- ── Dynamic: ehdr + PT_LOAD + PT_DYNAMIC with malformed dyn table ──

-- ── Dynamic: ehdr + PT_LOAD + PT_DYNAMIC with malformed dyn table ──
-- (`withDynamic` lives in Fixtures.lean — shared with EmitFixtures.lean.)

-- Positive: PT_DYNAMIC with just DT_NULL — empty dynamic table.
#guard expectOk (withDynamic #[baselineRawDyn 0 0])

-- DT_STRTAB without DT_STRSZ.
#guard expectErr "DT_STRSZ"
  (withDynamic #[baselineRawDyn 5 0x900, baselineRawDyn 0 0])

-- DT_SYMTAB without DT_SYMENT.
#guard expectErr "DT_SYMENT"
  (withDynamic #[baselineRawDyn 6 0x900, baselineRawDyn 0 0])

-- DT_STRTAB pointing to a vaddr not covered by any PT_LOAD.
#guard expectErr "not in any PT_LOAD"
  (withDynamic #[baselineRawDyn 5 0xDEADBEEF, baselineRawDyn 10 16, baselineRawDyn 0 0])

-- DT_SYMTAB with no DT_HASH and no DT_GNU_HASH.
#guard expectErr "no DT_HASH or DT_GNU_HASH"
  (withDynamic #[baselineRawDyn 6 0x900, baselineRawDyn 11 24, baselineRawDyn 0 0])

-- ── Round-trip property: `RawT.read ∘ RawT.write = pure` ───────────
--
-- For every elf_record, writing then reading recovers the original raw
-- value. This is the encoder/decoder agreement property that the
-- differential fuzz CANNOT see — a lossy writer that emits different
-- bytes-than-it-reads would still pass the differential if those bytes
-- happen to be parseable elsewhere. Direct round-trip catches that.

private def roundtripsRaw {α : Type} [BEq α] (read : ByteArray → Except String α)
    (write : α → ByteArray) (x : α) : Bool :=
  match read (write x) with
  | .ok y    => y == x
  | .error _ => false

#guard roundtripsRaw RawElf64_Ehdr.read    RawElf64_Ehdr.write    baselineRawEhdr
#guard roundtripsRaw RawElf64_Phdr.read    RawElf64_Phdr.write    baselineRawPhdr
#guard roundtripsRaw RawElf64_Shdr.read    RawElf64_Shdr.write    baselineRawShdr
#guard roundtripsRaw RawElf64_Dyn.read     RawElf64_Dyn.write     (baselineRawDyn 5 0x800)
#guard roundtripsRaw RawElf64_Sym.read     RawElf64_Sym.write
        { st_name := 1, st_info := 0x12, st_other := 0, st_shndx := 7
        , st_value := 0xabcd, st_size := 16 }
#guard roundtripsRaw RawElf64_Rela.read    RawElf64_Rela.write
        { r_offset := 0x4000, r_info := 0x0000000700000008, r_addend := 0xdead }
#guard roundtripsRaw RawElf64_Verneed.read RawElf64_Verneed.write
        { vn_version := 1, vn_cnt := 3, vn_file := 5, vn_aux := 16, vn_next := 0 }
#guard roundtripsRaw RawElf64_Vernaux.read RawElf64_Vernaux.write
        { vna_hash := 0x12345678, vna_flags := 0, vna_other := 7, vna_name := 32
        , vna_next := 0 }
#guard roundtripsRaw RawElf64_Verdef.read  RawElf64_Verdef.write
        { vd_version := 1, vd_flags := 1, vd_ndx := 2, vd_cnt := 1
        , vd_hash := 0xdeadbeef, vd_aux := 20, vd_next := 0 }
#guard roundtripsRaw RawElf64_Verdaux.read RawElf64_Verdaux.write
        { vda_name := 64, vda_next := 0 }

-- Spot-check: an extreme-value edge case (all 0xff) still round-trips.
#guard roundtripsRaw RawElf64_Phdr.read RawElf64_Phdr.write
        { p_type := 0xffffffff, p_flags := 0xffffffff, p_offset := 0xffffffffffffffff
        , p_vaddr := 0xffffffffffffffff, p_paddr := 0xffffffffffffffff
        , p_filesz := 0xffffffffffffffff, p_memsz := 0xffffffffffffffff
        , p_align := 0xffffffffffffffff }

-- ── Versym ↔ Verneed/Verdef cross-validation ───────────────────────

-- Empty input: trivially resolves.
#guard (unresolvedVersyms #[] none none).isEmpty

-- LOCAL (0) and GLOBAL (1) always resolve regardless of tables.
#guard (unresolvedVersyms #[0, 1, 0x8000, 0x8001] none none).isEmpty

-- Index 2 with no Verneed/Verdef ⇒ unresolved.
#guard (unresolvedVersyms #[2] none none) = #[(0, 2)]

-- Index 2 matched by a Verdef entry ⇒ resolved.
#guard (unresolvedVersyms #[2] none (some #[
  { verdef := { vd_version := 1, vd_flags := 0, vd_ndx := 2, vd_cnt := 0
              , vd_hash := 0, vd_aux := 0, vd_next := 0 }
  , auxes  := #[] }])).isEmpty

-- Index 3 matched by a Vernaux.vna_other ⇒ resolved.
#guard (unresolvedVersyms #[3] (some #[
  { verneed := { vn_version := 1, vn_cnt := 1, vn_file := 0, vn_aux := 0, vn_next := 0 }
  , auxes   := #[{ vna_hash := 0, vna_flags := 0, vna_other := 3, vna_name := 0
                 , vna_next := 0 }] }]) none).isEmpty

-- High bit (HIDDEN) is stripped before lookup: 0x8002 looks up as 2.
#guard (unresolvedVersyms #[0x8002] none (some #[
  { verdef := { vd_version := 1, vd_flags := 0, vd_ndx := 2, vd_cnt := 0
              , vd_hash := 0, vd_aux := 0, vd_next := 0 }
  , auxes  := #[] }])).isEmpty
