# WhatTheElf

ELF64 parser in Lean 4 — a precise, witnessed spec of (a strict subset of)
the System V gABI ELF format.

## Layout

```
WhatTheElf.lean              top-level `Elf64_File` aggregate + parse driver
WhatTheElf/Basic.lean        primitives: Cursor, ByteArray builders, ToJsonStr,
                             Parser typeclass, parseTable, TableLayout
WhatTheElf/Macro.lean        the `elf_record` command — emits 10 functions +
                             3 types per record (see top of file)
WhatTheElf/ElfHeader.lean    Elf64_Ehdr  (gabi 02 § ELF Header)
WhatTheElf/ProgramHeader.lean  Elf64_Phdr (gabi 07 § Program Header) +
                             generic helpers (parsePhdrTable, parseInterp,
                             segment, virtualToFileOffset)
WhatTheElf/Dynamic.lean      Elf64_Dyn  (gabi 08 § Dynamic Linking) +
                             lookupDtag + parseDynamic
WhatTheElf/Strtab.lean       .dynstr — null-terminated string pool with
                             gabi-correct suffix-sharing lookup
WhatTheElf/Symtab.lean       Elf64_Sym + DT_HASH / DT_GNU_HASH symbol-count
                             derivation (works on stripped binaries with no
                             section headers)
WhatTheElf/Rela.lean         Elf64_Rela for .rela.dyn and .rela.plt
WhatTheElf/Version.lean      .gnu.version (Versym) + .gnu.version_r
                             (Verneed/Vernaux) — GNU symbol versioning
Main.lean                    CLI: stdin bytes → JSON to stdout
tests/Fixtures.lean          baselines + Elf64Layout + withDynamic + loadableElf
tests/Negative.lean          26 `#guard` tests, one per parser error path
tests/EmitFixtures.lean      lean_exe that dumps named ELF fixtures to disk
tests/differential.py        runs each fixture through 6 other ELF parsers
                             (glibc ld.so, eu-readelf, readelf, llvm-readelf,
                             objdump, llvm-objdump) and tabulates verdicts
```

## Build / run

```bash
lake build              # the library + the `whattheelf` CLI
./.lake/build/bin/whattheelf < /bin/ls          # JSON to stdout

lake build Tests        # 26 #guard tests run at elaboration time

lake build emit_fixtures && \
  ./.lake/build/bin/emit_fixtures fixtures_out && \
  python3 tests/differential.py fixtures_out    # cross-parser comparison table
```

## Design notes

### Four-layer pipeline per `elf_record`

Every record `T` decomposes parsing into pure total functions, each with a
distinct failure mode:

```
ByteArray  ── read    ──→  RawT
RawT       ── decode  ──→  T.Decoded      (apply per-enum ofRaw)
T.Decoded  ── check   ──→  T              (verify invariant Props)

T.parse = read >=> decode >=> check
```

`read` is total modulo "short read", `decode` modulo unknown enum values,
`check` modulo invariant violation. Each layer's type carries the witnesses
of the previous layer's successes.

### Raw serializer for round-trip & test fixtures

The macro also emits `RawT.write : RawT → ByteArray` (the inverse of `read`).
Combined with the typed `Raw*` baselines in `tests/Fixtures.lean`, this lets
us build *both* good and bad fixtures with the same API — overriding one
field in a baseline gives a one-line test case:

```lean
#guard expectErr "EiClass"
  (RawElf64_Ehdr.write { baselineRawEhdr with ei_class := 99 })
```

Field names + types are checked by Lean, so typos and wrong-width values
fail to compile rather than producing silently-wrong bytes — a class of
mistake that's possible with Python `struct.pack` or hand-written C.

### Strict acceptance policy

`Elf64_Ehdr` enforces invariants beyond gabi structural validity:
`ei_class = .class64`, `ei_data = .lsb`, `e_type ≠ .exec`, `e_machine ∈
{em_x86_64, em_aarch64}`, `e_ehsize = 64`, `e_phentsize = 56`. These are
intentional — the parser is for a specific subset, not a general gabi
acceptor — and the differential test surfaces where this strictness
disagrees with other ELF tools (it's the spec policy, not a bug).

### Hash-table-driven symbol count

The dynamic section provides `DT_SYMTAB` (address) and `DT_SYMENT` (stride)
but no symbol count. Real loaders recover the count from the hash table:
`DT_HASH.nchain` or by walking `DT_GNU_HASH` chains. We do both, preferring
the simpler `DT_HASH` when present. This means we parse `.dynsym` on
stripped binaries without section headers — exactly the position the
dynamic linker is in at runtime.
