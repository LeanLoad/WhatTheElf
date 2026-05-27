-- This module serves as the root of the `WhatTheElf` library.
-- Note: `WhatTheElf.Macro` is intentionally NOT imported here — the macro is
-- compile-time-only, and importing it pulls `Lean.*` into the runtime
-- transitive closure (a constraint kept around in case we ever revisit a
-- minimal-runtime build target like WASM).
import WhatTheElf.Basic
import WhatTheElf.ElfHeader
import WhatTheElf.ProgramHeader
import WhatTheElf.SectionHeader
import WhatTheElf.Dynamic
import WhatTheElf.Strtab
import WhatTheElf.Symtab
import WhatTheElf.Rela
import WhatTheElf.Relr
import WhatTheElf.Version
import WhatTheElf.Note

namespace WhatTheElf

structure Elf64_File where
  ehdr      : Elf64_Ehdr
  phdrs     : Array Elf64_Phdr
  shdrs?    : Option (Array Elf64_Shdr)
  shstrtab? : Option Strtab
  shdrNames? : Option (Array (Option String))
  interp?   : Option String
  dynamic?  : Option (Array Elf64_Dyn)
  strtab?   : Option Strtab
  symtab?   : Option (Array Elf64_Sym)
  /-- Full linker symbol table `.symtab`, located via shdrs. Stripped
      binaries don't have one and this is `none`. -/
  symtabSh? : Option SymtabFromShdrs
  /-- `.dynsym` re-parsed via shdrs (independent of the DT_SYMTAB / hash
      table path used for `symtab?`). Useful as a cross-check. -/
  dynsymSh? : Option SymtabFromShdrs
  relaDyn?  : Option (Array Elf64_Rela)
  relaPlt?  : Option (Array Elf64_Rela)
  /-- `.relr.dyn` — compact relative relocations (glibc 2.36+). The raw
      entries (`.addr` / `.bitmap`); use `expandRelr` to materialize the
      individual addresses. -/
  relr?     : Option (Array RelrEntry)
  versym?   : Option (Array UInt16)
  verneed?  : Option (Array VerneedEntry)
  /-- `.gnu.version_d` — versions this object *defines*. Typically `none`
      for executables; populated for libraries like `libc.so.6` that
      export versioned symbols. -/
  verdef?   : Option (Array VerdefEntry)
  notes?    : Option (Array Note)
  deriving Repr

def Elf64_File.parse (file : ByteArray) : Except String Elf64_File := do
  let ehdr     ← Elf64_Ehdr.parse file
  let phdrs    ← ehdr.parsePhdrs file
  let shdrs?   ← ehdr.parseShdrs file
  let shstrtab? ← match shdrs? with
                  | none    => pure none
                  | some ss => parseShstrtab file ehdr ss
  let shdrNames? : Option (Array (Option String)) :=
    match shdrs?, shstrtab? with
    | some ss, some st => some (ss.map (·.name st))
    | _, _ => none
  let symtabSh? ← match shdrs? with
                  | none    => pure none
                  | some ss => parseSymtabFromShdrs file ss .sht_symtab
  let dynsymSh? ← match shdrs? with
                  | none    => pure none
                  | some ss => parseSymtabFromShdrs file ss .sht_dynsym
  let interp?  ← parseInterp  file phdrs
  let dynamic? ← parseDynamic file phdrs
  let strtab?  ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseStrtab file phdrs dyn
  let symtab?  ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseSymtab file phdrs dyn
  let relaDyn? ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseRelaDyn file phdrs dyn
  let relaPlt? ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseRelaPlt file phdrs dyn
  let relr?    ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseRelr file phdrs dyn
  let versym?  ← match dynamic?, symtab? with
                 | some dyn, some syms => parseVersym file phdrs dyn syms.size
                 | _, _ => pure none
  let verneed? ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseVerneeds file phdrs dyn
  let verdef?  ← match dynamic? with
                 | none     => pure none
                 | some dyn => parseVerdefs file phdrs dyn
  let notes?   ← parseNotes file phdrs
  return { ehdr, phdrs, shdrs?, shstrtab?, shdrNames?, symtabSh?, dynsymSh?
         , interp?, dynamic?, strtab?, symtab?
         , relaDyn?, relaPlt?, relr?, versym?, verneed?, verdef?, notes? }

instance : ToJsonStr Elf64_File where
  toJsonStr f :=
    "{\"ehdr\":"       ++ toJsonStr f.ehdr      ++
    ",\"phdrs\":"      ++ toJsonStr f.phdrs     ++
    ",\"shdrs\":"      ++ toJsonStr f.shdrs?    ++
    ",\"shdr_names\":" ++ toJsonStr f.shdrNames? ++
    ",\"shstrtab\":"   ++ toJsonStr f.shstrtab? ++
    ",\"symtab_sh\":"  ++ toJsonStr f.symtabSh? ++
    ",\"dynsym_sh\":"  ++ toJsonStr f.dynsymSh? ++
    ",\"interp\":"     ++ toJsonStr f.interp?   ++
    ",\"dynamic\":"    ++ toJsonStr f.dynamic?  ++
    ",\"strtab\":"     ++ toJsonStr f.strtab?   ++
    ",\"symtab\":"     ++ toJsonStr f.symtab?   ++
    ",\"rela_dyn\":"   ++ toJsonStr f.relaDyn?  ++
    ",\"rela_plt\":"   ++ toJsonStr f.relaPlt?  ++
    ",\"relr\":"       ++ toJsonStr f.relr?     ++
    ",\"versym\":"     ++ toJsonStr f.versym?   ++
    ",\"verneed\":"    ++ toJsonStr f.verneed?  ++
    ",\"verdef\":"     ++ toJsonStr f.verdef?   ++
    ",\"notes\":"      ++ toJsonStr f.notes?    ++ "}"

end WhatTheElf
