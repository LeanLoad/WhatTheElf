/-
The `elf_record` command — DSL whose elaboration produces a four-layer
parse pipeline (`read → decode → check → parse`) for a fixed-shape ELF
record. Each layer is a pure total function modulo its own failure mode,
so the spec separates IO concerns (only `read`'s input) from interpretation
(`decode`), validation (`check`), and the end-to-end fast path (`parse`).

```
elf_record Elf64_Ehdr where
  ei_magic    : UInt32 { elf = 0x464c457f }
  ei_class    : UInt8  { class32 = 1, class64 = 2 }
  ei_pad      : bytes 7
  e_type      : UInt16 { none = 0, …, osSpecific = 0xfe00..0xfeff, … }
  …
invariant
  class_ok    : ei_class = .class64
  not_exec    : e_type   ≠ .exec
```

Per record `T`, emits (in order):

  * one inline-enum block per `<base> { … }` field:
      `inductive T.<Enum>`, `def T.<Enum>.ofRaw`, `instance : ToJsonStr`
  * `def T.size : Nat`                                       — static byte size
  * `structure RawT`                                         — raw widths only
  * `def RawT.read : ByteArray → Except String RawT`         — byte-binding
  * `def RawT.write : RawT → ByteArray`                      — inverse of read
  * `structure T.Decoded`                                    — typed (enums), no Props
  * `def RawT.decode : RawT → Except String T.Decoded`       — apply enum ofRaws
  * `structure T extends T.Decoded where …`                  — Decoded + invariant Props
  * `def T.Decoded.check : T.Decoded → Except String T`      — verify invariants
  * `def T.parse : ByteArray → Except String T`              — read ∘ decode ∘ check
  * `instance : ToJsonStr T`                                 — JSON (uses extends)
  * `instance : Parser T`                                    — for `parseTable`

`read` takes a sized buffer so it can be hooked to any IO source (mmap,
`IO.FS.Handle`, browser `Fetch`) — the outer layer just supplies a
`ByteArray` of the right size, no `Cursor` plumbing leaks out.

Implementation is text-based (build Lean source, `runParserCategory`,
`elabCommand`) — easier to debug than fighting `Syntax`-quotation hygiene.
-/

import Lean
import WhatTheElf.Basic

open Lean Elab Command

namespace WhatTheElf

-- ── Syntax ───────────────────────────────────────────────────────────

/-- Pattern for a single enum case: a literal, a closed range, or `_` for
    the catch-all. Range / wildcard produce constructors that bind the raw. -/
declare_syntax_cat elfEnumPat
syntax num : elfEnumPat
syntax num ".." num : elfEnumPat
syntax "_" : elfEnumPat

syntax elfEnumCase := ident " = " elfEnumPat

/-- A field's type is one of:
    * a primitive width (`UInt8` / `UInt16` / `UInt32` / `UInt64` / `Addr` / `Off`),
      optionally followed by a `{ … }` enum block which inlines a typed enum;
    * `bytes N` for an opaque fixed-size byte array;
    * any other identifier, treated as a previously-defined `elf_record`
      type `T` (must expose `T.size`, `T.Raw`, `T.Raw.read`, `T.Raw.decode`). -/
declare_syntax_cat elfFieldTy
syntax (name := elfFieldEnum) ident " {" sepBy(elfEnumCase, ", ") "}" : elfFieldTy
syntax (name := elfFieldSized) ident num : elfFieldTy
syntax ident : elfFieldTy

syntax elfField := ident " : " elfFieldTy
syntax elfInv   := ident " : " term

syntax (name := elfRecord)
  "elf_record " ident " where" many1Indent(elfField)
  ("invariant" many1Indent(elfInv))? : command

-- ── Internal representations ─────────────────────────────────────────

private inductive EnumCase
  /-- `name = <num>` — nullary constructor. -/
  | nullary  (name : String) (val : Nat)
  /-- `name = <lo>..<hi>` — unary constructor binding the raw value. -/
  | range    (name : String) (lo hi : Nat)
  /-- `name = _` — unary catch-all binding the raw value. -/
  | wildcard (name : String)
  deriving Inhabited

private def EnumCase.name : EnumCase → String
  | .nullary n _    => n
  | .range n _ _    => n
  | .wildcard n     => n

private def EnumCase.isParameterized : EnumCase → Bool
  | .nullary _ _ => false
  | _            => true

private structure FieldSpec where
  name        : String   -- e.g. "ei_class"
  rawType     : String   -- e.g. "UInt8" / "ByteArray" / "Elf64_Phdr.Raw"
  decodedType : String   -- e.g. "Elf64_Ehdr.EiClass" / "UInt8" / "Elf64_Phdr"
  sizeExpr    : String   -- e.g. "1" / "7" / "Elf64_Phdr.size"
  /-- One line in `Raw.read`'s `do` block. Cursor `c` is in scope. -/
  readStep    : String
  /-- One line in `Raw.decode`'s `do` block. The raw record `r` is in scope. -/
  decodeStep  : String
  /-- One line in `Raw.write`'s pipeline. The raw record `r` and current
      buffer `bs` are in scope; the line should produce an updated `bs`. -/
  writeStep   : String
  /-- Nullary enum cases for this field as `(case_name, raw_value)` pairs;
      empty for non-enum fields. Used by `invariantViolators` to pick
      "another valid case" when violating equality invariants. -/
  enumNullaries : List (String × Nat) := []
  deriving Inhabited

private structure InvSpec where
  name : String
  prop : String        -- pretty-printed term
  deriving Inhabited

/-- For a known primitive type identifier, return
    `(leanType, decoderMethod, writerMethod, sizeBytes)`. `Addr` / `Off` are
    reducible aliases over `UInt64`. Returns `none` for any other identifier
    — the caller treats those as user-defined records. -/
private def baseInfo? (name : String) : Option (String × String × String × Nat) :=
  match name with
  | "UInt8"  => some ("UInt8",  "u8",    "push",          1)
  | "UInt16" => some ("UInt16", "u16le", "pushUInt16LE",  2)
  | "UInt32" => some ("UInt32", "u32le", "pushUInt32LE",  4)
  | "UInt64" => some ("UInt64", "u64le", "pushUInt64LE",  8)
  | "Addr"   => some ("Addr",   "u64le", "pushUInt64LE",  8)
  | "Off"    => some ("Off",    "u64le", "pushUInt64LE",  8)
  | _        => none

private def parseAndElab (src : String) : CommandElabM Unit := do
  match Parser.runParserCategory (← getEnv) `command src with
  | .ok stx  => elabCommand stx
  | .error e => throwError s!"elf_record: failed to parse generated:\n--BEGIN--\n{src}\n--END--\n→ {e}"

/-- Derive an enum type name from the field name: capitalize each
    `_`-separated segment and concatenate. `ei_class` → `EiClass`,
    `magic` → `Magic`. Caller prefixes with the record name. -/
private def deriveImplicitName (fieldName : String) : String :=
  let cap (s : String) : String :=
    match s.toList with
    | []      => ""
    | c :: rs => String.ofList (c.toUpper :: rs)
  String.join ((fieldName.splitOn "_").map cap)

private def parseEnumCase (c : TSyntax `WhatTheElf.elfEnumCase) :
    CommandElabM EnumCase := do
  match c with
  | `(elfEnumCase| $n:ident = $v:num) =>
      return .nullary n.getId.toString v.getNat
  | `(elfEnumCase| $n:ident = $lo:num .. $hi:num) =>
      return .range n.getId.toString lo.getNat hi.getNat
  | `(elfEnumCase| $n:ident = _) =>
      return .wildcard n.getId.toString
  | _ => throwError "elf_record: each enum arm must read `name = <num | num..num | _>`"

-- ── Field handling ───────────────────────────────────────────────────

private def fieldSpec (recName : String) (f : TSyntax `WhatTheElf.elfField) :
    CommandElabM FieldSpec := do
  match f with
  | `(elfField| $n:ident : $t:ident $sz:num) =>
      -- Sized form. Currently only `Bytes N` (fixed-size opaque buffer).
      let nm := n.getId.toString
      match t.getId.toString with
      | "Bytes" =>
          return { name        := nm
                 , rawType     := "ByteArray", decodedType := "ByteArray"
                 , sizeExpr    := toString sz.getNat
                 , readStep    := s!"  let ({nm}, c) ← c.readBytes {sz.getNat}"
                 , decodeStep  := s!"  let {nm} := r.{nm}"
                 , writeStep   := s!"  let bs := bs ++ r.{nm}" }
      | other => throwError s!"elf_record: unknown sized type `{other}` (only `Bytes N` is supported)"
  | `(elfField| $n:ident : $t:ident { $[$cases:elfEnumCase],* }) =>
      let nm := n.getId.toString
      let tName := t.getId.toString
      let some (rawTy, dec, wr, sz) := baseInfo? tName
        | throwError s!"elf_record: enum block over non-primitive type `{tName}`"
      let enumTy := s!"{recName}.{deriveImplicitName nm}"
      let parsed ← cases.mapM parseEnumCase
      let nullaries := parsed.toList.filterMap fun
        | .nullary cn cv => some (cn, cv)
        | _ => none
      return { name        := nm
             , rawType     := rawTy, decodedType := enumTy
             , sizeExpr    := toString sz
             , readStep    := s!"  let ({nm}, c) ← c.{dec}"
             , decodeStep  := s!"  let {nm} ← {enumTy}.ofRaw r.{nm}"
             , writeStep   := s!"  let bs := bs.{wr} r.{nm}"
             , enumNullaries := nullaries }
  | `(elfField| $n:ident : $t:ident) =>
      let nm := n.getId.toString
      let tName := t.getId.toString
      match baseInfo? tName with
      | some (ty, dec, wr, sz) =>
          return { name        := nm
                 , rawType     := ty, decodedType := ty
                 , sizeExpr    := toString sz
                 , readStep    := s!"  let ({nm}, c) ← c.{dec}"
                 , decodeStep  := s!"  let {nm} := r.{nm}"
                 , writeStep   := s!"  let bs := bs.{wr} r.{nm}" }
      | none =>
          -- User-defined record: rawType is `T.Raw`, decoded is `T`.
          return { name        := nm
                 , rawType     := s!"{tName}.Raw", decodedType := tName
                 , sizeExpr    := s!"{tName}.size"
                 , readStep    := s!"  let (raw_{nm}, c) ← c.readBytes {tName}.size\n" ++
                                  s!"  let {nm} ← {tName}.Raw.read raw_{nm}"
                 , decodeStep  := s!"  let {nm} ← {tName}.Raw.decode r.{nm}"
                 , writeStep   := s!"  let bs := bs ++ {tName}.Raw.write r.{nm}" }
  | _ => throwError "elf_record: unsupported field shape"

private def invSpec (i : TSyntax `WhatTheElf.elfInv) : CommandElabM InvSpec := do
  let `(elfInv| $n:ident : $p:term) := i
    | throwError "elf_record: each invariant must read `name : prop`"
  return { name := n.getId.toString,
           prop := (← liftCoreM (PrettyPrinter.ppTerm p)).pretty }

-- ── Code emitters ────────────────────────────────────────────────────

/-- Inline enum: inductive + `ofRaw` + `ToJsonStr`. No per-enum `parse` —
    enums are decoded en-masse by the parent record's `Raw.decode`. -/
private def emitInlineEnum
    (eName rawTy : String) (cases : Array EnumCase) :
    CommandElabM Unit := do
  let ctors := String.join (cases.toList.map fun c =>
    if c.isParameterized then s!"  | {c.name} (raw : {rawTy})\n"
    else s!"  | {c.name}\n")
  parseAndElab s!"inductive {eName} where\n{ctors}  deriving Repr, BEq, DecidableEq, Inhabited"

  -- `ofRaw`: nullary literal arms first; a final `| n =>` arm with chained
  -- range checks and either a wildcard tail or an error.
  let nullaryArms : List String := cases.toList.filterMap fun
    | .nullary n v => some s!"  | {v} => .ok .{n}\n"
    | _            => none
  let ranges : List (String × Nat × Nat) := cases.toList.filterMap fun
    | .range n lo hi => some (n, lo, hi)
    | _              => none
  let wildcard : Option String := cases.toList.findSome? fun
    | .wildcard n => some n
    | _           => none
  let errorTail :=
    s!".error s!\"{eName}: unknown raw value \{n}\""
  let catchAll :=
    if ranges.isEmpty ∧ wildcard.isNone then
      s!"  | n => {errorTail}"
    else
      let tail := match wildcard with
        | some w => s!".ok (.{w} n)"
        | none   => errorTail
      let chain := ranges.foldr (fun (n, lo, hi) rest =>
        s!"if {lo} ≤ n.toNat ∧ n.toNat ≤ {hi} then .ok (.{n} n) else {rest}") tail
      s!"  | n => {chain}"
  parseAndElab <|
    s!"def {eName}.ofRaw : {rawTy} → Except String {eName}\n" ++
    String.join nullaryArms ++ catchAll

  let jsonArms := String.join (cases.toList.map fun c =>
    match c with
    | .nullary n _   => s!"  | .{n} => \"\\\"{n}\\\"\"\n"
    | .range n _ _   => s!"  | .{n} r => \"\{\\\"{n}\\\":\" ++ WhatTheElf.toJsonStr r ++ \"}\"\n"
    | .wildcard n    => s!"  | .{n} r => \"\{\\\"{n}\\\":\" ++ WhatTheElf.toJsonStr r ++ \"}\"\n")
  parseAndElab s!"instance : WhatTheElf.ToJsonStr {eName} where toJsonStr\n{jsonArms}"

  -- `invalidRaw` — a raw value `ofRaw` will *reject*. `none` for enums with
  -- a `_` wildcard arm (every raw value decodes successfully). Used by the
  -- fuzz/differential harness to auto-generate decode-failure fixtures, one
  -- per closed enum, without hand-picking values.
  let nullaryVals : List Nat := cases.toList.filterMap fun
    | .nullary _ v => some v
    | _            => none
  let rangeBounds : List (Nat × Nat) := cases.toList.filterMap fun
    | .range _ lo hi => some (lo, hi)
    | _              => none
  let hasWildcard : Bool := cases.toList.any fun
    | .wildcard _ => true
    | _           => false
  let invalidExpr : String :=
    if hasWildcard then "none"
    else Id.run do
      for n in [0:65536] do
        let covered := nullaryVals.contains n ∨
          rangeBounds.any (fun (lo, hi) => lo ≤ n ∧ n ≤ hi)
        if !covered then return s!"some {n}"
      return "none"  -- exhausted scan; shouldn't happen for current enums
  parseAndElab s!"def {eName}.invalidRaw : Option {rawTy} := {invalidExpr}"

private def trimAsciiString (s : String) : String :=
  s.trimAscii.toString

private def lastDottedComponent (s : String) : String :=
  ((trimAsciiString s).splitOn ".").getLast!

/-- Try to recognize a "simple invariant" in the pretty-printed Prop and
    return a Lean-source lambda `fun h => { h with f := <bad raw> }` that
    flips one field to a value violating the invariant. Returns `none` if
    the Prop doesn't fit any auto-violator pattern (e.g. complex
    conjunctions, function-call witnesses).

    Supported patterns:
      *  `<f>.toNat = <n>`        → set `<f>` to `(n+1).toUIntN`
      *  `<f> = <Path>.<ctor>`    → set `<f>` to a *different* nullary case's raw
      *  `<f> ≠ <Path>.<ctor>`    → set `<f>` to `<ctor>`'s raw
      *  `<f> = … ∨ <f> = …`      → set `<f>` to a case mentioned in *neither*

    For each, the field has to be a known field of the record with known
    `enumNullaries` (for the enum cases) or `rawType` (for `.toNat = N`). -/
private def autoViolator (fs : List FieldSpec) (prop : String) : Option String :=
  let prop := trimAsciiString prop
  -- Disjunction first (its disjuncts contain `=` substrings).
  if (prop.splitOn " ∨ ").length > 1 then
    let disjuncts := prop.splitOn " ∨ "
    let parsed : List (Option (String × String)) := disjuncts.map fun d =>
      match d.splitOn " = " with
      | [lhs, rhs] => some (trimAsciiString lhs, lastDottedComponent rhs)
      | _          => none
    if parsed.all Option.isSome then
      let unwrapped := parsed.filterMap id
      let firstField := (unwrapped.head!).1
      if unwrapped.all (·.1 = firstField) then
        let mentionedCtors : List String := unwrapped.map (·.2)
        match fs.find? (·.name = firstField) with
        | some f =>
          match f.enumNullaries.find? (fun (cn, _) => !mentionedCtors.contains cn) with
          | some (_, v) => some s!"fun h => \{ h with {firstField} := {v} }"
          | none => none
        | none => none
      else none
    else none
  -- `<f>.toNat = <n>`
  else if let some (field, numStr) := (match prop.splitOn ".toNat = " with
                                       | [a, b] => some (trimAsciiString a, trimAsciiString b)
                                       | _      => none) then
    match fs.find? (·.name = field), numStr.toNat? with
    | some f, some n =>
      let cast := match f.rawType with
        | "UInt8"  => "toUInt8"
        | "UInt16" => "toUInt16"
        | "UInt32" => "toUInt32"
        | _        => "toUInt64"
      some s!"fun h => \{ h with {field} := ({n+1}).{cast} }"
    | _, _ => none
  -- `<f> ≠ <Path>.<ctor>`
  else if let some (field, ctor) := (match prop.splitOn " ≠ " with
                                     | [a, b] => some (trimAsciiString a, lastDottedComponent b)
                                     | _      => none) then
    match fs.find? (·.name = field) with
    | some f =>
      match f.enumNullaries.find? (·.1 = ctor) with
      | some (_, v) => some s!"fun h => \{ h with {field} := {v} }"
      | none => none
    | none => none
  -- `<f> = <Path>.<ctor>`
  else if let some (field, ctor) := (match prop.splitOn " = " with
                                     | [a, b] => some (trimAsciiString a, lastDottedComponent b)
                                     | _      => none) then
    match fs.find? (·.name = field) with
    | some f =>
      match f.enumNullaries.find? (·.1 ≠ ctor) with
      | some (_, v) => some s!"fun h => \{ h with {field} := {v} }"
      | none => none
    | none => none
  else none

/-- The whole `elf_record` elaborator. -/
@[command_elab elfRecord]
def elabElfRecord : CommandElab := fun stx => do
  let recName     : String := stx[1].getId.toString
  let rawName     : String := s!"Raw{recName}"
  let decodedName : String := s!"{recName}.Decoded"
  let fields      : Array (TSyntax `WhatTheElf.elfField) := stx[3].getArgs.map (⟨·⟩)
  let invs        : Array (TSyntax `WhatTheElf.elfInv) :=
    if stx[4].getNumArgs = 0 then #[] else stx[4][1].getArgs.map (⟨·⟩)
  -- 1. Inline enums.
  for f in fields do
    if let `(elfField| $fName:ident :
              $b:ident { $[$cases:elfEnumCase],* }) := f then
      let some (rawTy, _, _, _) := baseInfo? b.getId.toString
        | throwError s!"elf_record: enum block over non-primitive type `{b.getId}`"
      let parsed ← cases.mapM parseEnumCase
      let enumName := s!"{recName}.{deriveImplicitName fName.getId.toString}"
      emitInlineEnum enumName rawTy parsed

  let fs ← fields.mapM (fieldSpec recName)
  let is ← invs.mapM invSpec
  let names := fs.toList.map (·.name)
  let ctorBindings := String.intercalate ", " names

  -- 2. Static byte size.
  let sizeExpr := String.intercalate " + " (fs.toList.map (·.sizeExpr))
  parseAndElab s!"def {recName}.size : Nat := {sizeExpr}"

  -- 3. Raw structure (raw widths / ByteArrays / sub-record Raws). We derive
  --    `BEq` so round-trip tests can write `read (write x) = .ok x`
  --    without hand-rolling a per-field comparison.
  let rawLines := fs.toList.map fun f => s!"  {f.name} : {f.rawType}"
  parseAndElab <|
    s!"structure {rawName} where\n" ++ String.intercalate "\n" rawLines ++
    "\n  deriving Repr, Inhabited, BEq"

  -- 4. RawT.read: sized ByteArray in, RawT out. Internal Cursor.
  let readSteps := String.intercalate "\n" (fs.toList.map (·.readStep))
  parseAndElab <|
    s!"def {rawName}.read (bs : ByteArray) : Except String {rawName} := do\n" ++
    s!"  if bs.size < {recName}.size then\n" ++
    s!"    .error s!\"{rawName}.read: short read, need \{{recName}.size}, got \{bs.size}\"\n" ++
    s!"  else\n" ++
    s!"  let c := WhatTheElf.Cursor.ofBytes bs\n" ++
    readSteps ++ "\n" ++
    s!"  return \{ {ctorBindings} : {rawName} }"

  -- 4b. RawT.write: serialize a Raw value back to bytes. Inverse of `read`.
  let writeSteps := String.intercalate "\n" (fs.toList.map (·.writeStep))
  parseAndElab <|
    s!"def {rawName}.write (r : {rawName}) : ByteArray :=\n" ++
    s!"  let bs : ByteArray := ByteArray.empty\n" ++
    writeSteps ++ "\n" ++
    s!"  bs"

  -- 5. Decoded structure (typed enums; no Props yet).
  let decodedLines := fs.toList.map fun f => s!"  {f.name} : {f.decodedType}"
  parseAndElab <|
    s!"structure {decodedName} where\n" ++ String.intercalate "\n" decodedLines ++
    "\n  deriving Repr, Inhabited"

  -- 6. RawT.decode: apply each enum's `ofRaw`; pass-through non-enum fields.
  let decodeSteps := String.intercalate "\n" (fs.toList.map (·.decodeStep))
  parseAndElab <|
    s!"def {rawName}.decode (r : {rawName}) : Except String {decodedName} := do\n" ++
    decodeSteps ++ "\n" ++
    s!"  return \{ {ctorBindings} : {decodedName} }"

  -- 7. Canonical T extends Decoded with one Prop field per invariant.
  let invFields := is.toList.map fun i => s!"  {i.name} : {i.prop}"
  let invBlock  := if invFields.isEmpty then "" else String.intercalate "\n" invFields ++ "\n"
  parseAndElab <|
    s!"structure {recName} extends {decodedName} where\n" ++ invBlock ++ "  deriving Repr"

  -- 8. T.Decoded.check: bind each field as `let f := h.f` (def-equal to the
  -- projection) so the user's invariant terms can refer to bare names; then
  -- chained `if h : inv then … else …`. The canonical T is constructed with
  -- `{ toDecoded := h, inv₁, inv₂, … }`.
  let invNames := is.toList.map (·.name)
  let checkedCtor :=
    s!"\{ toDecoded := h" ++
    String.join (invNames.map fun n => s!", {n}") ++ " }"
  let projBindings := String.intercalate "\n"
                        (names.map fun n => s!"  let {n} := h.{n}")
  let ifChain   := String.intercalate "\n" (is.toList.map fun i =>
                     s!"  if {i.name} : {i.prop} then")
  let elseChain := String.intercalate "\n" (is.toList.reverse.map fun i =>
                     s!"  else .error \"constraint '{i.name}' violated\"")
  parseAndElab <|
    s!"def {decodedName}.check (h : {decodedName}) : Except String {recName} :=\n" ++
    projBindings ++ "\n" ++
    (if ifChain.isEmpty then "" else ifChain ++ "\n") ++
    s!"  .ok {checkedCtor}" ++
    (if elseChain.isEmpty then "" else "\n" ++ elseChain)

  -- 9. T.parse = read ∘ decode ∘ check.
  parseAndElab <|
    s!"def {recName}.parse (bs : ByteArray) : Except String {recName} := do\n" ++
    s!"  let raw ← {rawName}.read bs\n" ++
    s!"  let dec ← {rawName}.decode raw\n" ++
    s!"  {decodedName}.check dec"

  -- 10. ToJsonStr for the canonical T. The body references `h.field` —
  -- those resolve via the `extends T.Decoded` projection. Built via plain
  -- concatenation because the target itself contains many `"` characters.
  let q  := "\""          -- one literal " character
  let bq := "\\\""        -- the source `\"` (= a quoted-" inside another string)
  let chunk (sep name : String) : String :=
    q ++ sep ++ bq ++ name ++ bq ++ ":" ++ q ++ " ++ WhatTheElf.toJsonStr h." ++ name
  let pieces := (List.range fs.size).zip fs.toList |>.map fun (i, f) =>
    chunk (if i = 0 then "" else ",") f.name
  let body :=
    q ++ "{" ++ q ++ " ++ " ++ String.intercalate " ++ " pieces ++ " ++ " ++ q ++ "}" ++ q
  parseAndElab <|
    s!"instance : WhatTheElf.ToJsonStr {recName} where\n" ++
    s!"  toJsonStr h := " ++ body

  -- 11. `Parser` instance so generic `parseTable` can iterate tables of T.
  parseAndElab <|
    s!"instance : WhatTheElf.Parser {recName} where\n" ++
    s!"  size  := {recName}.size\n" ++
    s!"  parse := {recName}.parse"

  -- 12. `invariantViolators`: one entry per invariant the auto-violator
  -- pattern matcher could handle. Each entry is `(name, override)` where
  -- `override : RawT → RawT` flips a single field to a value that breaks
  -- exactly that one invariant (and ideally no others). The fuzz/diff
  -- harness loops over this list to emit one fixture per invariant
  -- without hand-picking values.
  let violatorEntries : List String := is.toList.filterMap fun i =>
    autoViolator fs.toList i.prop |>.map fun lam => s!"  (\"{i.name}\", {lam})"
  let listBody :=
    if violatorEntries.isEmpty then "[]"
    else "[\n" ++ String.intercalate ",\n" violatorEntries ++ "\n]"
  parseAndElab <|
    s!"def {recName}.invariantViolators : List (String × ({rawName} → {rawName})) :=\n" ++
    listBody

  -- 12b. `invariantPropStrings`: parallel list of `(name, prop_text)` for
  -- every invariant — handy for debugging the auto-violator pattern
  -- matcher when an expected violator doesn't show up in the list above.
  let propEntries : List String := is.toList.map fun i =>
    "  (" ++ "\"" ++ i.name ++ "\", " ++ "\"" ++ i.prop ++ "\")"
  let propsBody :=
    if propEntries.isEmpty then "[]"
    else "[\n" ++ String.intercalate ",\n" propEntries ++ "\n]"
  parseAndElab <|
    s!"def {recName}.invariantPropStrings : List (String × String) :=\n" ++
    propsBody

  -- 13. `fieldOffsets`: byte offset of each field within RawT, for use by
  -- truncation fixtures. Each entry pairs a field name with the byte index
  -- where its serialized form starts (i.e. the sum of all preceding
  -- fields' sizes). Truncating bytes to that offset produces a file that
  -- can read all earlier fields but fails on this one — surfaced as a
  -- short-read error from the corresponding `Cursor.u8`/`u16le`/... call.
  -- Only emitted when every field has a numeric `sizeExpr` (no embedded
  -- sub-records); skipped otherwise.
  let allNumeric := fs.toList.all fun f => f.sizeExpr.toNat?.isSome
  if allNumeric then
    let mut runningOff : Nat := 0
    let mut offEntries : List String := []
    for f in fs do
      offEntries := offEntries ++ [s!"  (\"{f.name}\", {runningOff})"]
      runningOff := runningOff + f.sizeExpr.toNat!
    parseAndElab <|
      s!"def {recName}.fieldOffsets : List (String × Nat) :=\n" ++
      (if offEntries.isEmpty then "  []"
       else "[\n" ++ String.intercalate ",\n" offEntries ++ "\n]")

end WhatTheElf
