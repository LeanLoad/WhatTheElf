/-
Root scalar types + byte-level read primitives + JSON-as-`String` encoder.

`Addr` / `Off` are reducible aliases for `UInt64` mirroring the gabi
`Elf64_Addr` / `Elf64_Off` typedefs; specs that want spec-color can write
`e_entry : Addr` rather than `e_entry : UInt64`. `Cursor` is the parser
state — the shared `(bytes, pos)` view every decoder threads.

JSON output uses a tiny home-grown `ToJsonStr` typeclass that produces a
compact `String` directly. We deliberately avoid `Lean.Data.Json` — the
motivation was a minimal-runtime build target (WASM) which is no longer
pursued, but the lean dependency surface is worth keeping anyway.

Spec note: gabi 02 § ELF Identification permits either byte order; LeanLoad /
WhatTheElf target little-endian psABIs (`ELFDATA2LSB`) and reject the rest
at parse time, so we only ship LE readers.
-/

namespace WhatTheElf

-- ── gabi typedefs (reducible aliases over UInt64) ────────────────────

/-- gabi `Elf64_Addr`: a 64-bit virtual address. Reducible alias over
    `UInt64`; all `UInt64` operations apply transparently. -/
abbrev Addr : Type := UInt64

/-- gabi `Elf64_Off`: a 64-bit file offset. Reducible alias over `UInt64`. -/
abbrev Off : Type := UInt64

-- ── Cursor + byte-level decoders ─────────────────────────────────────

/-- Parser state: an immutable byte buffer plus the current read offset. -/
structure Cursor where
  bytes : ByteArray
  pos   : Nat

namespace Cursor

def ofBytes (b : ByteArray) : Cursor := { bytes := b, pos := 0 }
def remaining (c : Cursor) : Nat := c.bytes.size - c.pos

/-- Read one byte and advance; EOF is an error. -/
def u8 (c : Cursor) : Except String (UInt8 × Cursor) :=
  if h : c.pos < c.bytes.size then
    .ok (c.bytes[c.pos]'h, { c with pos := c.pos + 1 })
  else
    .error s!"u8: EOF at offset {c.pos}/{c.bytes.size}"

def u16le (c : Cursor) : Except String (UInt16 × Cursor) := do
  let (lo, c) ← c.u8
  let (hi, c) ← c.u8
  return (lo.toUInt16 ||| (hi.toUInt16 <<< 8), c)

def u32le (c : Cursor) : Except String (UInt32 × Cursor) := do
  let (lo, c) ← c.u16le
  let (hi, c) ← c.u16le
  return (lo.toUInt32 ||| (hi.toUInt32 <<< 16), c)

def u64le (c : Cursor) : Except String (UInt64 × Cursor) := do
  let (lo, c) ← c.u32le
  let (hi, c) ← c.u32le
  return (lo.toUInt64 ||| (hi.toUInt64 <<< 32), c)

/-- Read exactly `n` bytes into a fresh `ByteArray`. -/
def readBytes (c : Cursor) (n : Nat) : Except String (ByteArray × Cursor) :=
  if c.pos + n ≤ c.bytes.size then
    .ok (c.bytes.extract c.pos (c.pos + n), { c with pos := c.pos + n })
  else
    .error s!"bytes: requested {n} bytes at offset {c.pos}, file size {c.bytes.size}"

end Cursor
end WhatTheElf

-- ── ByteArray builders (mirror of the `Cursor` readers) ─────────────
-- Defined at top level so the macro can emit `bs.pushUInt32LE r.foo` and
-- have it resolve via Lean's dot-notation on `ByteArray`.

/-- Append a little-endian `UInt16` to a byte buffer. -/
def ByteArray.pushUInt16LE (bs : ByteArray) (v : UInt16) : ByteArray :=
  bs.push v.toUInt8 |>.push (v >>> 8).toUInt8

/-- Append a little-endian `UInt32` to a byte buffer. -/
def ByteArray.pushUInt32LE (bs : ByteArray) (v : UInt32) : ByteArray :=
  bs.push v.toUInt8
  |>.push (v >>> 8).toUInt8
  |>.push (v >>> 16).toUInt8
  |>.push (v >>> 24).toUInt8

/-- Append a little-endian `UInt64` to a byte buffer. -/
def ByteArray.pushUInt64LE (bs : ByteArray) (v : UInt64) : ByteArray :=
  bs.push v.toUInt8
  |>.push (v >>> 8).toUInt8
  |>.push (v >>> 16).toUInt8
  |>.push (v >>> 24).toUInt8
  |>.push (v >>> 32).toUInt8
  |>.push (v >>> 40).toUInt8
  |>.push (v >>> 48).toUInt8
  |>.push (v >>> 56).toUInt8

namespace WhatTheElf

-- ── JSON-as-`String` encoder ─────────────────────────────────────────

/-- A type that knows how to render itself as JSON, directly as a `String`.
    Compact (no whitespace), no intermediate `Json` ADT, no `libLean`. -/
class ToJsonStr (α : Type) where
  toJsonStr : α → String

export ToJsonStr (toJsonStr)

/-- Escape a `String` for use inside a JSON string literal — quotes and
    control bytes get backslash-escaped. -/
def jsonEscape (s : String) : String :=
  let escape : Char → String := fun
    | '\\' => "\\\\"
    | '"'  => "\\\""
    | '\n' => "\\n"
    | '\r' => "\\r"
    | '\t' => "\\t"
    | c    => c.toString
  "\"" ++ String.join (s.toList.map escape) ++ "\""

instance : ToJsonStr Bool   where toJsonStr b := if b then "true" else "false"
instance : ToJsonStr Nat    where toJsonStr n := toString n
instance : ToJsonStr UInt8  where toJsonStr n := toString n.toNat
instance : ToJsonStr UInt16 where toJsonStr n := toString n.toNat
instance : ToJsonStr UInt32 where toJsonStr n := toString n.toNat
/-- 64-bit ints become decimal strings so JS `number` precision is preserved.
    `Addr` / `Off` are reducible aliases over `UInt64` and share this instance. -/
instance : ToJsonStr UInt64 where toJsonStr n := s!"\"{n.toNat}\""
instance : ToJsonStr String where toJsonStr := jsonEscape

instance : Repr ByteArray where reprPrec b prec := reprPrec b.data prec
instance : ToJsonStr ByteArray where
  toJsonStr b := "[" ++ String.intercalate "," (b.toList.map (toString ·.toNat)) ++ "]"

/-- Render an `Array` as a JSON array. -/
instance [ToJsonStr α] : ToJsonStr (Array α) where
  toJsonStr xs := "[" ++ String.intercalate "," (xs.toList.map toJsonStr) ++ "]"

/-- `Option`: `none` → JSON `null`, `some x` → `toJsonStr x`. -/
instance [ToJsonStr α] : ToJsonStr (Option α) where
  toJsonStr
    | none   => "null"
    | some x => toJsonStr x

-- ── Generic table parsing ────────────────────────────────────────────

/-- A type with a fixed on-disk binary size and a parser from a sized
    buffer. The macro auto-emits an instance per `elf_record`. -/
class Parser (α : Type) where
  /-- Bytes per entry on disk. -/
  size  : Nat
  /-- Parse a single entry from a buffer of at least `size` bytes. -/
  parse : ByteArray → Except String α

/-- Where a homogeneous run of records lives in a file. `stride` may exceed
    the entry's natural size (gabi permits per-table padding via the parent
    record's `*entsize` field). -/
structure TableLayout where
  offset : Nat
  stride : Nat
  count  : Nat
  deriving Repr

instance : ToJsonStr TableLayout where
  toJsonStr l :=
    "{\"offset\":" ++ toJsonStr l.offset ++
    ",\"stride\":" ++ toJsonStr l.stride ++
    ",\"count\":"  ++ toJsonStr l.count  ++ "}"

/-- Parse a table of `α` entries from `file` according to `layout`. Stops on
    the first failure and tags the error with the entry index + byte offset. -/
def parseTable [Parser α] (file : ByteArray) (layout : TableLayout) :
    Except String (Array α) := Id.run do
  let entSize := Parser.size α
  let mut out := Array.mkEmpty layout.count
  let mut err : Option String := none
  for i in [0:layout.count] do
    if err.isSome then break
    let off := layout.offset + i * layout.stride
    let entry := file.extract off (off + entSize)
    match Parser.parse (α := α) entry with
    | .ok x    => out := out.push x
    | .error e => err := some s!"[{i}] @ off={off}: {e}"
  return match err with
    | some e => .error e
    | none   => .ok out

end WhatTheElf
