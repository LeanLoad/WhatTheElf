/-
WhatTheElf CLI. Reads stdin as ELF bytes, parses the header, prints a
JSON-shaped summary to stdout.

Output protocol (one line of JSON):
  {"ok":true,  "header": { ... fields ... }}
  {"ok":false, "error":  "..."}

Everything is encoded via `WhatTheElf.ToJsonStr`, a tiny home-grown
`String`-producing typeclass — no `Lean.Data.Json` dependency. (The motivation
was a minimal-runtime build target like WASM; we kept the lean dependency
even after abandoning that target.)
-/

import WhatTheElf

open WhatTheElf

def readAllStdin : IO ByteArray := do
  let stdin ← IO.getStdin
  let mut buf : ByteArray := ByteArray.empty
  while true do
    let chunk ← stdin.read 65536
    if chunk.isEmpty then break
    buf := buf ++ chunk
  return buf

def main : IO UInt32 := do
  let data ← readAllStdin
  match Elf64_File.parse data with
  | .ok file =>
      IO.println ("{\"ok\":true,\"file\":" ++ toJsonStr file ++ "}")
      return 0
  | .error e =>
      IO.println ("{\"ok\":false,\"error\":" ++ jsonEscape e ++ "}")
      return 1
