import Lake
open Lake DSL

package "WhatTheElf" where
  version := v!"0.1.0"

@[default_target]
lean_lib «WhatTheElf» where

@[default_target]
lean_exe «whattheelf» where
  root := `Main

/-- Tests live in `tests/` and check parser behavior via `#guard`. Built
    with `lake build Tests`; failures show up as elaboration errors. -/
lean_lib «Tests» where
  srcDir := "tests"
  roots := #[`Fixtures, `Negative, `FuzzGuard]

/-- Emit fixture ELFs to disk for cross-parser differential testing.
    Run via `lake build emit_fixtures && ./.lake/build/bin/emit_fixtures <dir>`. -/
lean_exe «emit_fixtures» where
  root := `EmitFixtures
  srcDir := "tests"

/-- Round-trip-check `RawT.write ∘ RawT.read = id` on real-binary input.
    Run via `lake build roundtrip_check && ./.lake/build/bin/roundtrip_check [files...]`. -/
lean_exe «roundtrip_check» where
  root := `RoundtripCheck
  srcDir := "tests"
