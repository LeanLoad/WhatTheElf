/-
Elaboration-time fuzz: every synthetic fixture from `EmitFixtures.lean`
parsed through `Elf64_File.parse` and compared against its expected
verdict. This is the same check the Python differential harness does,
but in-process: failures show up as Lean build errors.

The fixture list (`EmitFixtures.fixtures`) is the single source of
truth — adding a new synthetic fixture there automatically extends the
coverage here. Fixtures of category `real_binary` are skipped (their
bytes are loaded from system paths at emit time, not from the Lean
value).

Why have this alongside the Python diff?

  * `lake build Tests` is the single command that proves the parser
    still upholds every fixture's expected behavior. No external
    tooling (Python, system binaries) required.
  * Catches regressions before they reach `emit_fixtures` + the
    differential harness, with much faster feedback.
-/

import Fixtures
import EmitFixtures

open WhatTheElf
open WhatTheElf.Test

/-- True iff our parser's verdict on `bs` matches `expected`. -/
private def fixtureAgrees (expected : Bool) (bs : ByteArray) : Bool :=
  match Elf64_File.parse bs with
  | .ok _    => expected
  | .error _ => !expected

/-- Every fixture with a Lean-side `bytes` value (so all synthetic ones)
    must agree with its `ourVerdict`. We materialize a single `Bool` —
    `true` iff every applicable fixture agrees — so a failure surfaces
    as the `#guard` below being false.

    Mismatches are accumulated into a side-channel `Array String` via
    `partition`; the result includes both the boolean and the list so
    a future test runner could surface offending names. -/
def fuzzAgreement : Bool × Array String := Id.run do
  let mut allOk : Bool := true
  let mut mismatches : Array String := #[]
  for f in fixtures do
    match f.bytes with
    | none    => continue            -- real_binary: skipped
    | some bs =>
      if ¬ fixtureAgrees f.ourVerdict bs then
        allOk := false
        mismatches := mismatches.push f.name
  return (allOk, mismatches)

/- The headline assertion: every synthetic fixture's behavior matches
   what `EmitFixtures.lean` claims. If this fails, the `mismatches`
   list (second component of `fuzzAgreement`) names the offenders. -/
#guard fuzzAgreement.1

/- The mismatches list is empty when everything agrees — surfaced as
   its own guard so a regression names which fixture broke. -/
#guard fuzzAgreement.2.isEmpty
