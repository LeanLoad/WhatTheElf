//! Crashes in **llvm-objdump**, found by AFL++ FRIDA-mode (binary-only) fuzzing
//! of the installed `llvm-objdump -p` — no LLVM rebuild. Reproduce on the stock
//! binary.
use crate::crash::{Crash, Repro::RawArtifact, Signal::Segv, Target::LlvmObjdump};
use crate::elf::ImageSpec;

/// SIGSEGV in LLVM's object-file parser on a mutated shared object.
pub const SO_SIGSEGV: Crash = Crash {
    id: "objdump_so_sigsegv",
    target: LlvmObjdump,
    signal: Segv,
    site: "LLVM object parser (llvm-objdump -p)",
    repro: RawArtifact,
    details: "Mutating a valid shared object and parsing it with `llvm-objdump -p` SIGSEGVs \
inside LLVM's object-file parsing — LLVM's crash handler fires (\"PLEASE submit a bug report \
to the LLVM project\"). Found by AFL++ FRIDA-mode binary-only fuzzing of the installed tool; \
the distribution binary is stripped so the exact LLVM function is not pinned down. Confirmed \
to reproduce on stock llvm-objdump 18.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/objdump_00_so_sigsegv.elf").to_vec()),
};
