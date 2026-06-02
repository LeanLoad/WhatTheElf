//! Fuzzer-found loader crashes (see [`crate::crash::Crash`]).
//!
//! Every crash here reproduces on the stock system loader. They flow through the
//! same `gen` -> `fixtures/` -> `check` pipeline as [`crate::cases`], via `id`
//! and [`crate::crash::Crash::image`].
pub mod glibc;
pub mod musl;
pub mod objdump;
pub mod qemu;

use crate::crash::Crash;

pub const ALL: &[Crash] = &[
    // glibc ld.so --verify
    glibc::LOAD_MEMSZ_PAST_EOF,
    glibc::LOAD_WILD_VADDR_PHDR,
    glibc::DYN_LSONAME_OOB,
    glibc::RTLD_STARTUP_STRCMP,
    glibc::WILD_VADDR_ASLR,
    // musl ld-musl --list (one per distinct fault site)
    musl::MUSL_SYSV_LOOKUP_261,
    musl::MUSL_RELOC_ALL_430,
    musl::MUSL_LOAD_DIRECT_DEPS_1067,
    musl::MUSL_DO_RELR_RELOCS_570,
    musl::MUSL___DLS3_1414,
    musl::MUSL_MEMSET_847,
    musl::MUSL_DO_RELOCS_473,
    musl::MUSL_DO_RELOCS_486,
    musl::MUSL_DO_RELOCS_345,
    musl::MUSL___DLS3_852,
    musl::MUSL_MEMCPY_66,
    // qemu-user's own loader (qemu-x86_64), pre-guest
    qemu::PGB_DYNAMIC_ASSERT,
    qemu::GLIB_OOM,
    // llvm-objdump (FRIDA-mode binary-only fuzzing)
    objdump::SO_SIGSEGV,
];
