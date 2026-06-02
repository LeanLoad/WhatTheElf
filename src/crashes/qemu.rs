//! Crashes in **qemu-user**'s own ELF loader (`qemu-x86_64`), before the guest
//! program ever runs — found by running malformed ELFs through the emulator (the
//! `qemu-x86_64` check backend). Raw artifacts copied from the triggering
//! fixtures; both reproduce on the stock qemu-user.
use crate::crash::{Crash, Repro::RawArtifact, Signal::Abort, Target::Qemu};
use crate::elf::ImageSpec;

/// qemu-user aborts in its own loader laying out the guest address space.
pub const PGB_DYNAMIC_ASSERT: Crash = Crash {
    id: "qemu_pgb_dynamic_assert",
    target: Qemu,
    signal: Abort,
    site: "pgb_dynamic assertion (linux-user/elfload.c:3019)",
    repro: RawArtifact,
    details: "qemu-user aborts in its own ELF loader, before launching the guest: pgb_dynamic \
asserts `QEMU_IS_ALIGNED(guest_loaddr, align)` (linux-user/elfload.c:3019). A malformed \
PT_LOAD vaddr/alignment violates the guest-base alignment qemu assumes while laying out the \
guest address space. Triggered here by the note_truncated_header fixture; several \
note_*/phdr_* inputs reach the same assertion.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/qemu_00_pgb_dynamic_assert.elf").to_vec()),
};

/// qemu-user's GLib allocator aborts on an absurd allocation request.
pub const GLIB_OOM: Crash = Crash {
    id: "qemu_glib_oom",
    target: Qemu,
    signal: Abort,
    site: "GLib g_malloc abort (glib/gmem.c:106)",
    repro: RawArtifact,
    details: "qemu-user's GLib allocator aborts trying to satisfy an absurd allocation — \
\"failed to allocate 4467573029374787584 bytes\" (~4 EB, glib/gmem.c:106) — a size derived \
from a bogus field in the malformed ELF and requested during loader setup, before the guest \
runs. Triggered by the glibc_rtld_startup_strcmp input, which also crashes glibc.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/qemu_01_glib_oom.elf").to_vec()),
};
