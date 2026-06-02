//! Crashes in glibc's `ld.so --verify`.
//!
//! Where the mechanism is fully understood the case is an understandable
//! structured reproducer built from the ELF builders; where the crash depends on
//! the loader walking off into garbage memory (no clean structural form) the raw
//! fuzzer artifact is kept (`crashes/*.elf`). All reproduce on the stock system
//! loader (glibc 2.39).
//!
//! `--verify` is not just a header check: `_dl_map_object_from_fd` (dl-load.c)
//! mmaps the program-header segments and re-walks them, so most faults are in
//! the mapping / dynamic-section handling rather than header validation.
use crate::crash::{Crash, Target::Glibc, Repro::*, Signal::*};
use crate::elf::{Ehdr, ImageSpec, Phdr, PF_R, PF_W, PF_X, PT_LOAD};

/// Structured reproducer. Reduced from `crashes/glibc_00_sig7.elf`.
pub const LOAD_MEMSZ_PAST_EOF: Crash = Crash {
    id: "glibc_load_memsz_past_eof",
    target: Glibc,
    signal: Bus,
    site: "_dl_map_segments memset (dl-map-segments.h:177)",
    repro: Structured,
    details: "A single PT_LOAD declares p_filesz=0x1800 and p_memsz=0x2000 in a file that \
is only 0xc0 bytes long. _dl_map_segments mmaps the segment from the (short) file, then \
zero-fills the gap between p_filesz and the end of the segment's last page with \
`memset((void *) zero, 0, zeropage - zero)` (dl-map-segments.h:177) to create the .bss. \
Because p_filesz points past the real end of the file, that page has no file backing and \
the store raises SIGBUS. The original fuzzer artifact (crashes/glibc_00_sig7.elf) used a \
176-byte file with p_memsz≈0x6_0000_0002, giving the loader a 24 GiB maplength; the \
reproducer keeps the essential condition (filesz/memsz past EOF, memsz>filesz) minimal.",
    spec: || {
        ImageSpec::new(0xc0, Ehdr::exec64().phoff(0x40).phnum(1).entry(0x10000)).phdr(
            Phdr::new(PT_LOAD)
                .flags(PF_R | PF_W)
                .offset(0)
                .vaddr(0x10000)
                .paddr(0x10000)
                .filesz(0x1800)
                .memsz(0x2000)
                .align(0x1000),
        )
    },
};

/// Structured reproducer. Reduced from `crashes/glibc_01_sig11.elf`.
pub const LOAD_WILD_VADDR_PHDR: Crash = Crash {
    id: "glibc_load_wild_vaddr_phdr",
    target: Glibc,
    signal: Bus,
    site: "_dl_map_object_from_fd phdr rescan (dl-load.c:1342)",
    repro: Structured,
    details: "After mapping the segments, _dl_map_object_from_fd walks the program headers \
backward looking for PT_GNU_PROPERTY: `for (ph = &l->l_phdr[l->l_phnum]; ph != l->l_phdr; \
--ph) if (ph[-1].p_type == PT_GNU_PROPERTY)` (dl-load.c:1342). l->l_phdr is derived from \
the load layout / PT_PHDR. The first PT_LOAD here has a wild p_vaddr (0xb000_0000), \
p_filesz=0xb000_0000 and an absurd p_align (0x0600_0000_0200_0000), so the address glibc \
computes for l_phdr does not fall inside any mapped segment and dereferencing ph[-1] faults \
(SIGSEGV, or SIGBUS when the bad address lands on a file-backed page past EOF). The second \
PT_LOAD provides the offset/vaddr mismatch that drives l_phdr off the mapping. Reduced from \
crashes/glibc_01_sig11.elf (the corpus also held byte-variants glibc_02/03/05).",
    spec: || {
        ImageSpec::new(0xb0, Ehdr::exec64().phoff(0x40).phnum(2).entry(0x400080))
            .phdr(
                Phdr::new(PT_LOAD)
                    .flags(PF_X)
                    .offset(0)
                    .vaddr(0xb0000000)
                    .paddr(0xb0000000)
                    .filesz(0xb0000000)
                    .memsz(0x10_0000_0000)
                    .align(0x0600_0000_0200_0000),
            )
            .phdr(
                Phdr::new(PT_LOAD)
                    .flags(PF_R)
                    .offset(0x8_b000_0000)
                    .vaddr(0x6000_0000)
                    .paddr(0x6000_0000)
                    .filesz(0x6000_0000)
                    .memsz(0x0800_0000)
                    .align(0),
            )
    },
};

/// Raw artifact: the malformed PT_DYNAMIC makes the dynamic walk run into
/// garbage, so there is no clean structural form. `crashes/glibc_07_sig11.elf`.
pub const DYN_LSONAME_OOB: Crash = Crash {
    id: "glibc_dyn_lsoname_oob",
    target: Glibc,
    signal: Segv,
    site: "l_soname (ldsodefs.h:99, from dl-load.c:1429)",
    repro: RawArtifact,
    details: "The object pairs a PT_LOAD (vaddr 0xb000_0000) with a PT_DYNAMIC at p_offset=0xe, \
vaddr 0xb000_0000 (overlapping the load) and p_filesz=0xffff_b000_0080_0000. \
_dl_map_object_from_fd reaches the 'did we just load libc.so?' check at dl-load.c:1429: \
`l_soname(l) != NULL && strcmp(l_soname(l), LIBC_SO)`. l_soname returns \
`D_PTR(l, l_info[DT_STRTAB]) + l_info[DT_SONAME]->d_un.d_val` (ldsodefs.h:99). \
elf_get_dynamic_info populated l_info[] by walking the dynamic array until DT_NULL, but the \
overlapping/oversized PT_DYNAMIC makes that walk run past the mapped bytes into adjacent \
memory; an entry there looks like DT_SONAME/DT_STRTAB pointing out of the mapping, so \
l_soname dereferences a wild l_info[] pointer and faults.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/glibc_07_sig11.elf").to_vec()),
};

/// Raw artifact: data flow is inlined away under -O2 and not fully pinned.
/// `crashes/glibc_04_sig11.elf`.
pub const RTLD_STARTUP_STRCMP: Crash = Crash {
    id: "glibc_rtld_startup_strcmp",
    target: Glibc,
    signal: Segv,
    site: "strcmp from dl_main start-up (rtld.c:1687)",
    repro: RawArtifact,
    details: "A 203-byte object with a PT_LOAD plus a PT_INTERP whose fields are wildly out of \
range (p_filesz=0x3e00_0200_0000_0000, p_offset=0xb0_0000_0000_0000) and no valid \
PT_DYNAMIC. The instrumented build faults in strcmp (strcmp-sse2.S:160) with the caller \
attributed to dl_main at rtld.c:1687 — the start-up step that reconciles the loader's own \
libname with its soname. strcmp dereferences a string pointer that ends up out of range, \
but at -O2 the rtld start-up code is heavily inlined, so the exact field->pointer chain is \
not fully pinned down; this is recorded honestly as an observed SIGSEGV string-deref reached \
from that code rather than a clean reproducer. glibc_06 is a second byte-variant.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/glibc_04_sig11.elf").to_vec()),
};

/// Raw artifact: layout-sensitive variant of [`LOAD_WILD_VADDR_PHDR`] that
/// faults only under ASLR (not under gdb), so a deterministic builder cannot pin
/// it. `crashes/glibc_03_sig11.elf`.
pub const WILD_VADDR_ASLR: Crash = Crash {
    id: "glibc_wild_vaddr_aslr",
    target: Glibc,
    signal: Segv,
    site: "_dl_map_object_from_fd phdr rescan (dl-load.c:1342)",
    repro: RawArtifact,
    details: "Two PT_LOADs with wild p_vaddr/p_offset, same family as glibc_load_wild_vaddr_phdr: \
the loader computes l_phdr outside the real mapping. Here whether the computed address hits \
an unmapped page depends on the randomized mmap base, so it SIGSEGVs under normal ASLR but \
runs clean under gdb (ASLR disabled). Kept as the raw artifact because the trigger is \
layout-dependent and not reproducible deterministically.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/glibc_03_sig11.elf").to_vec()),
};
