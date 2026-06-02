//! Crashes found by fuzzing glibc's `ld.so --verify`, plus understandable
//! reconstructions of them.
//!
//! AFL++ produced opaque crashing blobs (kept under `crashes/`). Where the
//! mechanism is fully understood we prefer a *structured reproducer* built from
//! the ELF builders, so the malformation is legible; the original raw artifact
//! is noted in `details` for provenance. Where the crash depends on the loader
//! walking off into garbage memory (so there is no clean structural form), we
//! keep the raw artifact and explain the path in `details`.
//!
//! `--verify` is not just a header check: `_dl_map_object_from_fd` (dl-load.c)
//! mmaps the program-header segments and re-walks them, so most faults are in
//! the mapping / dynamic-section handling rather than header validation.
//!
//! All cases reproduce on the unmodified system loader (glibc 2.39).
use crate::case::{Case, Tag};
use crate::elf::{Ehdr, ImageSpec, Phdr, PF_R, PF_W, PF_X, PT_LOAD};

// ---- understood -> structured reproducers --------------------------------

/// SIGBUS in `memset`, called from `_dl_map_segments` (dl-map-segments.h:177).
/// Reduced from `crashes/crash_00_sig7.elf`.
pub const LOAD_MEMSZ_PAST_EOF: Case = Case {
    id: "glibc_load_memsz_past_eof",
    summary: "PT_LOAD filesz/memsz reach pages beyond EOF; ld.so SIGBUS zero-filling .bss.",
    details: "A single PT_LOAD declares p_filesz=0x1800 and p_memsz=0x2000 in a file that \
is only 0xc0 bytes long. _dl_map_segments mmaps the segment from the (short) file, then \
zero-fills the gap between p_filesz and the end of the segment's last page with \
`memset((void *) zero, 0, zeropage - zero)` (dl-map-segments.h:177) to create the .bss. \
Because p_filesz points past the real end of the file, that page has no file backing and \
the store raises SIGBUS. The original fuzzer artifact (crashes/crash_00_sig7.elf) used a \
176-byte file with p_memsz≈0x6_0000_0002, giving the loader a 24 GiB maplength; the \
reproducer keeps the essential condition (filesz/memsz past EOF, memsz>filesz) minimal.",
    tags: &[Tag::Bounds, Tag::Consistency],
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

/// Fault in the post-mapping program-header rescan in `_dl_map_object_from_fd`
/// (dl-load.c:1342). Reduced from `crashes/crash_01_sig11.elf`.
pub const LOAD_WILD_VADDR_PHDR: Case = Case {
    id: "glibc_load_wild_vaddr_phdr",
    summary: "Wild PT_LOAD vaddr/align puts l_phdr outside any segment; ld.so faults in phdr rescan.",
    details: "After mapping the segments, _dl_map_object_from_fd walks the program headers \
backward looking for PT_GNU_PROPERTY: `for (ph = &l->l_phdr[l->l_phnum]; ph != l->l_phdr; \
--ph) if (ph[-1].p_type == PT_GNU_PROPERTY)` (dl-load.c:1342). l->l_phdr is derived from \
the load layout / PT_PHDR. The first PT_LOAD here has a wild p_vaddr (0xb000_0000), \
p_filesz=0xb000_0000 and an absurd p_align (0x0600_0000_0200_0000), so the address glibc \
computes for l_phdr does not fall inside any mapped segment and dereferencing ph[-1] faults \
(SIGSEGV, or SIGBUS when the bad address lands on a file-backed page past EOF). The second \
PT_LOAD provides the offset/vaddr mismatch that drives l_phdr off the mapping. Reduced from \
crashes/crash_01_sig11.elf (the corpus also held several byte-variants: crash_02/03/05).",
    tags: &[Tag::Bounds, Tag::Alignment],
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

// ---- not cleanly reducible -> raw artifact kept for reference ------------

/// SIGSEGV in `l_soname` (ldsodefs.h:99), via a malformed PT_DYNAMIC. Kept raw:
/// the fault depends on the dynamic walk running into garbage memory.
pub const DYN_LSONAME_OOB: Case = Case {
    id: "glibc_dyn_lsoname_oob",
    summary: "Malformed PT_DYNAMIC; SIGSEGV in l_soname reading l_info[] (dl-load.c:1429).",
    details: "The object pairs a PT_LOAD (vaddr 0xb000_0000) with a PT_DYNAMIC at p_offset=0xe, \
vaddr 0xb000_0000 (overlapping the load) and p_filesz=0xffff_b000_0080_0000. \
_dl_map_object_from_fd reaches the 'did we just load libc.so?' check at dl-load.c:1429: \
`l_soname(l) != NULL && strcmp(l_soname(l), LIBC_SO)`. l_soname returns \
`D_PTR(l, l_info[DT_STRTAB]) + l_info[DT_SONAME]->d_un.d_val` (ldsodefs.h:99). \
elf_get_dynamic_info populated l_info[] by walking the dynamic array until DT_NULL, but the \
overlapping/oversized PT_DYNAMIC makes that walk run past the mapped bytes into adjacent \
memory; an entry there looks like DT_SONAME/DT_STRTAB with a value pointing out of the \
mapping, so l_soname dereferences a wild l_info[] pointer and faults. This is a \
'dynamic table walks into garbage' corruption with no tidy structural form, so the raw \
fuzzer artifact (crashes/crash_07_sig11.elf) is kept verbatim.",
    tags: &[Tag::Bounds, Tag::Conjugate],
    spec: || ImageSpec::raw(include_bytes!("../../crashes/crash_07_sig11.elf").to_vec()),
};

/// SIGSEGV in `strcmp` reached from `dl_main` start-up (rtld.c:1687). Kept raw:
/// the data flow is inlined away under -O2 and not fully pinned.
pub const RTLD_STARTUP_STRCMP: Case = Case {
    id: "glibc_rtld_startup_strcmp",
    summary: "Malformed PT_INTERP; SIGSEGV in strcmp reached from dl_main start-up (rtld.c:1687).",
    details: "A 203-byte object with a PT_LOAD plus a PT_INTERP whose fields are wildly out of \
range (p_filesz=0x3e00_0200_0000_0000, p_offset=0xb0_0000_0000_0000) and no valid \
PT_DYNAMIC. The instrumented build faults in strcmp (strcmp-sse2.S:160) with the caller \
attributed to dl_main at rtld.c:1687 — the start-up step that reconciles the loader's own \
libname with its soname. strcmp dereferences a string pointer that ends up out of range, \
but at -O2 the rtld start-up code is heavily inlined, so the exact field->pointer chain is \
not fully pinned down; this is recorded honestly as an observed SIGSEGV string-deref \
reached from that code rather than a clean reproducer. Raw artifact: \
crashes/crash_04_sig11.elf (crash_06 is a second byte-variant of the same site).",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes/crash_04_sig11.elf").to_vec()),
};

/// SIGSEGV, layout-sensitive variant of [`LOAD_WILD_VADDR_PHDR`]: faults under
/// normal ASLR but not under gdb (which disables ASLR). Kept raw because the
/// fault depends on the randomized mmap base, which a deterministic builder
/// cannot pin.
pub const WILD_VADDR_ASLR: Case = Case {
    id: "glibc_wild_vaddr_aslr",
    summary: "Layout-sensitive wild-l_phdr crash (faults under ASLR, not under gdb).",
    details: "Two PT_LOADs with wild p_vaddr/p_offset, same family as \
glibc_load_wild_vaddr_phdr: the loader computes l_phdr outside the real mapping. Here \
whether the computed address hits an unmapped page depends on the randomized mmap base, so \
it SIGSEGVs under normal ASLR but runs clean under gdb (ASLR disabled). Kept as the raw \
artifact (crashes/crash_03_sig11.elf) because the trigger is layout-dependent and not \
reproducible deterministically.",
    tags: &[Tag::Bounds, Tag::Alignment],
    spec: || ImageSpec::raw(include_bytes!("../../crashes/crash_03_sig11.elf").to_vec()),
};
