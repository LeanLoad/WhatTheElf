//! Crashes found by fuzzing the **musl** dynamic loader (`ld-musl-x86_64.so.1 --list`).
//!
//! One representative per distinct crash site (file:line) from an 8-hour AFL++
//! run, each confirmed to reproduce on the stock system musl loader. musl's whole
//! loader is one file (ldso/dynlink.c); unlike the glibc `--verify` run, fuzzing
//! `--list` reached deep into relocation, symbol resolution, dependency loading
//! and TLS setup, so these span the pipeline. Kept as raw artifacts - the
//! malformations are dynamic-table corruptions, not tidy structural ones; see each
//! `details` for the code path.
use crate::case::{Case, Tag};
use crate::elf::ImageSpec;

/// SIGSEGV in `sysv_lookup` (dynlink.c:261).
pub const MUSL_SYSV_LOOKUP_261: Case = Case {
    id: "musl_sysv_lookup_261",
    summary: "musl ld.so --list: SIGSEGV in sysv_lookup (dynlink.c:261).",
    details: "Symbol lookup over a malformed SysV hash table: sysv_lookup walks for (i=hashtab[2+h%hashtab[0]]; i; i=hashtab[2+hashtab[0]+i]) and compares strings+syms[i].st_name (dynlink.c:261). Bad DT_HASH/DT_SYMTAB/DT_STRTAB drive the chain indices out of bounds.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_00_dynlink_c_261.elf").to_vec()),
};

/// SIGSEGV in `reloc_all` (dynlink.c:430).
pub const MUSL_RELOC_ALL_430: Case = Case {
    id: "musl_reloc_all_430",
    summary: "musl ld.so --list: SIGSEGV in reloc_all (dynlink.c:430).",
    details: "While relocating the object, do_relocs dereferences the symbol/string tables built from a malformed dynamic section: sym = syms + sym_index; name = strings + sym->st_name (dynlink.c:430). Bad DT_SYMTAB/DT_STRTAB make these pointers land outside the mapping; both SIGSEGV and SIGBUS (file-backed page past EOF) were observed here.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_01_reloc_all.elf").to_vec()),
};

/// SIGSEGV in `load_direct_deps` (dynlink.c:1067).
pub const MUSL_LOAD_DIRECT_DEPS_1067: Case = Case {
    id: "musl_load_direct_deps_1067",
    summary: "musl ld.so --list: SIGSEGV in load_direct_deps (dynlink.c:1067).",
    details: "Resolving DT_NEEDED dependencies: each dependency name is strtab + d_val, then load_library(name,...) dereferences it at 'if (!*name)' (dynlink.c:1067). A wild DT_STRTAB makes the name pointer point outside the image, so the first byte read faults.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_02_load_direct_deps.elf").to_vec()),
};

/// SIGSEGV in `do_relr_relocs` (dynlink.c:570).
pub const MUSL_DO_RELR_RELOCS_570: Case = Case {
    id: "musl_do_relr_relocs_570",
    summary: "musl ld.so --list: SIGSEGV in do_relr_relocs (dynlink.c:570).",
    details: "Processing DT_RELR relative relocations: reloc_addr = laddr(dso, relr[0]); *reloc_addr++ += base (dynlink.c:570). A crafted RELR table decodes to addresses outside the mapping, so the relocation write hits unmapped memory (SIGSEGV) or a file-backed page past EOF (SIGBUS) - both signals were observed at this site.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_03_do_relr_relocs.elf").to_vec()),
};

/// SIGSEGV in `__dls3` (dynlink.c:1414).
pub const MUSL___DLS3_1414: Case = Case {
    id: "musl___dls3_1414",
    summary: "musl ld.so --list: SIGSEGV in __dls3 (dynlink.c:1414).",
    details: "__dls3 drives loading + relocation of the crafted object; the fault occurs in the relocation pass it invokes (reloc_all/do_relocs at dynlink.c:1414) over malformed dynamic tables.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_04___dls3.elf").to_vec()),
};

/// SIGBUS in `memset` (dynlink.c:847).
pub const MUSL_MEMSET_847: Case = Case {
    id: "musl_memset_847",
    summary: "musl ld.so --list: SIGBUS in memset (dynlink.c:847).",
    details: "map_library zeroes the .bss tail of a PT_LOAD: brk=base+p_vaddr+p_filesz; memset((void*)brk, 0, pgbrk-brk & PAGE_SIZE-1) (dynlink.c:847). When p_filesz runs past the real end of the file the page being zeroed has no file backing, so the store raises SIGBUS. musl analogue of the glibc _dl_map_segments zero-fill crash.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_05_memset.elf").to_vec()),
};

/// SIGSEGV in `do_relocs` (dynlink.c:473).
pub const MUSL_DO_RELOCS_473: Case = Case {
    id: "musl_do_relocs_473",
    summary: "musl ld.so --list: SIGSEGV in do_relocs (dynlink.c:473).",
    details: "Applying a REL_GOT/REL_PLT relocation: *reloc_addr = sym_val + addend (dynlink.c:473). reloc_addr is laddr(dso, r_offset) from a crafted relocation whose offset lands outside the mapping, so the write faults.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_07_do_relocs.elf").to_vec()),
};

/// SIGSEGV in `do_relocs` (dynlink.c:486).
pub const MUSL_DO_RELOCS_486: Case = Case {
    id: "musl_do_relocs_486",
    summary: "musl ld.so --list: SIGSEGV in do_relocs (dynlink.c:486).",
    details: "Applying a REL_COPY relocation: memcpy(reloc_addr, (void*)sym_val, sym->st_size) (dynlink.c:486). Crafted symbol/relocation values give a wild destination, source, or size, so the copy faults.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_08_do_relocs.elf").to_vec()),
};

/// SIGSEGV in `do_relocs` (dynlink.c:345).
pub const MUSL_DO_RELOCS_345: Case = Case {
    id: "musl_do_relocs_345",
    summary: "musl ld.so --list: SIGSEGV in do_relocs (dynlink.c:345).",
    details: "do_relocs resolves a relocation's symbol via the (malformed) DT_SYMTAB/DT_STRTAB and looks it up with find_sym (dynlink.c:345); bad tables drive the lookup out of bounds.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_09_do_relocs.elf").to_vec()),
};

/// SIGSEGV in `__dls3` (dynlink.c:852).
pub const MUSL___DLS3_852: Case = Case {
    id: "musl___dls3_852",
    summary: "musl ld.so --list: SIGSEGV in __dls3 (dynlink.c:852).",
    details: "After mapping segments, map_library scans the dynamic array for DT_TEXTREL: for (i=0; ((size_t*)(base+dyn))[i]; i+=2) (dynlink.c:852). A bogus PT_DYNAMIC vaddr makes base+dyn point outside the mapping, so the scan reads unmapped memory.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_10___dls3.elf").to_vec()),
};

/// SIGSEGV in `memcpy` (__init_tls.c:66).
pub const MUSL_MEMCPY_66: Case = Case {
    id: "musl_memcpy_66",
    summary: "musl ld.so --list: SIGSEGV in memcpy (__init_tls.c:66).",
    details: "Setting up TLS, __copy_tls copies each module's TLS image: memcpy(mem - p->offset, p->image, p->len) (__init_tls.c:66). A crafted PT_TLS gives a wild offset/image/len, so the copy reads or writes outside the allocated TLS block.",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || ImageSpec::raw(include_bytes!("../../crashes-musl/musl_12_memcpy.elf").to_vec()),
};

