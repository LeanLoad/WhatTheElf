//! Crashes in the musl dynamic loader (`ld-musl-x86_64.so.1 --list`).
//!
//! One per distinct fault site (file:line) from an 8-hour AFL++ run, each
//! confirmed on the stock system musl loader. musl's whole loader is one file
//! (ldso/dynlink.c); fuzzing `--list` reached deep into relocation, symbol
//! resolution, dependency loading and TLS setup, so these span the pipeline.
//! Kept raw - the malformations are dynamic-table corruptions, not structural.
use crate::crash::{Crash, Target::Musl, Repro::RawArtifact, Signal::*};
use crate::elf::ImageSpec;

/// SIGSEGV in `sysv_lookup`.
pub const MUSL_SYSV_LOOKUP_261: Crash = Crash {
    id: "musl_sysv_lookup_261",
    target: Musl,
    signal: Segv,
    site: "sysv_lookup (dynlink.c:261)",
    repro: RawArtifact,
    details: "Symbol lookup over a malformed SysV hash table: sysv_lookup walks for (i=hashtab[2+h%hashtab[0]]; i; i=hashtab[2+hashtab[0]+i]) and compares strings+syms[i].st_name (dynlink.c:261). Bad DT_HASH/DT_SYMTAB/DT_STRTAB drive the chain indices out of bounds.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_00_dynlink_c_261.elf").to_vec()),
};

/// SIGSEGV in `reloc_all`.
pub const MUSL_RELOC_ALL_430: Crash = Crash {
    id: "musl_reloc_all_430",
    target: Musl,
    signal: Segv,
    site: "reloc_all (dynlink.c:430)",
    repro: RawArtifact,
    details: "While relocating the object, do_relocs dereferences the symbol/string tables built from a malformed dynamic section: sym = syms + sym_index; name = strings + sym->st_name (dynlink.c:430). Bad DT_SYMTAB/DT_STRTAB make these pointers land outside the mapping; both SIGSEGV and SIGBUS (file-backed page past EOF) were observed here.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_01_reloc_all.elf").to_vec()),
};

/// SIGSEGV in `load_direct_deps`.
pub const MUSL_LOAD_DIRECT_DEPS_1067: Crash = Crash {
    id: "musl_load_direct_deps_1067",
    target: Musl,
    signal: Segv,
    site: "load_direct_deps (dynlink.c:1067)",
    repro: RawArtifact,
    details: "Resolving DT_NEEDED dependencies: each dependency name is strtab + d_val, then load_library(name,...) dereferences it at 'if (!*name)' (dynlink.c:1067). A wild DT_STRTAB makes the name pointer point outside the image, so the first byte read faults.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_02_load_direct_deps.elf").to_vec()),
};

/// SIGSEGV in `do_relr_relocs`.
pub const MUSL_DO_RELR_RELOCS_570: Crash = Crash {
    id: "musl_do_relr_relocs_570",
    target: Musl,
    signal: Segv,
    site: "do_relr_relocs (dynlink.c:570)",
    repro: RawArtifact,
    details: "Processing DT_RELR relative relocations: reloc_addr = laddr(dso, relr[0]); *reloc_addr++ += base (dynlink.c:570). A crafted RELR table decodes to addresses outside the mapping, so the relocation write hits unmapped memory (SIGSEGV) or a file-backed page past EOF (SIGBUS) - both signals were observed at this site.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_03_do_relr_relocs.elf").to_vec()),
};

/// SIGSEGV in `__dls3`.
pub const MUSL___DLS3_1414: Crash = Crash {
    id: "musl___dls3_1414",
    target: Musl,
    signal: Segv,
    site: "__dls3 (dynlink.c:1414)",
    repro: RawArtifact,
    details: "__dls3 drives loading + relocation of the crafted object; the fault occurs in the relocation pass it invokes (reloc_all/do_relocs at dynlink.c:1414) over malformed dynamic tables.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_04___dls3.elf").to_vec()),
};

/// SIGBUS in `memset`.
pub const MUSL_MEMSET_847: Crash = Crash {
    id: "musl_memset_847",
    target: Musl,
    signal: Bus,
    site: "memset (dynlink.c:847)",
    repro: RawArtifact,
    details: "map_library zeroes the .bss tail of a PT_LOAD: brk=base+p_vaddr+p_filesz; memset((void*)brk, 0, pgbrk-brk & PAGE_SIZE-1) (dynlink.c:847). When p_filesz runs past the real end of the file the page being zeroed has no file backing, so the store raises SIGBUS. musl analogue of the glibc _dl_map_segments zero-fill crash.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_05_memset.elf").to_vec()),
};

/// SIGSEGV in `do_relocs`.
pub const MUSL_DO_RELOCS_473: Crash = Crash {
    id: "musl_do_relocs_473",
    target: Musl,
    signal: Segv,
    site: "do_relocs (dynlink.c:473)",
    repro: RawArtifact,
    details: "Applying a REL_GOT/REL_PLT relocation: *reloc_addr = sym_val + addend (dynlink.c:473). reloc_addr is laddr(dso, r_offset) from a crafted relocation whose offset lands outside the mapping, so the write faults.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_07_do_relocs.elf").to_vec()),
};

/// SIGSEGV in `do_relocs`.
pub const MUSL_DO_RELOCS_486: Crash = Crash {
    id: "musl_do_relocs_486",
    target: Musl,
    signal: Segv,
    site: "do_relocs (dynlink.c:486)",
    repro: RawArtifact,
    details: "Applying a REL_COPY relocation: memcpy(reloc_addr, (void*)sym_val, sym->st_size) (dynlink.c:486). Crafted symbol/relocation values give a wild destination, source, or size, so the copy faults.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_08_do_relocs.elf").to_vec()),
};

/// SIGSEGV in `do_relocs`.
pub const MUSL_DO_RELOCS_345: Crash = Crash {
    id: "musl_do_relocs_345",
    target: Musl,
    signal: Segv,
    site: "do_relocs (dynlink.c:345)",
    repro: RawArtifact,
    details: "do_relocs resolves a relocation's symbol via the (malformed) DT_SYMTAB/DT_STRTAB and looks it up with find_sym (dynlink.c:345); bad tables drive the lookup out of bounds.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_09_do_relocs.elf").to_vec()),
};

/// SIGSEGV in `__dls3`.
pub const MUSL___DLS3_852: Crash = Crash {
    id: "musl___dls3_852",
    target: Musl,
    signal: Segv,
    site: "__dls3 (dynlink.c:852)",
    repro: RawArtifact,
    details: "After mapping segments, map_library scans the dynamic array for DT_TEXTREL: for (i=0; ((size_t*)(base+dyn))[i]; i+=2) (dynlink.c:852). A bogus PT_DYNAMIC vaddr makes base+dyn point outside the mapping, so the scan reads unmapped memory.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_10___dls3.elf").to_vec()),
};

/// SIGSEGV in `memcpy`.
pub const MUSL_MEMCPY_66: Crash = Crash {
    id: "musl_memcpy_66",
    target: Musl,
    signal: Segv,
    site: "__copy_tls memcpy (__init_tls.c:66)",
    repro: RawArtifact,
    details: "Setting up TLS, __copy_tls copies each module's TLS image: memcpy(mem - p->offset, p->image, p->len) (__init_tls.c:66). A crafted PT_TLS gives a wild offset/image/len, so the copy reads or writes outside the allocated TLS block.",
    spec: || ImageSpec::raw(include_bytes!("../../crashes/musl_12_memcpy.elf").to_vec()),
};

