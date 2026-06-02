mod dynamic;
mod glibc_crashes;
mod headers;
mod musl_crashes;
mod interp_sections;
mod notes;
mod program_headers;
mod section_headers;
mod versions;

use crate::case::Case;
use crate::elf::{Phdr, PF_R, PF_X, PT_LOAD};

pub const ALL: &[Case] = &[
    headers::BAD_MAGIC_ZERO,
    headers::BAD_CLASS_ELF32,
    headers::BAD_DATA_BIG_ENDIAN,
    headers::BAD_IDENT_VERSION,
    headers::BAD_FILE_VERSION,
    headers::BAD_EHSIZE_SHORT,
    headers::BAD_PHENTSIZE_SHORT,
    headers::BAD_PHENTSIZE_LARGE,
    headers::BAD_SHENTSIZE_SHORT,
    headers::BAD_SHENTSIZE_LARGE,
    headers::BAD_FILE_TYPE,
    program_headers::PHNUM_ZERO,
    program_headers::PHNUM_HUGE_OOB,
    program_headers::PHOFF_OOB,
    program_headers::PHDR_TABLE_TRUNCATED,
    program_headers::PHDR_OVERLAPS_EHDR,
    program_headers::PHDR_MISALIGNED,
    program_headers::PT_PHDR_MISALIGNED,
    program_headers::FILESZ_GT_MEMSZ,
    program_headers::LOAD_OFFSET_OOB,
    program_headers::LOAD_VADDR_WRAPAROUND,
    program_headers::LOAD_ALIGN_NON_POWER_TWO,
    program_headers::INTERP_FILESZ_ZERO,
    program_headers::INTERP_EMPTY_STRING,
    program_headers::INTERP_OFFSET_OOB,
    program_headers::INTERP_NO_NUL,
    section_headers::SHOFF_OOB,
    section_headers::SHNUM_HUGE_OOB,
    section_headers::SHDR_TABLE_TRUNCATED,
    section_headers::SHDR_OVERLAPS_EHDR,
    section_headers::SHSTRNDX_OOB,
    section_headers::SHSTRNDX_NOT_STRTAB,
    section_headers::SH_INFO_OOB_INFO_LINK,
    section_headers::SYMTAB_SHLINK_OOB,
    section_headers::SYMTAB_SHLINK_NOT_STRTAB,
    section_headers::SYMTAB_ENTSIZE_ZERO,
    section_headers::SYMTAB_ENTSIZE_TOO_LARGE,
    section_headers::SYMTAB_SIZE_NOT_MULTIPLE,
    section_headers::SYMTAB_SHINFO_TOO_LARGE,
    section_headers::RELA_SHLINK_NOT_SYMTAB,
    interp_sections::INTERP_SECTION_MISSING,
    interp_sections::INTERP_SHNAME_OOB,
    interp_sections::INTERP_SHOFFSET_OOB,
    interp_sections::INTERP_SHSIZE_ZERO,
    interp_sections::INTERP_SECTION_NO_NUL,
    dynamic::DYNAMIC_STRTAB_WITHOUT_STRSZ,
    dynamic::DYNAMIC_SYMTAB_WITHOUT_SYMENT,
    dynamic::DYNAMIC_SYMTAB_WITHOUT_HASH,
    dynamic::DYNAMIC_SYMENT_ZERO,
    dynamic::DYNAMIC_STRTAB_OOB,
    dynamic::DYNAMIC_STRTAB_SIZE_OOB,
    dynamic::DYNAMIC_HASH_OOB,
    dynamic::DYNAMIC_HASH_SELF_LOOP,
    dynamic::DYNAMIC_GNU_HASH_OOB,
    dynamic::DYNAMIC_GNU_HASH_ZERO_BUCKETS,
    dynamic::DYNAMIC_GNU_HASH_ZERO_BLOOM_WORDS,
    dynamic::DYNAMIC_GNU_HASH_BAD_CHAIN_PTR,
    dynamic::DYNAMIC_VERNEED_WITHOUT_COUNT,
    dynamic::DYNAMIC_VERSYM_OOB,
    dynamic::DYNAMIC_RELR_WITHOUT_SIZE,
    dynamic::DYNAMIC_RELRENT_WRONG,
    dynamic::DYNAMIC_RELR_OOB,
    dynamic::DYNAMIC_RELENT_ZERO,
    dynamic::DYNAMIC_NULL_MISSING,
    notes::NOTE_TRUNCATED_HEADER,
    notes::NOTE_HEADER_SHORT_FIELDS,
    notes::NOTE_NAME_OOB,
    notes::NOTE_DESC_OOB,
    versions::VERDEF_TRUNCATED_HEADER,
    versions::VERDEF_BAD_AUX_OFFSET,
    versions::VERNEED_TRUNCATED_HEADER,
    versions::VERNEED_BAD_AUX_OFFSET,
    versions::VERSYM_SIZE_ODD,
    // glibc ld.so --verify crashes (structured reproducers + raw-for-reference)
    glibc_crashes::LOAD_MEMSZ_PAST_EOF,
    glibc_crashes::LOAD_WILD_VADDR_PHDR,
    glibc_crashes::DYN_LSONAME_OOB,
    glibc_crashes::RTLD_STARTUP_STRCMP,
    glibc_crashes::WILD_VADDR_ASLR,
    // musl ld.so --list crashes (one per distinct fault site)
    musl_crashes::MUSL_SYSV_LOOKUP_261,
    musl_crashes::MUSL_RELOC_ALL_430,
    musl_crashes::MUSL_LOAD_DIRECT_DEPS_1067,
    musl_crashes::MUSL_DO_RELR_RELOCS_570,
    musl_crashes::MUSL___DLS3_1414,
    musl_crashes::MUSL_MEMSET_847,
    musl_crashes::MUSL_DO_RELOCS_473,
    musl_crashes::MUSL_DO_RELOCS_486,
    musl_crashes::MUSL_DO_RELOCS_345,
    musl_crashes::MUSL___DLS3_852,
    musl_crashes::MUSL_MEMCPY_66,
];

pub(crate) fn load_phdr() -> Phdr {
    Phdr::new(PT_LOAD)
        .flags(PF_R | PF_X)
        .offset(0)
        .vaddr(0x400000)
        .paddr(0x400000)
        .filesz(0x8c)
        .memsz(0x8c)
        .align(0x1000)
}
