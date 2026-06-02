use crate::case::{Case, Tag};
use crate::elf::{Ehdr, ImageSpec, Shdr, SHF_INFO_LINK, SHT_RELA, SHT_STRTAB, SHT_SYMTAB};

use super::load_phdr;

pub const SHOFF_OOB: Case = Case {
    id: "shoff_oob",
    summary: "Section-header table offset points beyond the file.",
    tags: &[Tag::Bounds],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().shoff(0x10000).shnum(1)),
};

pub const SHNUM_HUGE_OOB: Case = Case {
    id: "shnum_huge_oob",
    summary: "Section-header count is huge while the file contains only one entry.",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || {
        ImageSpec::new(0xb0 + 0x40, Ehdr::exec64().shoff(0xb0).shnum(0xffff)).shdr(Shdr::null())
    },
};

pub const SHDR_TABLE_TRUNCATED: Case = Case {
    id: "shdr_table_truncated",
    summary: "Section-header count asks for two entries but only one is present.",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || ImageSpec::new(0xb0 + 0x40, Ehdr::exec64().shoff(0xb0).shnum(2)).shdr(Shdr::null()),
};

pub const SHDR_OVERLAPS_EHDR: Case = Case {
    id: "shdr_overlaps_ehdr",
    summary: "Section-header table range starts inside the ELF header.",
    tags: &[Tag::NonOverlap, Tag::Containment],
    spec: || ImageSpec::new(0x20 + 0x40, Ehdr::exec64().shoff(0x20).shnum(1)),
};

pub const SHSTRNDX_OOB: Case = Case {
    id: "shstrndx_oob",
    summary: "Section-name string-table index points outside the section table.",
    tags: &[Tag::Bounds],
    spec: || {
        ImageSpec::new(0xb0 + 0x40, Ehdr::exec64().shoff(0xb0).shnum(1).shstrndx(7))
            .shdr(Shdr::null())
    },
};

pub const SHSTRNDX_NOT_STRTAB: Case = Case {
    id: "shstrndx_not_strtab",
    summary: "Section-name string-table index points at a non-string-table section.",
    tags: &[Tag::Conjugate, Tag::Encoding],
    spec: || {
        ImageSpec::new(0xb0 + 0x80, Ehdr::exec64().shoff(0xb0).shnum(2).shstrndx(1))
            .shdr(Shdr::null())
            .shdr(Shdr::new(SHT_SYMTAB).offset(0x78).size(0x18).entsize(0x18))
    },
};

pub const SH_INFO_OOB_INFO_LINK: Case = Case {
    id: "sh_info_oob_info_link",
    summary: "Section with SHF_INFO_LINK has an out-of-range sh_info reference.",
    tags: &[Tag::Bounds],
    spec: || {
        ImageSpec::new(0xb0 + 0x80, Ehdr::exec64().shoff(0xb0).shnum(2))
            .shdr(Shdr::null())
            .shdr(Shdr::new(SHT_STRTAB).flags(SHF_INFO_LINK).info(3))
    },
};

pub const SYMTAB_SHLINK_OOB: Case = Case {
    id: "symtab_shlink_oob",
    summary: "Symbol table sh_link points outside the section table.",
    tags: &[Tag::Bounds],
    spec: || {
        ImageSpec::new(
            0x130,
            Ehdr::exec64().shoff(0xb0).phnum(1).shnum(2).shstrndx(0),
        )
        .phdr(load_phdr())
        .shdr(Shdr::null())
        .shdr(
            Shdr::new(SHT_SYMTAB)
                .name(0x13)
                .offset(0x78)
                .size(0x18)
                .link(0x01000000)
                .info(1)
                .addralign(8)
                .entsize(0x18),
        )
    },
};

pub const SYMTAB_SHLINK_NOT_STRTAB: Case = Case {
    id: "symtab_shlink_not_strtab",
    summary: "Symbol table sh_link points at another symbol table instead of a string table.",
    tags: &[Tag::Conjugate, Tag::Encoding],
    spec: || {
        ImageSpec::new(0xb0 + 0xc0, Ehdr::exec64().shoff(0xb0).shnum(3))
            .shdr(Shdr::null())
            .shdr(
                Shdr::new(SHT_SYMTAB)
                    .offset(0x78)
                    .size(0x18)
                    .link(2)
                    .entsize(0x18),
            )
            .shdr(Shdr::new(SHT_SYMTAB).offset(0x90).size(0x18).entsize(0x18))
    },
};

pub const SYMTAB_ENTSIZE_ZERO: Case = Case {
    id: "symtab_entsize_zero",
    summary: "Symbol table has non-zero size but zero entry size.",
    tags: &[Tag::Conjugate, Tag::Cardinality],
    spec: || {
        ImageSpec::new(0xb0 + 0xc0, Ehdr::exec64().shoff(0xb0).shnum(3))
            .shdr(Shdr::null())
            .shdr(
                Shdr::new(SHT_SYMTAB)
                    .offset(0x78)
                    .size(0x18)
                    .link(2)
                    .entsize(0),
            )
            .shdr(Shdr::new(SHT_STRTAB).offset(0x90).size(1))
    },
};

pub const SYMTAB_ENTSIZE_TOO_LARGE: Case = Case {
    id: "symtab_entsize_too_large",
    summary: "Symbol table entry size is larger than the table size.",
    tags: &[Tag::Conjugate, Tag::Cardinality],
    spec: || {
        ImageSpec::new(0xb0 + 0xc0, Ehdr::exec64().shoff(0xb0).shnum(3))
            .shdr(Shdr::null())
            .shdr(
                Shdr::new(SHT_SYMTAB)
                    .offset(0x78)
                    .size(0x18)
                    .link(2)
                    .entsize(0x20),
            )
            .shdr(Shdr::new(SHT_STRTAB).offset(0x90).size(1))
    },
};

pub const SYMTAB_SIZE_NOT_MULTIPLE: Case = Case {
    id: "symtab_size_not_multiple",
    summary: "Symbol table size is not a multiple of its entry size.",
    tags: &[Tag::Conjugate, Tag::Cardinality],
    spec: || {
        ImageSpec::new(0xb0 + 0xc0, Ehdr::exec64().shoff(0xb0).shnum(3))
            .shdr(Shdr::null())
            .shdr(
                Shdr::new(SHT_SYMTAB)
                    .offset(0x78)
                    .size(0x19)
                    .link(2)
                    .entsize(0x18),
            )
            .shdr(Shdr::new(SHT_STRTAB).offset(0x98).size(1))
    },
};

pub const SYMTAB_SHINFO_TOO_LARGE: Case = Case {
    id: "symtab_shinfo_too_large",
    summary: "Symbol table sh_info declares more local symbols than entries.",
    tags: &[Tag::Bounds, Tag::Conjugate],
    spec: || {
        ImageSpec::new(0xb0 + 0xc0, Ehdr::exec64().shoff(0xb0).shnum(3))
            .shdr(Shdr::null())
            .shdr(
                Shdr::new(SHT_SYMTAB)
                    .offset(0x78)
                    .size(0x18)
                    .link(2)
                    .info(2)
                    .entsize(0x18),
            )
            .shdr(Shdr::new(SHT_STRTAB).offset(0x90).size(1))
    },
};

pub const RELA_SHLINK_NOT_SYMTAB: Case = Case {
    id: "rela_shlink_not_symtab",
    summary: "Rela relocation section sh_link points to a string table instead of a symbol table.",
    tags: &[Tag::Conjugate, Tag::Encoding],
    spec: || {
        ImageSpec::new(0xb0 + 0xc0, Ehdr::exec64().shoff(0xb0).shnum(3))
            .shdr(Shdr::null())
            .shdr(
                Shdr::new(SHT_RELA)
                    .offset(0x78)
                    .size(0x18)
                    .link(2)
                    .entsize(0x18),
            )
            .shdr(Shdr::new(SHT_STRTAB).offset(0x90).size(1))
            .bytes(0x78, vec![0; 0x18])
    },
};
