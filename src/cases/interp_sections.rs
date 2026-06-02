use crate::case::{Case, Tag};
use crate::elf::{Ehdr, ImageSpec, Shdr, SHT_PROGBITS, SHT_STRTAB};

const SHOFF: u64 = 0xb0;
const SHSTRTAB_OFF: usize = 0x170;
const INTERP_OFF: usize = 0x190;
const SHSTRTAB: &[u8] = b"\0.shstrtab\0.interp\0";
const SHSTRTAB_NAME: u32 = 1;
const INTERP_NAME: u32 = 11;

pub const INTERP_SECTION_MISSING: Case = Case {
    id: "interp_section_missing",
    summary: "Section table has names but no .interp section.",
    tags: &[Tag::Existence],
    spec: || {
        ImageSpec::new(
            SHSTRTAB_OFF + SHSTRTAB.len(),
            Ehdr::exec64().shoff(SHOFF).shnum(2).shstrndx(1),
        )
        .shdr(Shdr::null())
        .shdr(shstrtab())
        .bytes(SHSTRTAB_OFF, SHSTRTAB.to_vec())
    },
};

pub const INTERP_SHNAME_OOB: Case = Case {
    id: "interp_shname_oob",
    summary: ".interp-like section has a name offset outside .shstrtab.",
    tags: &[Tag::Bounds],
    spec: || {
        section(
            Shdr::new(SHT_PROGBITS)
                .name(0xffff)
                .offset(INTERP_OFF as u64)
                .size(4),
            b"ld\0\0",
        )
    },
};

pub const INTERP_SHOFFSET_OOB: Case = Case {
    id: "interp_shoffset_oob",
    summary: ".interp section file range points beyond the file.",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        section(
            Shdr::new(SHT_PROGBITS)
                .name(INTERP_NAME)
                .offset(0x1000)
                .size(8),
            b"",
        )
    },
};

pub const INTERP_SHSIZE_ZERO: Case = Case {
    id: "interp_shsize_zero",
    summary: ".interp section exists but has zero size.",
    tags: &[Tag::Existence, Tag::Cardinality],
    spec: || {
        section(
            Shdr::new(SHT_PROGBITS)
                .name(INTERP_NAME)
                .offset(INTERP_OFF as u64)
                .size(0),
            b"",
        )
    },
};

pub const INTERP_SECTION_NO_NUL: Case = Case {
    id: "interp_section_no_nul",
    summary: ".interp section content is not NUL-terminated.",
    tags: &[Tag::Encoding, Tag::Consistency],
    spec: || {
        section(
            Shdr::new(SHT_PROGBITS)
                .name(INTERP_NAME)
                .offset(INTERP_OFF as u64)
                .size(4),
            b"ld-x",
        )
    },
};

fn section(interp: Shdr, interp_bytes: &[u8]) -> ImageSpec {
    ImageSpec::new(
        INTERP_OFF + interp_bytes.len(),
        Ehdr::exec64().shoff(SHOFF).shnum(3).shstrndx(1),
    )
    .shdr(Shdr::null())
    .shdr(shstrtab())
    .shdr(interp)
    .bytes(SHSTRTAB_OFF, SHSTRTAB.to_vec())
    .bytes(INTERP_OFF, interp_bytes.to_vec())
}

fn shstrtab() -> Shdr {
    Shdr::new(SHT_STRTAB)
        .name(SHSTRTAB_NAME)
        .offset(SHSTRTAB_OFF as u64)
        .size(SHSTRTAB.len() as u64)
}
