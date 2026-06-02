use crate::case::{Case, Tag};
use crate::elf::{
    le16, le32, Ehdr, ImageSpec, Shdr, SHT_GNU_VERDEF, SHT_GNU_VERNEED, SHT_GNU_VERSYM, SHT_STRTAB,
};

const SHOFF: u64 = 0xb0;
const SHSTRTAB_OFF: usize = 0x1b0;
const STRTAB_OFF: usize = 0x1d0;
const DATA_OFF: usize = 0x1e0;
const SHSTRTAB: &[u8] = b"\0.shstrtab\0.dynstr\0.version\0";

pub const VERDEF_TRUNCATED_HEADER: Case = Case {
    id: "verdef_truncated_header",
    summary: "GNU version-definition section is shorter than one Verdef record.",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || version_section(SHT_GNU_VERDEF, vec![0; 8]),
};

pub const VERDEF_BAD_AUX_OFFSET: Case = Case {
    id: "verdef_bad_aux_offset",
    summary: "GNU version-definition entry points its auxiliary record outside the section.",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || version_section(SHT_GNU_VERDEF, verdef(1, 0, 1, 1, 0, 0x40, 0)),
};

pub const VERNEED_TRUNCATED_HEADER: Case = Case {
    id: "verneed_truncated_header",
    summary: "GNU version-need section is shorter than one Verneed record.",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || version_section(SHT_GNU_VERNEED, vec![0; 8]),
};

pub const VERNEED_BAD_AUX_OFFSET: Case = Case {
    id: "verneed_bad_aux_offset",
    summary: "GNU version-need entry points its auxiliary record outside the section.",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || version_section(SHT_GNU_VERNEED, verneed(1, 1, 0, 0x40, 0)),
};

pub const VERSYM_SIZE_ODD: Case = Case {
    id: "versym_size_odd",
    summary: "GNU version-symbol section size is not a multiple of a Versym entry.",
    tags: &[Tag::Cardinality, Tag::Conjugate],
    spec: || version_section(SHT_GNU_VERSYM, vec![0]),
};

fn version_section(ty: u32, bytes: Vec<u8>) -> ImageSpec {
    ImageSpec::new(
        DATA_OFF + bytes.len(),
        Ehdr::exec64().shoff(SHOFF).shnum(4).shstrndx(1),
    )
    .shdr(Shdr::null())
    .shdr(
        Shdr::new(SHT_STRTAB)
            .name(1)
            .offset(SHSTRTAB_OFF as u64)
            .size(SHSTRTAB.len() as u64),
    )
    .shdr(
        Shdr::new(SHT_STRTAB)
            .name(11)
            .offset(STRTAB_OFF as u64)
            .size(1),
    )
    .shdr(
        Shdr::new(ty)
            .name(19)
            .offset(DATA_OFF as u64)
            .size(bytes.len() as u64)
            .link(2)
            .info(1),
    )
    .bytes(SHSTRTAB_OFF, SHSTRTAB.to_vec())
    .bytes(STRTAB_OFF, vec![0])
    .bytes(DATA_OFF, bytes)
}

fn verdef(version: u16, flags: u16, ndx: u16, cnt: u16, hash: u32, aux: u32, next: u32) -> Vec<u8> {
    [
        le16(version),
        le16(flags),
        le16(ndx),
        le16(cnt),
        le32(hash),
        le32(aux),
        le32(next),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn verneed(version: u16, cnt: u16, file: u32, aux: u32, next: u32) -> Vec<u8> {
    [le16(version), le16(cnt), le32(file), le32(aux), le32(next)]
        .into_iter()
        .flatten()
        .collect()
}
