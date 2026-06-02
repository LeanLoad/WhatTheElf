use crate::case::{Case, Tag};
use crate::cases::load_phdr;
use crate::elf::{Ehdr, ImageSpec, Shdr};

pub const BAD_MAGIC_ZERO: Case = Case {
    id: "bad_magic_zero",
    summary: "ELF magic bytes are all zero.",
    details: "",
    tags: &[Tag::Encoding],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().magic([0, 0, 0, 0])),
};

pub const BAD_CLASS_ELF32: Case = Case {
    id: "bad_class_elf32",
    summary: "ELF ident class says ELF32 while the rest of the file is ELF64-shaped.",
    details: "",
    tags: &[Tag::Encoding, Tag::Consistency],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().class(1)),
};

pub const BAD_DATA_BIG_ENDIAN: Case = Case {
    id: "bad_data_big_endian",
    summary: "ELF ident data says big-endian while fields are written little-endian.",
    details: "",
    tags: &[Tag::Encoding, Tag::Consistency],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().data(2)),
};

pub const BAD_IDENT_VERSION: Case = Case {
    id: "bad_ident_version",
    summary: "ELF ident version is not EV_CURRENT.",
    details: "",
    tags: &[Tag::Encoding],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().ident_version(2)),
};

pub const BAD_FILE_VERSION: Case = Case {
    id: "bad_file_version",
    summary: "ELF file header version is not EV_CURRENT.",
    details: "",
    tags: &[Tag::Encoding],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().version(2)),
};

pub const BAD_EHSIZE_SHORT: Case = Case {
    id: "bad_ehsize_short",
    summary: "ELF header declares a size smaller than the actual ELF64 header.",
    details: "",
    tags: &[Tag::Consistency, Tag::Cardinality],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().ehsize(63)),
};

pub const BAD_PHENTSIZE_LARGE: Case = Case {
    id: "bad_phentsize_large",
    summary: "Program-header entry size disagrees with the ELF64 program-header size.",
    details: "",
    tags: &[Tag::Consistency, Tag::Cardinality],
    spec: || ImageSpec::new(0x40 + 0x39, Ehdr::exec64().phnum(1).phentsize(0x39)).phdr(load_phdr()),
};

pub const BAD_PHENTSIZE_SHORT: Case = Case {
    id: "bad_phentsize_short",
    summary: "Program-header entry size is smaller than the ELF64 program-header size.",
    details: "",
    tags: &[Tag::Consistency, Tag::Cardinality],
    spec: || ImageSpec::new(0x40 + 0x38, Ehdr::exec64().phnum(1).phentsize(0x37)).phdr(load_phdr()),
};

pub const BAD_SHENTSIZE_LARGE: Case = Case {
    id: "bad_shentsize_large",
    summary: "Section-header entry size disagrees with the ELF64 section-header size.",
    details: "",
    tags: &[Tag::Consistency, Tag::Cardinality],
    spec: || {
        ImageSpec::new(
            0x80 + 0x41,
            Ehdr::exec64().shoff(0x80).shnum(1).shentsize(0x41),
        )
        .shdr(Shdr::null())
    },
};

pub const BAD_SHENTSIZE_SHORT: Case = Case {
    id: "bad_shentsize_short",
    summary: "Section-header entry size is smaller than the ELF64 section-header size.",
    details: "",
    tags: &[Tag::Consistency, Tag::Cardinality],
    spec: || {
        ImageSpec::new(
            0x80 + 0x40,
            Ehdr::exec64().shoff(0x80).shnum(1).shentsize(0x3f),
        )
        .shdr(Shdr::null())
    },
};

pub const BAD_FILE_TYPE: Case = Case {
    id: "bad_file_type",
    summary: "ELF file type is outside the normal object-file type range.",
    details: "",
    tags: &[Tag::Encoding],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().ty(0xffff)),
};
