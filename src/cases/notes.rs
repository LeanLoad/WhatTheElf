use crate::case::{Case, Tag};
use crate::elf::{Ehdr, ImageSpec, Phdr, PF_R, PT_NOTE};

const NOTE_OFFSET: usize = 0xb0;

pub const NOTE_TRUNCATED_HEADER: Case = Case {
    id: "note_truncated_header",
    summary: "PT_NOTE segment is shorter than one note header.",
    details: "",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || note(vec![0; 8]),
};

pub const NOTE_HEADER_SHORT_FIELDS: Case = Case {
    id: "note_header_short_fields",
    summary: "PT_NOTE segment stops in the middle of the note type field.",
    details: "",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 0, 0]);
        note(bytes)
    },
};

pub const NOTE_NAME_OOB: Case = Case {
    id: "note_name_oob",
    summary: "Note header namesz extends beyond the PT_NOTE segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || note(note_header(0x100, 0, 1)),
};

pub const NOTE_DESC_OOB: Case = Case {
    id: "note_desc_oob",
    summary: "Note header descsz extends beyond the PT_NOTE segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        let mut bytes = note_header(4, 0x100, 1);
        bytes.extend_from_slice(b"GNU\0");
        note(bytes)
    },
};

fn note(bytes: Vec<u8>) -> ImageSpec {
    ImageSpec::new(NOTE_OFFSET + bytes.len(), Ehdr::exec64().phnum(1))
        .phdr(
            Phdr::new(PT_NOTE)
                .flags(PF_R)
                .offset(NOTE_OFFSET as u64)
                .filesz(bytes.len() as u64)
                .memsz(bytes.len() as u64)
                .align(4),
        )
        .bytes(NOTE_OFFSET, bytes)
}

fn note_header(namesz: u32, descsz: u32, ty: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&namesz.to_le_bytes());
    bytes.extend_from_slice(&descsz.to_le_bytes());
    bytes.extend_from_slice(&ty.to_le_bytes());
    bytes
}
