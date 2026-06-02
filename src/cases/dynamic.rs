use crate::case::{Case, Tag};
use crate::elf::{
    dyn_bytes, le32, Dyn, Ehdr, ImageSpec, Phdr, DT_GNU_HASH, DT_HASH, DT_JMPREL, DT_NULL,
    DT_PLTREL, DT_REL, DT_RELENT, DT_RELR, DT_RELRENT, DT_RELRSZ, DT_RELSZ, DT_STRSZ, DT_STRTAB,
    DT_SYMENT, DT_SYMTAB, DT_VERNEED, DT_VERSYM, PF_R, PF_W, PT_DYNAMIC, PT_LOAD,
};

const SEG_OFFSET: usize = 0xb0;
const LOAD_VADDR: u64 = SEG_OFFSET as u64;
const DYN_VADDR: u64 = 0x8b0;
const LOAD_SIZE: u64 = 0x1000;

pub const DYNAMIC_STRTAB_WITHOUT_STRSZ: Case = Case {
    id: "dynamic_strtab_without_strsz",
    summary: "Dynamic table has DT_STRTAB but no DT_STRSZ.",
    details: "",
    tags: &[Tag::Coexistence],
    spec: || dynamic(&[Dyn::new(DT_STRTAB, 0x900), Dyn::new(DT_NULL, 0)], &[]),
};

pub const DYNAMIC_SYMTAB_WITHOUT_SYMENT: Case = Case {
    id: "dynamic_symtab_without_syment",
    summary: "Dynamic table has DT_SYMTAB but no DT_SYMENT.",
    details: "",
    tags: &[Tag::Coexistence],
    spec: || dynamic(&[Dyn::new(DT_SYMTAB, 0x900), Dyn::new(DT_NULL, 0)], &[]),
};

pub const DYNAMIC_SYMTAB_WITHOUT_HASH: Case = Case {
    id: "dynamic_symtab_without_hash",
    summary: "Dynamic table has DT_SYMTAB and DT_SYMENT but no SysV or GNU hash table.",
    details: "",
    tags: &[Tag::Coexistence],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_SYMTAB, 0x900),
                Dyn::new(DT_SYMENT, 24),
                Dyn::new(DT_NULL, 0),
            ],
            &[],
        )
    },
};

pub const DYNAMIC_SYMENT_ZERO: Case = Case {
    id: "dynamic_syment_zero",
    summary: "Dynamic table declares a symbol table with zero DT_SYMENT.",
    details: "",
    tags: &[Tag::Conjugate, Tag::Cardinality],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_SYMTAB, 0x900),
                Dyn::new(DT_SYMENT, 0),
                Dyn::new(DT_HASH, 0x980),
                Dyn::new(DT_NULL, 0),
            ],
            &[(0x900, vec![0; 0x30]), (0x980, word_table(&[1, 1, 0, 0]))],
        )
    },
};

pub const DYNAMIC_STRTAB_OOB: Case = Case {
    id: "dynamic_strtab_oob",
    summary: "DT_STRTAB virtual address is outside every loadable segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_STRTAB, 0x2000),
                Dyn::new(DT_STRSZ, 8),
                Dyn::new(DT_NULL, 0),
            ],
            &[],
        )
    },
};

pub const DYNAMIC_STRTAB_SIZE_OOB: Case = Case {
    id: "dynamic_strtab_size_oob",
    summary: "DT_STRTAB starts in a loadable segment but DT_STRSZ extends beyond it.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_STRTAB, 0x900),
                Dyn::new(DT_STRSZ, 0x2000),
                Dyn::new(DT_NULL, 0),
            ],
            &[],
        )
    },
};

pub const DYNAMIC_HASH_OOB: Case = Case {
    id: "dynamic_hash_oob",
    summary: "DT_HASH points outside every loadable segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || dynamic(&[Dyn::new(DT_HASH, 0x2000), Dyn::new(DT_NULL, 0)], &[]),
};

pub const DYNAMIC_HASH_SELF_LOOP: Case = Case {
    id: "dynamic_hash_self_loop",
    summary: "SysV hash table chain points back to itself.",
    details: "",
    tags: &[Tag::Consistency, Tag::Bounds],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_SYMTAB, 0x940),
                Dyn::new(DT_SYMENT, 24),
                Dyn::new(DT_STRTAB, 0x9a0),
                Dyn::new(DT_STRSZ, 8),
                Dyn::new(DT_HASH, 0x900),
                Dyn::new(DT_NULL, 0),
            ],
            &[
                (0x900, word_table(&[1, 2, 1, 0, 1])),
                (0x940, vec![0; 0x30]),
                (0x9a0, b"\0x\0".to_vec()),
            ],
        )
    },
};

pub const DYNAMIC_GNU_HASH_OOB: Case = Case {
    id: "dynamic_gnu_hash_oob",
    summary: "DT_GNU_HASH points outside every loadable segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || dynamic(&[Dyn::new(DT_GNU_HASH, 0x2000), Dyn::new(DT_NULL, 0)], &[]),
};

pub const DYNAMIC_GNU_HASH_ZERO_BUCKETS: Case = Case {
    id: "dynamic_gnu_hash_zero_buckets",
    summary: "GNU hash table header declares zero buckets.",
    details: "",
    tags: &[Tag::Cardinality, Tag::Consistency],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_GNU_HASH, 0x900),
                Dyn::new(DT_SYMTAB, 0x940),
                Dyn::new(DT_SYMENT, 24),
                Dyn::new(DT_NULL, 0),
            ],
            &[(0x900, word_table(&[0, 1, 0, 0])), (0x940, vec![0; 0x30])],
        )
    },
};

pub const DYNAMIC_GNU_HASH_ZERO_BLOOM_WORDS: Case = Case {
    id: "dynamic_gnu_hash_zero_bloom_words",
    summary: "GNU hash table header declares zero bloom filter words.",
    details: "",
    tags: &[Tag::Cardinality, Tag::Consistency],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_GNU_HASH, 0x900),
                Dyn::new(DT_SYMTAB, 0x940),
                Dyn::new(DT_SYMENT, 24),
                Dyn::new(DT_NULL, 0),
            ],
            &[(0x900, word_table(&[1, 0, 0, 1])), (0x940, vec![0; 0x30])],
        )
    },
};

pub const DYNAMIC_GNU_HASH_BAD_CHAIN_PTR: Case = Case {
    id: "dynamic_gnu_hash_bad_chain_ptr",
    summary: "GNU hash bucket points below symoffset, making the chain pointer underflow.",
    details: "",
    tags: &[Tag::Bounds, Tag::Consistency],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_GNU_HASH, 0x900),
                Dyn::new(DT_SYMTAB, 0x940),
                Dyn::new(DT_SYMENT, 24),
                Dyn::new(DT_STRTAB, 0x9a0),
                Dyn::new(DT_STRSZ, 8),
                Dyn::new(DT_NULL, 0),
            ],
            &[
                (0x900, gnu_hash_bad_chain_ptr()),
                (0x940, vec![0; 0x30]),
                (0x9a0, b"\0x\0".to_vec()),
            ],
        )
    },
};

pub const DYNAMIC_VERNEED_WITHOUT_COUNT: Case = Case {
    id: "dynamic_verneed_without_count",
    summary: "Dynamic table has DT_VERNEED but no DT_VERNEEDNUM.",
    details: "",
    tags: &[Tag::Coexistence],
    spec: || dynamic(&[Dyn::new(DT_VERNEED, 0x900), Dyn::new(DT_NULL, 0)], &[]),
};

pub const DYNAMIC_VERSYM_OOB: Case = Case {
    id: "dynamic_versym_oob",
    summary: "Dynamic version-symbol table points outside every loadable segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_GNU_HASH, 0x900),
                Dyn::new(DT_SYMTAB, 0x940),
                Dyn::new(DT_SYMENT, 24),
                Dyn::new(DT_STRTAB, 0x9a0),
                Dyn::new(DT_STRSZ, 8),
                Dyn::new(DT_VERSYM, 0x2000),
                Dyn::new(DT_NULL, 0),
            ],
            &[
                (0x900, gnu_hash_normal()),
                (0x940, vec![0; 0x30]),
                (0x9a0, b"\0x\0".to_vec()),
            ],
        )
    },
};

pub const DYNAMIC_RELR_WITHOUT_SIZE: Case = Case {
    id: "dynamic_relr_without_size",
    summary: "Dynamic table has DT_RELR but no DT_RELRSZ.",
    details: "",
    tags: &[Tag::Coexistence],
    spec: || dynamic(&[Dyn::new(DT_RELR, 0x900), Dyn::new(DT_NULL, 0)], &[]),
};

pub const DYNAMIC_RELRENT_WRONG: Case = Case {
    id: "dynamic_relrent_wrong",
    summary: "Dynamic table declares RELR entries with a non-word entry size.",
    details: "",
    tags: &[Tag::Conjugate, Tag::Encoding],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_RELR, 0x900),
                Dyn::new(DT_RELRSZ, 8),
                Dyn::new(DT_RELRENT, 4),
                Dyn::new(DT_NULL, 0),
            ],
            &[(0x900, vec![0; 8])],
        )
    },
};

pub const DYNAMIC_RELR_OOB: Case = Case {
    id: "dynamic_relr_oob",
    summary: "DT_RELR/DT_RELRSZ describes a RELR table outside every loadable segment.",
    details: "",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_RELR, 0x2000),
                Dyn::new(DT_RELRSZ, 8),
                Dyn::new(DT_RELRENT, 8),
                Dyn::new(DT_NULL, 0),
            ],
            &[],
        )
    },
};

pub const DYNAMIC_RELENT_ZERO: Case = Case {
    id: "dynamic_relent_zero",
    summary: "Dynamic table declares a REL relocation table with zero DT_RELENT.",
    details: "",
    tags: &[Tag::Conjugate, Tag::Cardinality],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_REL, 0x900),
                Dyn::new(DT_RELSZ, 8),
                Dyn::new(DT_RELENT, 0),
                Dyn::new(DT_PLTREL, DT_REL as u64),
                Dyn::new(DT_JMPREL, 0x900),
                Dyn::new(DT_NULL, 0),
            ],
            &[(0x900, vec![0; 8])],
        )
    },
};

pub const DYNAMIC_NULL_MISSING: Case = Case {
    id: "dynamic_null_missing",
    summary: "Dynamic table has entries but no DT_NULL terminator.",
    details: "",
    tags: &[Tag::Existence, Tag::Coexistence],
    spec: || {
        dynamic(
            &[
                Dyn::new(DT_STRTAB, 0x900),
                Dyn::new(DT_STRSZ, 8),
                Dyn::new(DT_SYMTAB, 0x940),
                Dyn::new(DT_SYMENT, 24),
            ],
            &[(0x900, b"\0name\0".to_vec()), (0x940, vec![0; 0x30])],
        )
    },
};

fn dynamic(entries: &[Dyn], extras: &[(u64, Vec<u8>)]) -> ImageSpec {
    let dynamic = dyn_bytes(entries);
    let dyn_offset = file_offset(DYN_VADDR);
    let mut spec = ImageSpec::new(SEG_OFFSET + LOAD_SIZE as usize, Ehdr::exec64().phnum(2))
        .phdr(
            Phdr::new(PT_LOAD)
                .flags(PF_R | PF_W)
                .offset(SEG_OFFSET as u64)
                .vaddr(LOAD_VADDR)
                .paddr(LOAD_VADDR)
                .filesz(LOAD_SIZE)
                .memsz(LOAD_SIZE)
                .align(0x1000),
        )
        .phdr(
            Phdr::new(PT_DYNAMIC)
                .flags(PF_R | PF_W)
                .offset(dyn_offset as u64)
                .vaddr(DYN_VADDR)
                .filesz(dynamic.len() as u64)
                .memsz(dynamic.len() as u64)
                .align(8),
        )
        .bytes(dyn_offset, dynamic);

    for (vaddr, bytes) in extras {
        spec = spec.bytes(file_offset(*vaddr), bytes.clone());
    }

    spec
}

fn file_offset(vaddr: u64) -> usize {
    SEG_OFFSET + (vaddr - LOAD_VADDR) as usize
}

fn word_table(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| le32(*word)).collect()
}

fn gnu_hash_normal() -> Vec<u8> {
    let mut bytes = word_table(&[1, 1, 1, 0]);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend(word_table(&[0]));
    bytes.extend(word_table(&[1]));
    bytes
}

fn gnu_hash_bad_chain_ptr() -> Vec<u8> {
    let mut bytes = word_table(&[1, 0x100, 1, 0]);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend(word_table(&[1]));
    bytes
}
