use crate::case::{Case, Tag};
use crate::elf::{Ehdr, ImageSpec, Phdr, PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD, PT_PHDR};

use super::load_phdr;

pub const PHNUM_ZERO: Case = Case {
    id: "phnum_zero",
    summary: "ELF executable declares zero program headers.",
    tags: &[Tag::Existence, Tag::Cardinality],
    spec: || ImageSpec::new(0x141, Ehdr::exec64().phnum(0)),
};

pub const PHOFF_OOB: Case = Case {
    id: "phoff_oob",
    summary: "Program-header table offset points beyond the file.",
    tags: &[Tag::Bounds],
    spec: || ImageSpec::new(0x40, Ehdr::exec64().phoff(0x10000).phnum(1)),
};

pub const PHNUM_HUGE_OOB: Case = Case {
    id: "phnum_huge_oob",
    summary: "Program-header count is huge while the file contains only one entry.",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || ImageSpec::new(0x40 + 0x38, Ehdr::exec64().phnum(0xffff)).phdr(load_phdr()),
};

pub const PHDR_TABLE_TRUNCATED: Case = Case {
    id: "phdr_table_truncated",
    summary: "Program-header count asks for two entries but only one is present.",
    tags: &[Tag::Bounds, Tag::Cardinality],
    spec: || ImageSpec::new(0x40 + 0x38, Ehdr::exec64().phnum(2)).phdr(load_phdr()),
};

pub const PHDR_OVERLAPS_EHDR: Case = Case {
    id: "phdr_overlaps_ehdr",
    summary: "Program-header table range starts inside the ELF header.",
    tags: &[Tag::NonOverlap, Tag::Containment],
    spec: || ImageSpec::new(0x20 + 0x38, Ehdr::exec64().phoff(0x20).phnum(1)),
};

pub const PHDR_MISALIGNED: Case = Case {
    id: "phdr_misaligned",
    summary: "Program-header table starts at an unaligned file offset.",
    tags: &[Tag::Alignment],
    spec: || ImageSpec::new(0x41 + 0x38, Ehdr::exec64().phoff(0x41).phnum(1)).phdr(load_phdr()),
};

pub const PT_PHDR_MISALIGNED: Case = Case {
    id: "pt_phdr_misaligned",
    summary: "Special PT_PHDR entry is itself placed at a misaligned file offset.",
    tags: &[Tag::Alignment],
    spec: || {
        ImageSpec::new(0x41 + 0x38, Ehdr::exec64().phoff(0x41).phnum(1)).phdr(
            Phdr::new(PT_PHDR)
                .flags(PF_R)
                .offset(0x41)
                .vaddr(0x400041)
                .paddr(0x400041)
                .filesz(0x38)
                .memsz(0x38)
                .align(8),
        )
    },
};

pub const FILESZ_GT_MEMSZ: Case = Case {
    id: "filesz_gt_memsz",
    summary: "Loadable segment has p_filesz greater than p_memsz.",
    tags: &[Tag::Conjugate],
    spec: || {
        ImageSpec::new(0x40 + 0x38, Ehdr::exec64().phnum(1)).phdr(
            Phdr::new(PT_LOAD)
                .flags(PF_R | PF_X)
                .offset(0)
                .vaddr(0x400000)
                .paddr(0x400000)
                .filesz(0x100)
                .memsz(0x80)
                .align(0x1000),
        )
    },
};

pub const LOAD_OFFSET_OOB: Case = Case {
    id: "load_offset_oob",
    summary: "Loadable segment file range points beyond the file.",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        ImageSpec::new(0x40 + 0x38, Ehdr::exec64().phnum(1)).phdr(
            Phdr::new(PT_LOAD)
                .flags(PF_R | PF_X)
                .offset(0x1000)
                .vaddr(0x400000)
                .paddr(0x400000)
                .filesz(0x20)
                .memsz(0x20)
                .align(0x1000),
        )
    },
};

pub const LOAD_VADDR_WRAPAROUND: Case = Case {
    id: "load_vaddr_wraparound",
    summary: "Loadable segment virtual-address arithmetic wraps around u64.",
    tags: &[Tag::Bounds, Tag::Conjugate],
    spec: || {
        ImageSpec::new(0x2000, Ehdr::exec64().phnum(1)).phdr(
            Phdr::new(PT_LOAD)
                .flags(PF_R | PF_X)
                .offset(0)
                .vaddr(0xffff_ffff_ffff_f000)
                .paddr(0xffff_ffff_ffff_f000)
                .filesz(0x2000)
                .memsz(0x2000)
                .align(0x1000),
        )
    },
};

pub const LOAD_ALIGN_NON_POWER_TWO: Case = Case {
    id: "load_align_non_power_two",
    summary: "Loadable segment alignment is neither zero nor a power of two.",
    tags: &[Tag::Alignment, Tag::Encoding],
    spec: || {
        ImageSpec::new(0x40 + 0x38, Ehdr::exec64().phnum(1)).phdr(
            Phdr::new(PT_LOAD)
                .flags(PF_R | PF_W)
                .offset(0)
                .vaddr(0x400000)
                .paddr(0x400000)
                .filesz(0x80)
                .memsz(0x80)
                .align(3),
        )
    },
};

pub const INTERP_FILESZ_ZERO: Case = Case {
    id: "interp_filesz_zero",
    summary: "PT_INTERP segment has zero file size.",
    tags: &[Tag::Existence, Tag::Cardinality],
    spec: || {
        ImageSpec::new(0xb1, Ehdr::exec64().phnum(2))
            .phdr(load_phdr())
            .phdr(
                Phdr::new(PT_INTERP)
                    .flags(PF_R)
                    .offset(0xb0)
                    .filesz(0)
                    .memsz(0)
                    .align(1),
            )
    },
};

pub const INTERP_EMPTY_STRING: Case = Case {
    id: "interp_empty_string",
    summary: "PT_INTERP contains only a NUL byte, yielding an empty interpreter path.",
    tags: &[Tag::Existence, Tag::Encoding],
    spec: || {
        ImageSpec::new(0xb1, Ehdr::exec64().phnum(2))
            .phdr(load_phdr())
            .phdr(
                Phdr::new(PT_INTERP)
                    .flags(PF_R)
                    .offset(0xb0)
                    .filesz(1)
                    .memsz(1)
                    .align(1),
            )
            .bytes(0xb0, vec![0])
    },
};

pub const INTERP_OFFSET_OOB: Case = Case {
    id: "interp_offset_oob",
    summary: "PT_INTERP segment points beyond the file.",
    tags: &[Tag::Bounds, Tag::Containment],
    spec: || {
        ImageSpec::new(0xb0, Ehdr::exec64().phnum(2))
            .phdr(load_phdr())
            .phdr(
                Phdr::new(PT_INTERP)
                    .flags(PF_R)
                    .offset(0x1000)
                    .filesz(8)
                    .memsz(8)
                    .align(1),
            )
    },
};

pub const INTERP_NO_NUL: Case = Case {
    id: "interp_no_nul",
    summary: "PT_INTERP segment contains a non-empty interpreter name without a trailing NUL.",
    tags: &[Tag::Encoding, Tag::Consistency],
    spec: || {
        ImageSpec::new(0xb4, Ehdr::exec64().phnum(2))
            .phdr(load_phdr())
            .phdr(
                Phdr::new(PT_INTERP)
                    .flags(PF_R)
                    .offset(0xb0)
                    .filesz(4)
                    .memsz(4)
                    .align(1),
            )
            .bytes(0xb0, b"ld-x".to_vec())
    },
};
