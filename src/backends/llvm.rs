use crate::backend::{default_classification, BackendSpec};

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command(
        "llvm-readelf",
        "llvm-readelf -a {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "llvm-objdump",
        "llvm-objdump -p {}",
        None,
        Some(default_classification),
    ),
];
