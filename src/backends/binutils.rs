use crate::backend::{default_classification, BackendSpec};

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command(
        "readelf",
        "readelf -a {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "objdump",
        "objdump -p {}",
        None,
        Some(default_classification),
    ),
];
