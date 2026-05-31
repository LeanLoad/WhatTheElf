use crate::backend::{default_classification, BackendSpec};

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command(
        "eu-readelf",
        "eu-readelf -a {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "eu-elflint",
        "eu-elflint {}",
        None,
        Some(default_classification),
    ),
];
