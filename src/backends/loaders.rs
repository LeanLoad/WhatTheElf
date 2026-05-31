use crate::backend::{default_classification, BackendSpec};

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command(
        "qemu-x86_64",
        "qemu-x86_64 {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "ld-linux",
        "/lib64/ld-linux-x86-64.so.2 --verify {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "ld-musl",
        "/lib/ld-musl-x86_64.so.1 --list {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "kernel-execve",
        "target/debug/kernel-execve {}",
        None,
        Some(default_classification),
    ),
];
