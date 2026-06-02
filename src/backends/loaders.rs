use crate::backend::{default_classification, BackendSpec};

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command(
        "qemu-x86_64",
        "qemu-x86_64 {}",
        None,
        Some(default_classification),
    ),
    // Full glibc loader lifecycle without executing the program: --preload's the
    // freestanding exitfirst.so, whose constructor _exit()s after the loader has
    // mapped + resolved + relocated everything but before the target's own
    // constructors / main. Mirrors the depth of `ld-musl --list` (and reaches
    // relocation, which `--verify` does not). Build exitfirst.so with setup.sh.
    // (IFUNC resolvers still run during relocation.)
    BackendSpec::command(
        "ld-glibc",
        "/lib64/ld-linux-x86-64.so.2 --preload tools/exitfirst.so {}",
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
