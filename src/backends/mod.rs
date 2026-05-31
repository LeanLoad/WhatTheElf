mod binutils;
mod elfutils;
mod libraries;
mod llvm;
mod loaders;
mod misc;

use crate::backend::{Backend, BackendSpec};

pub fn all() -> impl Iterator<Item = BackendSpec> {
    [
        loaders::ALL,
        misc::ALL,
        binutils::ALL,
        llvm::ALL,
        elfutils::ALL,
        libraries::ALL,
    ]
    .into_iter()
    .flatten()
    .copied()
}

pub fn resolve(spec: &str) -> Result<Backend, String> {
    all()
        .find(|backend| spec == backend.name)
        .map(Backend::from_spec)
        .unwrap_or_else(|| Backend::from_custom(spec))
}
