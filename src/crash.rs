//! A crash found by fuzzing a dynamic loader.
//!
//! Distinct from [`crate::case::Case`]: a `Case` is a deliberately crafted ELF
//! that violates a structural *invariant* (its `tags` are that taxonomy). A
//! `Crash` is a concrete input plus an *observed loader fault* — which loader,
//! which signal, where it faults, and whether we reduced it to an understandable
//! structured reproducer or kept the raw fuzzer artifact. Both flow through the
//! same `gen` -> `fixtures/` -> `check` pipeline via `id` + [`Crash::image`].
use crate::elf::{Image, ImageSpec};

/// Which loader the input crashes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Loader {
    Glibc,
    Musl,
}

/// The fault signal observed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signal {
    /// SIGSEGV — access to unmapped memory.
    Segv,
    /// SIGBUS — typically a store to a file-backed page past end-of-file.
    Bus,
}

/// How faithfully the case represents the original fuzzer finding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Repro {
    /// Rebuilt from the structured ELF builders so the malformation is legible.
    Structured,
    /// Verbatim fuzzer bytes — the fault depends on the loader walking into
    /// garbage/unmapped memory and has no tidy structural form.
    RawArtifact,
}

#[derive(Clone, Copy)]
pub struct Crash {
    /// Fixture name written under `fixtures/`.
    pub id: &'static str,
    /// Loader that faults on this input.
    pub loader: Loader,
    /// Observed fault signal (see `details` when a site can raise either).
    pub signal: Signal,
    /// Faulting site: function plus `file:line`, e.g.
    /// `"_dl_map_segments memset (dl-map-segments.h:177)"`.
    pub site: &'static str,
    /// Whether this is a structured reproducer or a kept-raw artifact.
    pub repro: Repro,
    /// Long-form analysis: triggering field(s) and root cause.
    pub details: &'static str,
    /// Builds the crashing image (structured spec, or `ImageSpec::raw` bytes).
    pub spec: fn() -> ImageSpec,
}

impl Crash {
    pub fn image(self) -> Image {
        (self.spec)().into_image()
    }
}

impl Loader {
    pub const fn name(self) -> &'static str {
        match self {
            Loader::Glibc => "glibc",
            Loader::Musl => "musl",
        }
    }
}

impl Signal {
    pub const fn name(self) -> &'static str {
        match self {
            Signal::Segv => "SIGSEGV",
            Signal::Bus => "SIGBUS",
        }
    }
}

impl Repro {
    pub const fn name(self) -> &'static str {
        match self {
            Repro::Structured => "structured",
            Repro::RawArtifact => "raw-artifact",
        }
    }
}
