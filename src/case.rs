use crate::elf::{Image, ImageSpec};

#[derive(Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    /// One-line description (compact `check` output, summary.tsv).
    pub summary: &'static str,
    /// Long-form analysis for cases that need it (notably fuzzer-found crashes:
    /// fault site, triggering field, root cause). Empty when the one-line
    /// `summary` already says everything. Kept as data, not a doc comment, so it
    /// can be rendered elsewhere (e.g. a generated report/webpage).
    pub details: &'static str,
    pub tags: &'static [Tag],
    pub spec: fn() -> ImageSpec,
}

impl Case {
    pub fn image(self) -> Image {
        (self.spec)().into_image()
    }
}

#[derive(Clone, Copy)]
pub enum Tag {
    Existence,
    Coexistence,
    Uniqueness,
    Bounds,
    NonOverlap,
    Containment,
    Conjugate,
    Cardinality,
    Alignment,
    Ordering,
    Consistency,
    Encoding,
}

impl Tag {
    pub const fn name(self) -> &'static str {
        match self {
            Tag::Existence => "existence",
            Tag::Coexistence => "coexistence",
            Tag::Uniqueness => "uniqueness",
            Tag::Bounds => "bounds",
            Tag::NonOverlap => "non-overlap",
            Tag::Containment => "containment",
            Tag::Conjugate => "conjugate",
            Tag::Cardinality => "cardinality",
            Tag::Alignment => "alignment",
            Tag::Ordering => "ordering",
            Tag::Consistency => "consistency",
            Tag::Encoding => "encoding",
        }
    }
}
