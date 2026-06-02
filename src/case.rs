use crate::elf::{Image, ImageSpec};

#[derive(Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    pub summary: &'static str,
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
