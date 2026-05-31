use std::path::Path;

use crate::backend::{
    default_classification, first_line, BackendSpec, Category, Classification, RunStatus,
};

const PYELFTOOLS: &str =
    "sh -c 'cd ../third_party/impl-tool/pyelftools && python3 scripts/readelf.py -e -d -n -r -V \"$1\"' sh {}";
const OBJECT_READOBJ: &str =
    "tools/bin/object-readobj --file-header --segments --sections --symbols --relocations --elf-dynamic --elf-notes --elf-version-info {}";

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command("pyelftools", PYELFTOOLS, None, Some(pyelftools_classify)),
    BackendSpec::command(
        "object-readobj",
        OBJECT_READOBJ,
        None,
        Some(default_classification),
    ),
];

fn pyelftools_classify(
    status: &RunStatus,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Classification {
    if matches!(status, RunStatus::Exit(_))
        && first_line(stderr_path).is_some_and(|line| line.contains("ModuleNotFoundError"))
    {
        Classification {
            category: Category::Missing,
            finding: Some("python3-pyelftools is not installed".to_string()),
        }
    } else {
        default_classification(status, stdout_path, stderr_path)
    }
}
