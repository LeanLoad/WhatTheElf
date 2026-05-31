use std::path::Path;

use crate::backend::{
    default_classification, first_line, BackendSpec, Category, Classification, RunStatus,
};

pub const ALL: &[BackendSpec] = &[
    BackendSpec::command(
        "file",
        "file {}",
        Some(no_summary),
        Some(file_output_classify),
    ),
    BackendSpec::command(
        "scanelf",
        "scanelf -q -F '%F %t %p %n' {}",
        None,
        Some(default_classification),
    ),
    BackendSpec::command(
        "patchelf",
        "patchelf --print-interpreter {}",
        None,
        Some(default_classification),
    ),
];

fn no_summary(_stdout_path: &Path, _stderr_path: &Path) -> Option<String> {
    Some(String::new())
}

fn file_output_classify(
    status: &RunStatus,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Classification {
    if !matches!(status, RunStatus::Exit(0)) {
        return default_classification(status, stdout_path, stderr_path);
    }

    let Some(line) = first_line(stdout_path) else {
        return Classification {
            category: Category::Accepted,
            finding: Some("file produced no classification output".to_string()),
        };
    };

    let (_, summary) = line.split_once(": ").unwrap_or(("", line.as_str()));
    if summary == "data" {
        Classification {
            category: Category::GracefulError,
            finding: Some("not recognized as ELF".to_string()),
        }
    } else if summary.contains("corrupted")
        || summary.contains("can't read")
        || summary.contains("missing section headers")
        || summary.contains("interpreter *empty*")
    {
        Classification {
            category: Category::GracefulError,
            finding: Some("classifier noticed malformed structure".to_string()),
        }
    } else {
        Classification {
            category: Category::Accepted,
            finding: Some("classified malformed input as ordinary ELF".to_string()),
        }
    }
}
