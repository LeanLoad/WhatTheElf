use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::IsTerminal;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use serde::Serialize;
use whattheelf::backend::{Category, Outcome, RunStatus};
use whattheelf::backends;

#[derive(Parser)]
struct Args {
    #[arg(long, help = "List built-in backends")]
    list: bool,

    #[arg(
        long,
        default_value = "5",
        value_parser = parse_timeout,
        help = "Per-fixture timeout in seconds"
    )]
    timeout: Duration,

    #[arg(value_name = "BACKEND")]
    backends: Vec<String>,

    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    #[arg(long, help = "Print every result instead of only unexpected results")]
    all: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Serialize)]
struct RunRecord {
    backend: String,
    case: String,
    category: String,
    status: String,
    stdout: String,
    stderr: String,
    note: String,
    finding: Option<String>,
}

struct RunLine {
    case: String,
    category: Category,
    status: RunStatus,
    json: PathBuf,
    note: String,
    finding: Option<String>,
}

fn parse_timeout(value: &str) -> Result<Duration, String> {
    let seconds = value
        .parse::<f64>()
        .map_err(|err| format!("invalid timeout: {err}"))?;
    if seconds.is_finite() && seconds >= 0.0 {
        Duration::try_from_secs_f64(seconds).map_err(|_| "timeout is too large".to_string())
    } else {
        Err("timeout must be finite and non-negative".to_string())
    }
}

fn fixtures(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn tsv(value: &str) -> String {
    value.replace('\t', " ").replace(['\r', '\n'], " ")
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn result_paths(backend_dir: &Path, case: &str) -> (PathBuf, PathBuf, PathBuf) {
    let stem = sanitize(case);
    (
        backend_dir.join(format!("{stem}.stdout")),
        backend_dir.join(format!("{stem}.stderr")),
        backend_dir.join(format!("{stem}.json")),
    )
}

fn write_record(root: &Path, path: &Path, record: &RunRecord) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", rel(root, parent)))?;
    }
    let file = File::create(path).map_err(|err| format!("{}: {err}", rel(root, path)))?;
    serde_json::to_writer_pretty(file, record).map_err(|err| format!("{}: {err}", rel(root, path)))
}

fn use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => std::io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none(),
    }
}

fn color_category(category: Category, value: &str, color: bool) -> String {
    if !color {
        return value.to_string();
    }

    let code = if matches!(category, Category::GracefulError) {
        "32"
    } else if matches!(category, Category::Crash | Category::ToolError) {
        "31"
    } else if matches!(category, Category::Timeout) {
        "35"
    } else {
        "33"
    };
    format!("\x1b[{code}m{value}\x1b[0m")
}

fn empty_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", path.display()))?;
    }
    File::create(path)
        .map(|_| ())
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = Args::parse();
    let color = use_color(args.color);

    if args.list {
        for backend in backends::all() {
            println!("{:34} {}", backend.name, backend.display());
        }
        return Ok(());
    }
    let timeout = args.timeout;
    let mut specs = args.backends;
    if specs.is_empty() {
        specs.extend(backends::all().map(|backend| backend.name.to_string()));
    }

    let fixtures = fixtures(&root.join("fixtures"))?;
    if fixtures.is_empty() {
        return Err("no fixtures found; run gen first".into());
    }

    let results = root.join("results");
    if results.exists() {
        fs::remove_dir_all(&results)?;
    }
    fs::create_dir_all(&results)?;

    let summary_path = results.join("summary.tsv");
    let mut summary = File::create(&summary_path)?;
    writeln!(
        summary,
        "backend\tcase\tcategory\tstatus\tjson\tnote\tfinding"
    )?;

    println!("results: {}", results.strip_prefix(root)?.display());
    for spec in specs {
        let backend = backends::resolve(&spec)?;
        let backend_name = sanitize(backend.name());
        let backend_dir = results.join(&backend_name);
        fs::create_dir_all(&backend_dir)?;

        println!("== {} ==", backend.name());
        if !backend.is_available() {
            println!("missing: {}", backend.program());
            for fixture in &fixtures {
                let case = fixture.file_name().unwrap_or_default().to_string_lossy();
                let (stdout, stderr, json) = result_paths(&backend_dir, &case);
                empty_file(&stdout).map_err(std::io::Error::other)?;
                empty_file(&stderr).map_err(std::io::Error::other)?;
                let status = RunStatus::Missing(backend.program().to_string());
                let record = RunRecord {
                    backend: backend.name().to_string(),
                    case: case.to_string(),
                    category: Category::Missing.as_str().to_string(),
                    status: status.to_string(),
                    stdout: rel(root, &stdout),
                    stderr: rel(root, &stderr),
                    note: String::new(),
                    finding: Some(format!("missing backend program: {}", backend.program())),
                };
                write_record(root, &json, &record).map_err(std::io::Error::other)?;
                writeln!(
                    summary,
                    "{}\t{}\t{}\t{}\t{}\t\t{}",
                    tsv(backend.name()),
                    tsv(&case),
                    Category::Missing.as_str(),
                    tsv(&status.to_string()),
                    tsv(&rel(root, &json)),
                    tsv(record.finding.as_deref().unwrap_or("")),
                )?;
            }
            continue;
        }

        let lines: Vec<_> = fixtures
            .par_iter()
            .map(|fixture| {
                let name = fixture.file_name().unwrap_or_default().to_string_lossy();
                let (stdout, stderr, json) = result_paths(&backend_dir, &name);
                let (category, status, note, finding) =
                    match backend.run(fixture, timeout, &stdout, &stderr) {
                        Outcome::Finished {
                            status,
                            category,
                            note,
                            finding,
                        } => (category, status, note, finding),
                        Outcome::Missing(program) => (
                            Category::Missing,
                            RunStatus::Missing(program.clone()),
                            String::new(),
                            Some(format!("missing backend program: {program}")),
                        ),
                        Outcome::Error(err) => (
                            Category::ToolError,
                            RunStatus::Error(err),
                            String::new(),
                            Some("runner or backend invocation failed".to_string()),
                        ),
                    };
                let record = RunRecord {
                    backend: backend.name().to_string(),
                    case: name.to_string(),
                    category: category.as_str().to_string(),
                    status: status.to_string(),
                    stdout: rel(root, &stdout),
                    stderr: rel(root, &stderr),
                    note: note.clone(),
                    finding: finding.clone(),
                };
                write_record(root, &json, &record)?;
                Ok(RunLine {
                    case: name.to_string(),
                    category,
                    status,
                    json,
                    note,
                    finding,
                })
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(std::io::Error::other)?;

        for line in lines {
            let RunLine {
                case,
                category,
                status,
                json,
                note,
                finding,
            } = line;
            if category.is_unexpected() || args.all {
                let terminal_category = color_category(category, category.as_str(), color);
                if let Some(finding) = &finding {
                    println!(
                        "{:14} {case:24} {terminal_category:24} {status:16} {note} [{finding}]",
                        backend.name()
                    );
                } else {
                    println!(
                        "{:14} {case:24} {terminal_category:24} {status:16} {note}",
                        backend.name()
                    );
                }
            }
            writeln!(
                summary,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                tsv(backend.name()),
                tsv(&case),
                category.as_str(),
                tsv(&status.to_string()),
                tsv(&rel(root, &json)),
                tsv(&note),
                tsv(finding.as_deref().unwrap_or("")),
            )?;
        }
    }

    println!("summary: {}", summary_path.strip_prefix(root)?.display());

    Ok(())
}
