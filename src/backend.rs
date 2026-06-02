use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

pub type Summarize = fn(&Path, &Path) -> Option<String>;
pub type Classify = fn(&RunStatus, &Path, &Path) -> Classification;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Category {
    Accepted,
    GracefulWarning,
    GracefulError,
    Crash,
    Timeout,
    Missing,
    ToolError,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Accepted => "accepted",
            Category::GracefulWarning => "graceful-warning",
            Category::GracefulError => "graceful-error",
            Category::Crash => "crash",
            Category::Timeout => "timeout",
            Category::Missing => "missing",
            Category::ToolError => "tool-error",
        }
    }

    pub fn is_unexpected(self) -> bool {
        !matches!(self, Category::GracefulWarning | Category::GracefulError)
    }
}

pub struct Classification {
    pub category: Category,
    pub finding: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunStatus {
    Exit(i32),
    Signal(i32),
    Timeout,
    Missing(String),
    Error(String),
}

impl RunStatus {
    fn from_exit_status(status: std::process::ExitStatus) -> Self {
        if let Some(signal) = status.signal() {
            Self::Signal(signal)
        } else {
            Self::Exit(status.code().unwrap_or_default())
        }
    }
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunStatus::Exit(code) => write!(fmt, "rc={code}"),
            RunStatus::Signal(signal) => match Signal::try_from(*signal) {
                Ok(name) => write!(fmt, "signal={name:?}({signal})"),
                Err(_) => write!(fmt, "signal=SIGUNKNOWN({signal})"),
            },
            RunStatus::Timeout => fmt.write_str("timeout"),
            RunStatus::Missing(program) => write!(fmt, "missing:{program}"),
            RunStatus::Error(err) => write!(fmt, "error:{err}"),
        }
    }
}

#[derive(Clone, Copy)]
pub struct BackendSpec {
    pub name: &'static str,
    pub command: &'static str,
    pub summarize: Option<Summarize>,
    pub classify: Option<Classify>,
}

impl BackendSpec {
    pub const fn command(
        name: &'static str,
        command: &'static str,
        summarize: Option<Summarize>,
        classify: Option<Classify>,
    ) -> Self {
        Self {
            name,
            command,
            summarize,
            classify,
        }
    }

    pub fn display(self) -> &'static str {
        self.command
    }
}

#[derive(Clone)]
pub struct Backend {
    name: String,
    argv: Vec<String>,
    summarize: Option<Summarize>,
    classify: Option<Classify>,
}

pub enum Outcome {
    Finished {
        status: RunStatus,
        category: Category,
        note: String,
        finding: Option<String>,
    },
    Missing(String),
    Error(String),
}

impl Backend {
    pub fn from_spec(spec: BackendSpec) -> Result<Self, String> {
        Self::new_command(spec.name, spec.command, spec.summarize, spec.classify)
    }

    pub fn from_custom(spec: &str) -> Result<Self, String> {
        let (name, command) = spec.split_once('=').unwrap_or((spec, spec));
        if name.is_empty() {
            return Err("backend name is empty".to_string());
        }
        Self::new_command(name, command, None, None)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn program(&self) -> &str {
        &self.argv[0]
    }

    pub fn is_available(&self) -> bool {
        command_exists(&self.argv[0])
    }

    pub fn run(
        &self,
        fixture: &Path,
        timeout: Duration,
        stdout_path: &Path,
        stderr_path: &Path,
    ) -> Outcome {
        let argv = self.fixture_argv(fixture);
        let stdout = match File::create(stdout_path) {
            Ok(file) => file,
            Err(err) => return Outcome::Error(err.to_string()),
        };
        let stderr = match File::create(stderr_path) {
            Ok(file) => file,
            Err(err) => return Outcome::Error(err.to_string()),
        };

        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Outcome::Missing(argv[0].clone());
            }
            Err(err) => return Outcome::Error(err.to_string()),
        };

        let process_group = Pid::from_raw(child.id() as i32);
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    kill_process_group(process_group);
                    let status = RunStatus::from_exit_status(status);
                    let classification = self.classification(&status, stdout_path, stderr_path);
                    return Outcome::Finished {
                        category: classification.category,
                        finding: classification.finding,
                        note: self.note(stdout_path, stderr_path),
                        status,
                    };
                }
                Ok(None) if start.elapsed() >= timeout => {
                    kill_process_group(process_group);
                    let _ = child.wait();
                    let status = RunStatus::Timeout;
                    let classification = self.classification(&status, stdout_path, stderr_path);
                    return Outcome::Finished {
                        status,
                        category: classification.category,
                        finding: classification.finding,
                        note: self.note(stdout_path, stderr_path),
                    };
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(err) => return Outcome::Error(err.to_string()),
            }
        }
    }

    pub fn new_command(
        name: &str,
        command: &str,
        summarize: Option<Summarize>,
        classify: Option<Classify>,
    ) -> Result<Self, String> {
        Ok(Self {
            name: name.to_string(),
            argv: command_argv(command)?,
            summarize,
            classify,
        })
    }

    fn note(&self, stdout_path: &Path, stderr_path: &Path) -> String {
        self.summarize
            .and_then(|summarize| summarize(stdout_path, stderr_path))
            .or_else(|| default_summary(stdout_path, stderr_path))
            .unwrap_or_default()
    }

    fn classification(
        &self,
        status: &RunStatus,
        stdout_path: &Path,
        stderr_path: &Path,
    ) -> Classification {
        self.classify
            .map(|classify| classify(status, stdout_path, stderr_path))
            .unwrap_or_else(|| default_classification(status, stdout_path, stderr_path))
    }

    fn fixture_argv(&self, fixture: &Path) -> Vec<String> {
        let fixture = fixture.display().to_string();
        if self.argv.iter().any(|arg| arg.contains("{}")) {
            self.argv
                .iter()
                .map(|arg| arg.replace("{}", &fixture))
                .collect()
        } else {
            let mut argv = self.argv.clone();
            argv.push(fixture);
            argv
        }
    }
}

fn command_argv(input: &str) -> Result<Vec<String>, String> {
    let words = shlex::split(input).ok_or_else(|| format!("invalid command: {input}"))?;
    if words.is_empty() {
        Err("empty command".to_string())
    } else {
        Ok(words)
    }
}

fn command_exists(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).is_file();
    }

    env::var_os("PATH")
        .into_iter()
        .flat_map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .any(|dir| dir.join(program).is_file())
}

fn kill_process_group(process_group: Pid) {
    let _ = killpg(process_group, Signal::SIGKILL);
}

fn default_summary(stdout_path: &Path, stderr_path: &Path) -> Option<String> {
    first_line(stderr_path).or_else(|| first_line(stdout_path))
}

pub(crate) fn first_line(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    BufReader::new(file).lines().find_map(Result::ok)
}

/// First line in `path` containing `needle`, if any.
pub(crate) fn find_line(path: &Path, needle: &str) -> Option<String> {
    let file = File::open(path).ok()?;
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .find(|line| line.contains(needle))
}

pub(crate) fn default_classification(
    status: &RunStatus,
    _stdout_path: &Path,
    stderr_path: &Path,
) -> Classification {
    match status {
        RunStatus::Exit(0) => {
            if let Some(line) = first_line(stderr_path) {
                Classification {
                    category: Category::GracefulWarning,
                    finding: Some(line),
                }
            } else {
                Classification {
                    category: Category::Accepted,
                    finding: Some("accepted malformed input".to_string()),
                }
            }
        }
        RunStatus::Exit(_) => Classification {
            category: Category::GracefulError,
            finding: first_line(stderr_path)
                .or_else(|| Some("backend rejected malformed input".to_string())),
        },
        RunStatus::Signal(_) => {
            // qemu-user (and similar emulators) actually execute the guest. When
            // the *loaded program* faults, qemu prints "qemu: uncaught target
            // signal N (...)" and re-raises it, so the qemu process dies with a
            // signal — but the emulator/loader handled the input fine; it is the
            // guest running (garbage) code that crashed, not a loader bug. Treat
            // that as a graceful guest fault rather than a backend crash.
            if let Some(line) = find_line(stderr_path, "uncaught target signal") {
                Classification {
                    category: Category::GracefulError,
                    finding: Some(line),
                }
            } else {
                Classification {
                    category: Category::Crash,
                    finding: Some("backend crashed".to_string()),
                }
            }
        }
        RunStatus::Timeout => Classification {
            category: Category::Timeout,
            finding: Some("backend timed out".to_string()),
        },
        RunStatus::Missing(_) => Classification {
            category: Category::Missing,
            finding: Some("backend program is missing".to_string()),
        },
        RunStatus::Error(_) => Classification {
            category: Category::ToolError,
            finding: Some("runner or backend invocation failed".to_string()),
        },
    }
}
