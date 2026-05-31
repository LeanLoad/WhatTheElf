use std::env;
use std::os::unix::process::ExitStatusExt;
use std::process::{self, Command};

use nix::sys::signal::{raise, Signal};

fn main() {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: kernel-execve PATH");
        process::exit(2);
    };

    match Command::new(path).status() {
        Ok(status) => {
            if let Some(signal) = status.signal() {
                if let Ok(signal) = Signal::try_from(signal) {
                    let _ = raise(signal);
                }
                process::exit(128 + signal);
            }
            process::exit(status.code().unwrap_or(1));
        }
        Err(err) => {
            eprintln!("execve: {err}");
            process::exit(126);
        }
    }
}
