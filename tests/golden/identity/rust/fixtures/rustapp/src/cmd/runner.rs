//! Tool runner — the cross-file module route (`rust_app.cmd.runner`), the impl
//! surface, a cfg twin, and the leaf kinds the corpus freezes.
//!
//! Deliberately NO path-typed generic args anywhere (e.g. `impl From<std::io::Error>`):
//! the reserved-colon rendering is an un-decided cross-tool ADR-049 case — see the
//! corpus README.

use std::process::Command;

use crate::Describe;

pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

pub enum Mode {
    Direct,
    Shell,
}

pub struct Runner;

impl Runner {
    /// @trusted(level=ASSURED)
    pub fn launch(&self) {
        let tool = std::env::var("RUSTAPP_TOOL").unwrap();
        // RS-WL-108: untrusted data selects the program run by Command::new.
        let mut command = Command::new(tool);
        command.output();
    }
}

impl Describe for Runner {
    fn describe(&self) -> &'static str {
        "runner"
    }
}

#[cfg(unix)]
pub fn shell_name() -> &'static str {
    "sh"
}

#[cfg(windows)]
pub fn shell_name() -> &'static str {
    "cmd.exe"
}
