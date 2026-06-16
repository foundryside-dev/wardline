//! Vendored identity fixture — the `rust-app` crate root (`main.rs` contributes
//! no module segment: this file IS the `rust_app` module).

use std::process::Command;

use crate::cmd::runner::Runner;

mod cmd;

pub trait Describe {
    fn describe(&self) -> &'static str;
}

/// @trusted(level=ASSURED)
fn main() {
    let tool = std::env::var("RUSTAPP_TOOL").unwrap();
    // RS-WL-112: untrusted data reaches a `sh -c` shell command line.
    Command::new("sh").arg("-c").arg(tool).output();
    let runner = Runner;
    runner.launch();
}
