// WP6 dense positive corpus: every @trusted fn below is an INTENDED command-injection
// sink (6 × RS-WL-108 program injection, 3 × RS-WL-112 shell injection) plus 3 benign
// neighbours that must NOT fire (the false-positive probes). The frontend must flag
// exactly the 9 intended sinks and none of the 3 benign ones (≤5% FP gate, target 0).
//
// All taint is sourced through the proven `.unwrap()`-wrapped std sources
// (env::var / env::var_os / fs::read_to_string / fs::read → EXTERNAL_RAW).

use std::process::Command;

// ---- RS-WL-108: untrusted data selects the program (6 sinks) ----

/// @trusted(level=ASSURED)
fn sink_env_var_output() {
    let t = std::env::var("PROG").unwrap();
    Command::new(t).output();
}

/// @trusted(level=ASSURED)
fn sink_env_var_os_status() {
    let t = std::env::var_os("PROG").unwrap();
    Command::new(t).status();
}

/// @trusted(level=ASSURED)
fn sink_fs_read_to_string_try() -> std::io::Result<()> {
    let t = std::fs::read_to_string("prog.txt").unwrap();
    Command::new(t).output()?;
    Ok(())
}

/// @trusted(level=ASSURED)
async fn sink_fs_read_await() {
    let t = std::fs::read("prog.bin").unwrap();
    Command::new(t).output().await;
}

/// @trusted(level=ASSURED)
fn sink_return_position() -> std::process::Output {
    let t = std::env::var("PROG").unwrap();
    return Command::new(t).output().unwrap();
}

/// @trusted(level=ASSURED)
fn sink_stepwise() {
    let t = std::fs::read_to_string("prog.txt").unwrap();
    let mut c = Command::new(t);
    c.output();
}

// ---- RS-WL-112: untrusted data reaches a shell command line (3 sinks) ----

/// @trusted(level=ASSURED)
fn sink_sh_dash_c() {
    let t = std::env::var("CMD").unwrap();
    Command::new("sh").arg("-c").arg(t).output();
}

/// @trusted(level=ASSURED)
fn sink_bin_bash_dash_c() {
    let t = std::fs::read_to_string("cmd.txt").unwrap();
    Command::new("/bin/bash").arg("-c").arg(t).status();
}

/// @trusted(level=ASSURED)
fn sink_powershell_command() {
    let t = std::env::var_os("CMD").unwrap();
    Command::new("powershell").arg("-Command").arg(t).spawn();
}

// ---- Benign neighbours: must NOT fire (false-positive probes) ----

/// @trusted(level=ASSURED)
fn benign_all_literal() {
    Command::new("ls").arg("-la").output();
}

/// @trusted(level=ASSURED)
fn benign_nonshell_tainted_arg() {
    // Tainted ARG into a NON-shell program is the argv-list flood, not injection.
    let t = std::env::var("NAME").unwrap();
    Command::new("ls").arg(t).output();
}

/// @trusted(level=ASSURED)
fn benign_rebound_to_clean() {
    let t = std::env::var("PROG").unwrap();
    let t = "safe";
    Command::new(t).output();
}
