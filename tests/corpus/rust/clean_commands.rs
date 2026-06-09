// WP6 hard-zero corpus: idiomatic, SAFE command usage that must yield ZERO RS-WL
// findings. Each fn is @trusted (so any spurious flag would surface, not be modulated
// away) and exercises an FP-prone shape the analyzer has full information to clear.

use std::process::Command;

/// @trusted(level=ASSURED)
fn all_literal() {
    Command::new("git").arg("status").arg("--short").output();
}

/// @trusted(level=ASSURED)
fn literal_shell_literal_arg() {
    // A shell with a LITERAL command line is not injection.
    Command::new("sh").arg("-c").arg("echo hello").output();
}

/// @trusted(level=ASSURED)
fn nonshell_program_tainted_arg() {
    // Tainted arg into a non-shell program: argv-list, no shell metacharacter risk.
    let user = std::env::var("USER").unwrap();
    Command::new("id").arg(user).output();
}

/// @trusted(level=ASSURED)
fn rebound_to_literal_before_use() {
    let prog = std::env::var("PROG").unwrap();
    let prog = "echo";
    Command::new(prog).arg("done").output();
}

/// @trusted(level=ASSURED)
fn tainted_value_never_reaches_command() {
    // The boundary read is used elsewhere; the command is fully literal.
    let _config = std::fs::read_to_string("config.toml").unwrap();
    Command::new("true").output();
}

/// @trusted(level=ASSURED)
fn shell_no_flag_literal() {
    // sh WITHOUT -c (no shell command line) and a literal program path.
    Command::new("/bin/sh").arg("script.sh").output();
}
