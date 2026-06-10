//! Class-2 fixture (under the crate root, OUTSIDE src/): frozen under the
//! reserved `#out` route segment — `rust_app.#out.tests.integration` — so a
//! class-2 FINDING with the non-conformance branding is pinned in the corpus.
//! No path-typed generic args (reserved-colon constraint, see the README).

use std::process::Command;

/// @trusted(level=ASSURED)
fn shell_smoke() {
    let tool = std::env::var("RUSTAPP_TOOL").unwrap();
    // RS-WL-112: untrusted data reaches a `sh -c` shell command line.
    Command::new("sh").arg("-c").arg(tool).output();
}
