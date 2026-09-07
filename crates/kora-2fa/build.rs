//! Bakes the short git commit hash into the binary as `GIT_SHA`, read at
//! runtime with `env!("GIT_SHA")`. Falls back to `"unknown"` when git is
//! unavailable (matches `docs/environment-variables.md`).

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=GIT_SHA={sha}");
    // Re-run when HEAD moves so the baked SHA stays current.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
}
