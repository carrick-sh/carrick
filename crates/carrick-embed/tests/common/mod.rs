//! Shared helpers for carrick-embed's guest-running (signed) tests.
//!
//! These suites are run ONLY through `just test-embed` (scripts/test-signed.sh),
//! which signs the test executable with the hypervisor entitlement, exports
//! `CARRICK_RUN_ID`, and runs it under `RUST_TEST_THREADS=1`.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use carrick_embed::{ContainerResult, EmbedError};

/// The canonical smoke image: the arm64 probe lane's image
/// (`crates/carrick-cli/tests/conformance.rs:209`, `ARM64.image`) and
/// AGENTS.md's default guest (frame pointers, so `carrick trace` can walk it).
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

static GUEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize guest-running tests inside one process: HVF allows one VM per
/// process, and the Inherit case redirects the process's own fd 1. The recipe
/// sets `RUST_TEST_THREADS=1`; this is the in-file belt for a filtered run.
pub fn guest_lock() -> MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The repository root (`crates/carrick-embed` is two levels down).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-embed lives under crates/carrick-embed")
        .to_path_buf()
}

/// Unwrap a container run, turning `EmbedError::Entitlement` into a loud,
/// actionable FAILURE. Never a skip: an unsigned test executable is a broken
/// gate, not an absent one.
pub fn run_or_fail(outcome: Result<ContainerResult, EmbedError>) -> ContainerResult {
    match outcome {
        Ok(result) => result,
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): this test executable lacks \
             com.apple.security.hypervisor. Run it through `just test-embed` \
             (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
             can never boot a guest."
        ),
        Err(err) => panic!("container run failed: {err}"),
    }
}

/// The run id `scripts/test-signed.sh` exported. Every guest this process
/// launches is titled `carrick:<run-id>:`, and the CLI-parity test derives
/// `<run-id>-cli` for the child it spawns, so `scripts/sudo/kill.sh` can reap
/// exactly this run. Fail closed: without the stamp nothing can clean up.
pub fn run_id() -> String {
    std::env::var("CARRICK_RUN_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .expect(
            "CARRICK_RUN_ID must be set: scripts/test-signed.sh exports it so \
             scripts/sudo/kill.sh can reap this run's guests",
        )
}
