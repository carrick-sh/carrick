//! Shared helpers for carrick-conformance-next guest-running tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use carrick_conformance_next::EmbedError;

/// The canonical conformance image: arm64 Ubuntu 24.04.
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

static GUEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize guest-running tests inside one process.
pub fn guest_lock() -> MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The repository root (`crates/carrick-conformance-next` is two levels down).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-conformance-next lives under crates/carrick-conformance-next")
        .to_path_buf()
}

/// Unwrap a container run, converting `EmbedError::Entitlement` into a loud failure.
pub fn run_or_fail<T>(outcome: Result<T, EmbedError>) -> T {
    match outcome {
        Ok(result) => result,
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): this test executable lacks \
             com.apple.security.hypervisor. Run it through `just test-conformance-next` \
             or `scripts/test-signed.sh carrick-conformance-next`."
        ),
        Err(err) => panic!("container run failed: {err}"),
    }
}

/// The run id exported by the test runner.
pub fn run_id() -> String {
    std::env::var("CARRICK_RUN_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .expect(
            "CARRICK_RUN_ID must be set: scripts/test-signed.sh exports it so \
             scripts/sudo/kill.sh can reap this run's guests",
        )
}
