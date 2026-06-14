//! Live bhyve threaded-loop acceptance (FreeBSD/x86_64 + real `/dev/vmm`; run as
//! root). Drives `carrick_runtime::runtime::run_elf_bhyve_dispatch` over the canonical
//! `SyscallDispatcher` loop (`run_threaded_bhyve_loop`), proving an x86_64 Linux
//! guest runs on bhyve through the FULL ~209-handler dispatcher — not the M1
//! hand-rolled ~15-syscall loop.
//!
//! Fixtures are static-musl x86_64 ELFs provided by absolute path via env
//! (cross-built off-box; the FreeBSD box has no musl cross-target):
//!   * `CARRICK_BHYVE_FIXTURE` → a hello-world (`crates/carrick-bhyve/fixtures/hello-x86_64`)
//!   * `CARRICK_BHYVE_FSPROBE` → the `uname(2)` differential (`crates/carrick-linux/fixtures/x86-fsprobe`)
//!
//! Run on the FreeBSD box (root, for `/dev/vmm`):
//! ```
//! CARRICK_BHYVE_FIXTURE=/root/fixtures/hello \
//! CARRICK_BHYVE_FSPROBE=/root/fixtures/fsprobe \
//!   cargo test -p carrick-runtime --no-default-features --features platform-freebsd \
//!   --test live_bhyve_x86 -- --nocapture
//! ```
#![cfg(all(
    target_os = "freebsd",
    target_arch = "x86_64",
    feature = "platform-freebsd"
))]
// Integration tests legitimately fail fast on missing test-infra.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

/// Resolve an env-provided fixture path, returning `None` (skip) if unset or
/// the file is absent — so the suite is a no-op on a box without the fixtures
/// staged, rather than a hard failure.
fn fixture(env: &str) -> Option<PathBuf> {
    std::env::var_os(env)
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

#[test]
fn hello_runs_to_zero_via_threaded_loop() {
    let Some(path) = fixture("CARRICK_BHYVE_FIXTURE") else {
        eprintln!("skip: set CARRICK_BHYVE_FIXTURE to a static x86_64 ELF");
        return;
    };
    let result =
        carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run failed");
    assert_eq!(
        result.exit_code,
        0,
        "hello must exit 0 via the threaded loop (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("hello, x86_64 world"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn fsprobe_uname_runs_to_zero_via_dispatcher() {
    // The `uname(2)` (canonical syscall 160) differential: the M1 standalone
    // ~15-syscall `run_elf_bhyve` returns -ENOSYS for it, but the full
    // SyscallDispatcher services it. Success here is the proof that the bhyve
    // guest reached the real dispatcher on the canonical loop.
    let Some(path) = fixture("CARRICK_BHYVE_FSPROBE") else {
        eprintln!("skip: set CARRICK_BHYVE_FSPROBE to the x86-fsprobe ELF");
        return;
    };
    let result =
        carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run failed");
    assert_eq!(
        result.exit_code,
        0,
        "fsprobe (uname) must exit 0 via the dispatcher (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("uname.sysname=Linux"),
        "the dispatcher must report sysname=Linux; stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}
