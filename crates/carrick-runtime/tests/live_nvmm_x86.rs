//! Live NVMM threaded-loop acceptance (NetBSD/x86_64 + real `/dev/nvmm`; run as
//! root). Drives `carrick_runtime::runtime::run_elf_nvmm_dispatch` over the
//! canonical `SyscallDispatcher` loop, proving an x86_64 Linux guest runs on
//! NVMM through the full runtime dispatcher rather than the standalone M1
//! startup loop.
//!
//! Fixtures are static-musl x86_64 ELFs provided by absolute path via env
//! (cross-built off-box; the NetBSD box has no musl cross-target):
//!   * `CARRICK_NVMM_FIXTURE` -> hello-world
//!   * `CARRICK_NVMM_FORK_RAW` -> raw fork + wait4 bisection fixture
//!   * `CARRICK_NVMM_EXECVE` -> execve caller fixture
//!   * `CARRICK_NVMM_SIGSEGV` -> handled null-store SIGSEGV fixture
//!   * `CARRICK_NVMM_SIGSEGV_DEFAULT` -> default-action null-store SIGSEGV fixture
//!
//! Run on the NetBSD box (root, for `/dev/nvmm`):
//! ```
//! CARRICK_NVMM_FIXTURE=/root/fixtures/hello \
//! CARRICK_NVMM_FORK_RAW=/root/fixtures/fork-raw \
//! CARRICK_NVMM_EXECVE=/root/fixtures/execve \
//! CARRICK_NVMM_SIGSEGV=/root/fixtures/nvmm-sigsegv \
//! CARRICK_NVMM_SIGSEGV_DEFAULT=/root/fixtures/nvmm-sigsegv-default \
//!   cargo test -p carrick-runtime --no-default-features --features platform-netbsd \
//!   --test live_nvmm_x86 -- --nocapture
//! ```
#![cfg(all(
    target_os = "netbsd",
    target_arch = "x86_64",
    feature = "platform-netbsd"
))]
// Integration tests legitimately fail fast on missing test infra.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

/// Resolve an env-provided fixture path, returning `None` (skip) if unset or
/// absent so the suite is a no-op on a box without staged fixtures.
fn fixture(env: &str) -> Option<PathBuf> {
    std::env::var_os(env)
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

#[test]
fn hello_runs_to_zero_via_threaded_loop() {
    let Some(path) = fixture("CARRICK_NVMM_FIXTURE") else {
        eprintln!("skip: set CARRICK_NVMM_FIXTURE to a static x86_64 ELF");
        return;
    };
    let result =
        carrick_runtime::runtime::run_elf_nvmm_dispatch(&path).expect("dispatch run failed");
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
fn fork_raw_runs_to_zero() {
    // The fork(2) bisection regression: a guest that forks via the raw x86_64
    // syscall, the child `_exit(7)`s immediately, and the parent wait4s +
    // verifies WEXITSTATUS==7. This isolates the NVMM child-side machine/vCPU
    // rebuild from musl's fork wrapper.
    let Some(path) = fixture("CARRICK_NVMM_FORK_RAW") else {
        eprintln!("skip: set CARRICK_NVMM_FORK_RAW to the raw-fork ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_nvmm_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "raw fork+wait4 guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn execve_runs_second_image() {
    // The execve(2) acceptance: the caller fixture execve's the deployed
    // `/root/fixtures/execd` target, which prints `execd ok` and exits 0.
    // This is the focused tripwire for the NVMM backend's `execve_rebuild`
    // hook, which the OCI conformance `go-build` smoke reaches through `/bin/sh`.
    let Some(path) = fixture("CARRICK_NVMM_EXECVE") else {
        eprintln!("skip: set CARRICK_NVMM_EXECVE to the execve-caller ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_nvmm_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "execve target must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("execd ok"),
        "the execve'd second image must print 'execd ok'; stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn handled_sigsegv_receives_linux_siginfo() {
    // The synchronous-fault acceptance: the guest installs a SA_SIGINFO
    // SIGSEGV handler, performs a null store, and exits 0 only when Linux-shaped
    // siginfo reports SIGSEGV/SEGV_MAPERR with si_addr == NULL.
    let Some(path) = fixture("CARRICK_NVMM_SIGSEGV") else {
        eprintln!("skip: set CARRICK_NVMM_SIGSEGV to the handled SIGSEGV ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_nvmm_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "handled SIGSEGV fixture must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("sigsegv-ok"),
        "handled SIGSEGV fixture must print sigsegv-ok; stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn default_sigsegv_action_exits_139() {
    // Same null-store fault with SIG_DFL left in place. The runtime should
    // apply Linux's default SIGSEGV termination status.
    let Some(path) = fixture("CARRICK_NVMM_SIGSEGV_DEFAULT") else {
        eprintln!("skip: set CARRICK_NVMM_SIGSEGV_DEFAULT to the default SIGSEGV ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_nvmm_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        139,
        "default SIGSEGV fixture must terminate as 128+SIGSEGV (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
}
