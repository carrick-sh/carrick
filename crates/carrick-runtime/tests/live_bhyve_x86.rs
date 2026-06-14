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

#[test]
fn threads_run_to_zero_via_sibling_vcpus() {
    // The multithreaded acceptance (M2 Tier 2): a guest that
    // `clone(CLONE_THREAD)`s sibling threads — each running on its own bhyve
    // sibling vCPU on the SHARED VM — with TLS and a futex-backed join, then
    // exits 0. Success here proves `materialize_sibling` fully programs a fresh
    // (real-mode) sibling vCPU for long mode and runs it into the child's
    // post-clone ring-3 context.
    let Some(path) = fixture("CARRICK_BHYVE_THREADS") else {
        eprintln!("skip: set CARRICK_BHYVE_THREADS to the threads ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "multithreaded guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("threads ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn fork_wait4_runs_to_zero() {
    // The fork(2) acceptance (SP1): a guest that `fork`s, the child `_exit(7)`s,
    // and the parent `wait4`s + verifies WEXITSTATUS==7, then exits 0. Success
    // here proves `BhyveTrapEngine::fork()` eagerly copies the parent guest RAM
    // into a fresh child VM, long-mode-programs child vCPU 0 at the post-fork
    // resume, and the child VM is destroyed on `_exit` (process_exit_cleanup,
    // no /dev/vmm leak). wait4 reuses the shared wait_proc_exit.
    let Some(path) = fixture("CARRICK_BHYVE_FORK") else {
        eprintln!("skip: set CARRICK_BHYVE_FORK to the fork ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "fork+wait4 guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("fork ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn fork_raw_runs_to_zero() {
    // The fork(2) BISECTION regression (SP1): a guest that forks via the RAW
    // `SYS_fork` syscall (NOT musl's fork() wrapper), the child `_exit(7)`s
    // immediately (no wait4, no musl child-side cleanup), and the parent wait4s +
    // verifies WEXITSTATUS==7, exiting 0. This isolates carrick's child
    // syscall-return-register delivery from musl's fork() wrapper: it stays GREEN
    // even if the wrapper-driven `fork_wait4_runs_to_zero` regresses, pinning
    // "the child sees fork()→0 in RAX" independent of libc.
    let Some(path) = fixture("CARRICK_BHYVE_FORK_RAW") else {
        eprintln!("skip: set CARRICK_BHYVE_FORK_RAW to the raw-fork ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "raw fork+wait4 guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn execve_runs_second_image() {
    // The execve(2) acceptance (SP2): the CALLER fixture (`CARRICK_BHYVE_EXECVE`)
    // `execve`s the deployed `execd` TARGET, which prints `execd ok` + exit 0.
    // Success here proves `BhyveTrapEngine::execve_into` rebuilt a fresh OWNED VM
    // from the second image (bring_up_x86_elf), swapped it in, tore down the old
    // image, and resumed at the new entry — with NO /dev/vmm leak.
    //
    // PATH RESOLUTION: the caller execve's the ABSOLUTE deployed host path of
    // execd (baked default `/root/fixtures/execd`). `load_execve_image` resolves
    // it overlay-first, then via the host-fs fallback (`std::fs::read`), which is
    // ON for the bare run-elf dispatcher — so the deployed execd is found.
    let Some(path) = fixture("CARRICK_BHYVE_EXECVE") else {
        eprintln!("skip: set CARRICK_BHYVE_EXECVE to the execve-caller ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
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
