//! M1 live acceptance (NetBSD/NVMM, runs on VM 201 as root).
//!
//! Boots a static-musl x86_64 Linux ELF through `run_elf_nvmm` — the thin M1
//! wrapper over the SHARED `carrick_x86::X86EngineCore<NvmmVmm>` + the shared
//! `run_elf_service_loop` — and asserts the guest prints "hello, x86_64 world"
//! and exits 0. This is the portability Stage-5 BINDING acceptance test: a real
//! x86-64 Linux ELF runs to "hello" on NVMM through the thin per-VMM trait pair
//! over the shared engine (zero copy from carrick-bhyve).
//!
//! The fixture is a static-musl x86_64 ELF provided by absolute path via env
//! (cross-built off-box; the NetBSD box has no musl cross-target):
//!   * `CARRICK_NVMM_FIXTURE` → hello (`crates/carrick-bhyve/fixtures/hello-x86_64`)
//!
//! Run on VM 201 (root, for `/dev/nvmm`; `modload nvmm` if ENXIO):
//! ```
//! CARRICK_NVMM_FIXTURE=/root/fixtures/hello \
//!   cargo test -p carrick-vmm-nvmm --test live_nvmm_x86 -- --nocapture
//! ```
#![cfg(target_os = "netbsd")]
#![allow(clippy::expect_used)]

use std::io::Read as _;
use std::os::fd::FromRawFd as _;
use std::path::PathBuf;

/// Resolve an env-provided fixture path; `None` (skip) if unset/absent so the
/// suite is a no-op on a box without the fixture staged.
fn fixture(env: &str) -> Option<PathBuf> {
    std::env::var_os(env)
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

/// Run `f` with host fd 1 (stdout) redirected to a pipe; return what was written.
/// The service loop writes guest stdout via `write(2)` on host fd 1, so we
/// capture it by temporarily dup'ing a pipe over fd 1.
fn capture_stdout<R>(f: impl FnOnce() -> R) -> (R, Vec<u8>) {
    // SAFETY: standard pipe + dup/dup2 fd plumbing, each result checked.
    unsafe {
        let mut fds = [0i32; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0, "pipe");
        let (rd, wr) = (fds[0], fds[1]);
        let saved = libc::dup(1);
        assert!(saved >= 0, "dup(1)");
        assert!(libc::dup2(wr, 1) >= 0, "dup2(wr,1)");
        libc::close(wr);

        let out = f();

        libc::fflush(std::ptr::null_mut()); // flush libc stdio if any
        assert!(libc::dup2(saved, 1) >= 0, "restore fd 1");
        libc::close(saved);

        let mut buf = Vec::new();
        let mut reader = std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(rd));
        let _ = reader.read_to_end(&mut buf);
        (out, buf)
    }
}

#[test]
fn hello_runs_to_zero() {
    let Some(path) = fixture("CARRICK_NVMM_FIXTURE") else {
        eprintln!("skip: set CARRICK_NVMM_FIXTURE to a static x86_64 ELF");
        return;
    };

    let (result, stdout) = capture_stdout(|| carrick_vmm_nvmm::run_elf_nvmm(&path));
    let exit = result.expect("run_elf_nvmm failed");
    let out = String::from_utf8_lossy(&stdout);

    assert_eq!(exit, 0, "hello must exit 0 (stdout: {out:?})");
    assert!(
        out.contains("hello, x86_64 world"),
        "guest must print the hello marker; stdout: {out:?}"
    );
}
