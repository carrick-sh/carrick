//! M2-runtime proof: a static x86_64 Linux ELF runs natively on FreeBSD/amd64
//! through the REAL `SyscallDispatcher` (the same dispatcher the bhyve/KVM x86
//! VMM lanes feed) — NO VMM.
//!
//! Unlike the `carrick-dsr-x86` in-crate tests (which service syscalls with a
//! throwaway in-test servicer), this drives the production
//! `runtime::run_elf_native_dispatch` entry: it builds the real dispatcher
//! (`make_linux_dispatcher`), loads the ELF via `native_freebsd`, translates
//! it through the gateway, and routes `write`/`exit_group` through the real
//! dispatcher. The guest's stdout is captured in the dispatcher's buffer and
//! surfaced in `RunResult.stdout`. The guest is the checked-in no_std
//! static-pie fixture (source
//! `crates/carrick-dsr-x86/tests/fixtures/tinyguest.rs`).
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

#[test]
fn native_backend_runs_a_static_x86_elf_through_the_real_dispatcher() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
    );
    assert!(
        std::path::Path::new(fixture).exists(),
        "fixture missing: {fixture}"
    );

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("native x86 run must succeed");

    assert_eq!(
        result.exit_code, 21,
        "exit_group(0+1+..+6) must round-trip the real dispatcher"
    );
    assert_eq!(
        result.stdout, b"native-elf ok\n",
        "the guest's write(1, ...) must be serviced by the real dispatcher"
    );
}
