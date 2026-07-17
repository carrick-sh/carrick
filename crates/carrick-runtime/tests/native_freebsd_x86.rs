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

/// A REAL static-pie musl conformance probe runs to completion natively: full
/// musl startup (TLS via arch_prctl, PLT indirect calls, RIP-relative rodata),
/// a `brk`-grown heap backed by the reserved guest arena, its output written,
/// and a clean exit — all through the real dispatcher. `brkheapgrow` is chosen
/// because it exercises the brk/heap arena backing and exits 0 deterministically.
///
/// Skips (does not fail) when the prebuilt probe is absent — the probe corpus
/// is a build artifact under `conformance-probes/target`, present on the
/// FreeBSD rig but not guaranteed elsewhere.
#[test]
fn native_backend_runs_a_real_musl_probe_with_a_grown_heap() {
    let probe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance-probes/target/x86_64-unknown-linux-musl/release/brkheapgrow"
    );
    if !std::path::Path::new(probe).exists() {
        eprintln!("skipping: prebuilt musl probe not present ({probe})");
        return;
    }

    let result = carrick_runtime::runtime::run_elf_native_dispatch(probe.as_ref())
        .expect("real musl probe must run to completion natively");

    assert_eq!(
        result.exit_code,
        0,
        "brkheapgrow exits 0; stdout was {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("brk_initial_nonzero=true") && out.contains("brk_grow_32mib=true"),
        "musl brk/heap must work through the real dispatcher; got {out:?}"
    );
}
