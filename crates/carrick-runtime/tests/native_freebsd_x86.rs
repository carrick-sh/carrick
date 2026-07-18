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

/// Direct-branch chaining, proven end-to-end: a `#![no_std]` guest runs a
/// 50-million-iteration PURE compute loop (no syscall inside the loop, only a
/// final `exit_group`) — source `crates/carrick-dsr-x86/tests/fixtures/
/// computeloop.rs`. Two assertions together prove chaining:
///
/// - `traps == 1`: the ONLY syscall is the final exit. The loop's conditional
///   back-edge executed natively in the JIT cache every iteration; without
///   chaining each of the 50M iterations would round-trip to Rust (and the
///   test would run for many seconds).
/// - `exit_code == 192`: the low byte of `sum(3*i + 1 for i in 0..50_000_000)`
///   — the loop's control flow, register state, and flags stayed correct
///   across the entire chain.
#[test]
fn direct_branch_chaining_runs_a_compute_loop_without_round_trips() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/computeloop-x86_64-linux"
    );
    if !std::path::Path::new(fixture).exists() {
        eprintln!("skipping: compute-loop fixture not present ({fixture})");
        return;
    }

    let start = std::time::Instant::now();
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("chained compute loop must run to completion");
    let elapsed = start.elapsed();

    assert_eq!(
        result.traps, 1,
        "a chained 50M-iteration loop makes ONE syscall (the final exit); \
         traps={} means the back-edge round-tripped to Rust",
        result.traps
    );
    assert_eq!(
        result.exit_code, 192,
        "sum(3i+1, i in 0..50M) mod 256 == 192 — chaining preserved the loop's result"
    );
    // Not a hard perf gate (CI variance), but a chained 50M-iteration loop is
    // sub-second here; unchained it is minutes. Flag a gross regression.
    assert!(
        elapsed.as_secs() < 20,
        "chained compute loop took {elapsed:?} — chaining likely broke"
    );
}

/// A REAL std Rust binary runs to completion natively: a `Vec` of computed
/// squares, iterators, and `println!` formatting (Debug of the Vec + a sum),
/// through the real dispatcher — source
/// `crates/carrick-dsr-x86/tests/fixtures/hello_std.rs`. Exercises full musl +
/// std startup (TLS via arch_prctl, signal/sigaltstack setup, brk/mmap heap,
/// RIP-relative rodata, PLT/indirect calls, a page-spanning instruction) and
/// the buffered-stdout write path. This is the "Rust ecosystem runs natively"
/// end-to-end proof.
#[test]
fn native_backend_runs_a_real_std_rust_binary() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/hello-std-x86_64-linux"
    );
    if !std::path::Path::new(fixture).exists() {
        eprintln!("skipping: std Rust fixture not present ({fixture})");
        return;
    }

    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("std Rust binary must run to completion natively");

    // exit(sum(n^2, n in 1..=10) % 256) = 385 % 256 = 129.
    assert_eq!(
        result.exit_code,
        129,
        "std Rust exit = 385 % 256 = 129; stdout was {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("squares=[1, 4, 9, 16, 25, 36, 49, 64, 81, 100]") && out.contains("sum=385"),
        "std Rust println! formatting must work through the dispatcher; got {out:?}"
    );
}
