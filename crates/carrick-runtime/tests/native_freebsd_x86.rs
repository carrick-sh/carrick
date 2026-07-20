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
fn native_backend_enters_dynamic_interpreter_with_linux_auxv() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/dynamic-main-x86_64-linux"
    );
    let interpreter = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/dynamic-interpreter-x86_64-linux"
    );
    let root = tempfile::tempdir().expect("dynamic fixture root");
    std::fs::create_dir(root.path().join("lib")).expect("fixture lib directory");
    std::fs::copy(
        interpreter,
        root.path().join("lib/carrick-dynamic-interpreter"),
    )
    .expect("install fixture interpreter");
    let prior_root = std::env::var_os("CARRICK_NATIVE_ROOTFS");
    // SAFETY: this integration binary's native runs are process-serialized by
    // the backend; the temporary root remains alive until the run returns.
    unsafe { std::env::set_var("CARRICK_NATIVE_ROOTFS", root.path()) };
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref());
    match prior_root {
        Some(value) => unsafe { std::env::set_var("CARRICK_NATIVE_ROOTFS", value) },
        None => unsafe { std::env::remove_var("CARRICK_NATIVE_ROOTFS") },
    }
    let result = result.expect("native x86 dynamic ELF must enter PT_INTERP");

    assert_eq!(result.exit_code, 23, "interpreter validated the entry auxv");
    assert_eq!(result.stdout, b"dynamic-elf ok\n");
}

#[test]
fn sibling_exit_group_interrupts_indefinite_private_and_shared_futex_waits() {
    let fixtures = [
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-futex-x86_64-linux"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-shared-futex-x86_64-linux"
        ),
    ];

    for fixture in fixtures {
        assert!(
            std::path::Path::new(fixture).exists(),
            "fixture missing: {fixture}"
        );
        let start = std::time::Instant::now();
        let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
            .expect("a sibling exit_group must release the initial futex waiter");

        assert_eq!(
            result.exit_code, 37,
            "the sibling's process-wide exit status must win for {fixture}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "exit_group must not wait for {fixture}'s infinite futex park"
        );
    }
}

#[test]
fn immediate_child_exit_group_does_not_deadlock_clone_publication() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-immediate-x86_64-linux"
    );
    for iteration in 0..16 {
        let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
            .expect("an immediate child exit_group must not join its waiting parent");
        assert_eq!(
            result.exit_code, 37,
            "child exit status on iteration {iteration}"
        );
    }
}

#[test]
fn exit_group_asynchronously_kicks_a_sibling_spinning_in_jit_code() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/exitgroup-sibling-busy-x86_64-linux"
    );
    let start = std::time::Instant::now();
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("exit_group must kick a sibling with no syscall boundary");

    assert_eq!(result.exit_code, 0);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "a chained JIT spin must not hide process exit"
    );
}

#[test]
fn native_identity_syscalls_chain_without_rust_traps() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/identity-loop-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("identity loop must run natively");

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.traps, 1,
        "1000 getpid + 1000 gettid calls must stay in JIT; only exit_group traps"
    );
}

#[test]
fn native_identity_fast_path_disables_live_for_seccomp() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-dsr-x86/tests/fixtures/identity-seccomp-x86_64-linux"
    );
    let result = carrick_runtime::runtime::run_elf_native_dispatch(fixture.as_ref())
        .expect("allow-all seccomp identity fixture must run");

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.traps, 23,
        "prctl + seccomp + 20 identity calls + exit_group must all dispatch"
    );
}

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
