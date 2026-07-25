//! ACCEPTANCE: a real static x86_64 Linux ELF runs natively on NetBSD/amd64
//! through the production `runtime::run_elf_native_dispatch` entry — the same
//! DSR gateway + `SyscallDispatcher` the FreeBSD native lane drives, with NO
//! VMM. This is the acceptance moment of the NetBSD native-lane campaign: the
//! first real guest execution on NetBSD 10.x.
//!
//! It is deliberately FOCUSED — it exercises only the simplest fixtures, in
//! escalating order of syscall surface, and asserts the same `RunResult`
//! contract (`exit_code` / `stdout` / `traps`) the FreeBSD suite asserts. The
//! broader fixture corpus (xstate/AVX512/pkru/fork/signal edge cases) is the
//! NetBSD red-list worklist tracked in `docs/netbsd-native-lane-evidence.md`,
//! not gated here.
//!
//! ## BLOCKED (2026-07-24): userspace FSGSBASE is unavailable on NetBSD 10.1
//!
//! Every test below is `#[ignore]`d because NONE of them currently reach a
//! single guest instruction: the SHARED `carrick-dsr-x86` gateway trampoline
//! (`gateway_x86_64.S`) swaps the hardware FS base with `rdfsbase`/`wrfsbase`
//! (offsets 56/58/273). NetBSD 10.1/amd64 does NOT enable `CR4.FSGSBASE` for
//! ring-3 (no sysctl toggle exists), so `rdfsbase %rcx` in the enter prologue
//! (`carrick_dsr_x86_enter_raw+59`) raises `#UD` → SIGILL and terminates the
//! host process before the guest runs. The CPU advertises FSGSBASE
//! (`CPUID.07H:EBX.FSGSBASE=1`); the kernel simply gates the ring-3 CR4 bit.
//!
//! This is a shared-seam gap, not a NetBSD-lane-glue bug: the gateway assembly
//! bakes in a FreeBSD/Linux CPU-feature assumption. The follow-on (see
//! `docs/netbsd-native-lane-evidence.md`) is a host-abstracted fsbase-swap seam
//! (NetBSD: `sysarch(X86_64_GET_FSBASE/SET_FSBASE)`). REMOVE the `#[ignore]`s
//! once that lands: these tests are the ready acceptance ladder.
//!
//! Run ONLY this file on the box (the inline `mod tests` in the FreeBSD-shaped
//! sources is a separate, pre-existing red-list item):
//!   cargo test -p carrick-runtime --no-default-features \
//!     --features platform-netbsd --test native_netbsd_x86 -- --test-threads=1
#![cfg(all(target_os = "netbsd", target_arch = "x86_64"))]

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../carrick-dsr-x86/tests/fixtures")
        .join(name)
}

/// Step 1a — the SMALLEST smoke test: a ~2KB static-pie no_std guest that
/// writes one line and `exit_group(0+1+..+6)`. If this exits correctly, the
/// NetBSD native run loop (ELF load → DSR translation → JIT execute → real
/// dispatcher servicing `write`/`exit_group`) is live end-to-end.
#[test]
#[ignore = "blocked: NetBSD 10.1 has no ring-3 FSGSBASE; gateway rdfsbase/wrfsbase SIGILLs — see docs/netbsd-native-lane-evidence.md"]
fn tinyguest_runs_natively_through_the_real_dispatcher() {
    let path = fixture("tinyguest-x86_64-linux");
    assert!(path.exists(), "fixture missing: {}", path.display());

    let result = carrick_runtime::runtime::run_elf_native_dispatch(&path)
        .expect("native x86 tinyguest must run on NetBSD");

    assert_eq!(
        result.exit_code, 21,
        "exit_group(0+1+..+6) must round-trip the real dispatcher"
    );
    assert_eq!(
        result.stdout, b"native-elf ok\n",
        "the guest's write(1, ...) must be serviced by the real dispatcher"
    );
}

/// Step 1b — simple compute + identity syscalls that must stay in the JIT
/// cache: 1000 getpid + 1000 gettid calls chain natively, only the final
/// `exit_group` traps to Rust.
#[test]
#[ignore = "blocked: NetBSD 10.1 has no ring-3 FSGSBASE; gateway rdfsbase/wrfsbase SIGILLs — see docs/netbsd-native-lane-evidence.md"]
fn identity_loop_chains_without_rust_traps() {
    let path = fixture("identity-loop-x86_64-linux");
    assert!(path.exists(), "fixture missing: {}", path.display());

    let result = carrick_runtime::runtime::run_elf_native_dispatch(&path)
        .expect("identity loop must run natively on NetBSD");

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        result.traps, 1,
        "1000 getpid + 1000 gettid must stay in JIT; only exit_group traps"
    );
}

/// Step 1b (cont.) — direct-branch chaining across a 50M-iteration PURE compute
/// loop. `traps == 1` proves the conditional back-edge executed natively every
/// iteration (no per-iteration round trip to Rust); `exit_code == 192` proves
/// the loop's control flow, registers, and flags stayed correct across the
/// whole chain.
#[test]
#[ignore = "blocked: NetBSD 10.1 has no ring-3 FSGSBASE; gateway rdfsbase/wrfsbase SIGILLs — see docs/netbsd-native-lane-evidence.md"]
fn compute_loop_chains_direct_branches() {
    let path = fixture("computeloop-x86_64-linux");
    if !path.exists() {
        eprintln!(
            "skipping: compute-loop fixture not present ({})",
            path.display()
        );
        return;
    }

    let start = std::time::Instant::now();
    let result = carrick_runtime::runtime::run_elf_native_dispatch(&path)
        .expect("chained compute loop must run to completion on NetBSD");
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
    assert!(
        elapsed.as_secs() < 20,
        "chained compute loop took {elapsed:?} — chaining likely broke"
    );
}

/// Step 1c — the "Rust ecosystem runs natively" end-to-end proof: a REAL std
/// Rust binary (Vec of computed squares, iterators, `println!` formatting)
/// runs to completion. Exercises full musl + std startup (TLS via arch_prctl,
/// signal/sigaltstack setup, brk/mmap heap, RIP-relative rodata, PLT/indirect
/// calls, a page-spanning instruction) and the buffered-stdout write path.
#[test]
#[ignore = "blocked: NetBSD 10.1 has no ring-3 FSGSBASE; gateway rdfsbase/wrfsbase SIGILLs — see docs/netbsd-native-lane-evidence.md"]
fn hello_std_rust_binary_runs_natively() {
    let path = fixture("hello-std-x86_64-linux");
    if !path.exists() {
        eprintln!(
            "skipping: std Rust fixture not present ({})",
            path.display()
        );
        return;
    }

    let result = carrick_runtime::runtime::run_elf_native_dispatch(&path)
        .expect("std Rust binary must run to completion natively on NetBSD");

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
