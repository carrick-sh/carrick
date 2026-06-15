//! Live bhyve threaded-loop acceptance (FreeBSD/x86_64 + real `/dev/vmm`; run as
//! root). Drives `carrick_runtime::runtime::run_elf_bhyve_dispatch` over the canonical
//! `SyscallDispatcher` loop (`run_threaded_bhyve_loop`), proving an x86_64 Linux
//! guest runs on bhyve through the FULL ~209-handler dispatcher — not the M1
//! hand-rolled ~15-syscall loop.
//!
//! Fixtures are static-musl x86_64 ELFs provided by absolute path via env
//! (cross-built off-box; the FreeBSD box has no musl cross-target):
//!   * `CARRICK_BHYVE_FIXTURE` → a hello-world (`crates/carrick-vmm-bhyve/fixtures/hello-x86_64`)
//!   * `CARRICK_BHYVE_FSPROBE` → the `uname(2)` differential (`crates/carrick-vmm-kvm/fixtures/x86-fsprobe`)
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
    // here proves `BhyveVmm::freeze_ram()` eagerly copies the parent guest RAM
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
    // Success here proves `BhyveVmm::execve_rebuild` rebuilt a fresh OWNED VM
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

#[test]
fn vfork_exit_runs_to_zero() {
    // The vfork(2)-without-exec acceptance (SP2): the guest `vfork`s (raw
    // SYS_vfork), the child `_exit(9)`s immediately, and the parent — released
    // when the child's exit closes the vfork suspend pipe (EOF) — `wait4`s and
    // verifies WEXITSTATUS==9, then exits 0. Success here proves bhyve's vfork
    // works through the trait DEFAULT `fork_vfork() → self.fork()` (a fork-COPY:
    // the child gets its OWN fresh VM via SP1, exactly like the `fork` test) plus
    // the generic loop's vfork-pipe parent-suspend. There is NO shared bhyve VM;
    // true cross-process CLONE_VM was proven infeasible (see the design spec).
    let Some(path) = fixture("CARRICK_BHYVE_VFORK_EXIT") else {
        eprintln!("skip: set CARRICK_BHYVE_VFORK_EXIT to the vfork-exit ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "vfork+_exit guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("vfork-exit ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn vfork_exec_runs_to_zero() {
    // The vfork(2)+execve(2) acceptance (SP2) — the DOMINANT vfork pattern. The
    // guest `vfork`s (raw SYS_vfork), the child immediately `execve`s the
    // deployed `execd` target (prints `execd ok` + exit 0), and the parent —
    // released the moment the child's execve succeeds (the loop writes the vfork
    // pipe in handle_execve) — `wait4`s and verifies WEXITSTATUS==0, then prints
    // `vfork-exec ok` + exits 0. Success here exercises the whole vfork+exec
    // path on bhyve: the trait-default `fork_vfork() → self.fork()` fork-COPY
    // child runs its OWN fresh VM, hits execve → `execve_into` rebuilds a fresh
    // VM AND releases the suspended parent → the parent resumes + reaps 0. There
    // is NO shared bhyve VM (cross-process CLONE_VM was proven infeasible).
    let Some(path) = fixture("CARRICK_BHYVE_VFORK_EXEC") else {
        eprintln!("skip: set CARRICK_BHYVE_VFORK_EXEC to the vfork-exec ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "vfork+execve guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("vfork-exec ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn signal_handler_runs_to_zero() {
    // The intra-process signal acceptance (SP3.1): the guest installs a
    // SA_SIGINFO SIGUSR1 handler, `raise`s it, runs the handler (correct
    // si_signo), returns through the libc restorer → rt_sigreturn, and RESUMES
    // here — exiting 0. Success proves the shared x86 signal-inject path wrote a
    // valid x86 rt_sigframe (GPR/RIP/RSP/siginfo/ucontext) via the shared
    // builder and `restore_from_sigframe` restored the pre-signal state.
    let Some(path) = fixture("CARRICK_BHYVE_SIGNAL") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGNAL to the signal ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "signal guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("signal-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn sigsegv_handler_receives_fault_siginfo() {
    // SP4.4 first fault-signal acceptance: a guest null store must become a
    // Linux SIGSEGV/SEGV_MAPERR with si_addr=0, delivered to an SA_SIGINFO
    // handler via the shared x86 sigframe path.
    let Some(path) = fixture("CARRICK_BHYVE_SIGSEGV") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGSEGV to the sigsegv ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "sigsegv guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("sigsegv-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn sigsegv_default_action_terminates_with_139() {
    // SP4.4 default-action acceptance: a guest null store with no installed
    // handler must take Linux's default SIGSEGV action and surface as exit 139.
    let Some(path) = fixture("CARRICK_BHYVE_SIGSEGV_DEFAULT") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGSEGV_DEFAULT to the sigsegv-default ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        139,
        "unhandled sigsegv guest must exit 139 (stdout: {:?}, stderr: {:?})",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn sigsegv_accerr_handler_receives_protection_siginfo() {
    // SP4.4 ACCERR acceptance: a write to a present read-only mapping must be
    // delivered as SIGSEGV/SEGV_ACCERR, not the null-page SEGV_MAPERR case.
    let Some(path) = fixture("CARRICK_BHYVE_SIGSEGV_ACCERR") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGSEGV_ACCERR to the sigsegv-accerr ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "sigsegv-accerr guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("sigsegv-accerr-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn sigill_handler_receives_ud2_siginfo() {
    // SP4.4 non-#PF oracle: Docker linux/amd64 reports UD2 as
    // SIGILL/ILL_ILLOPN with si_addr equal to the faulting instruction RIP.
    let Some(path) = fixture("CARRICK_BHYVE_SIGILL") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGILL to the sigill ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "sigill guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("sigill-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn sigfpe_handler_receives_divide_error_siginfo() {
    // SP4.4 non-#PF oracle: Docker linux/amd64 reports integer divide-by-zero as
    // SIGFPE/FPE_INTDIV with si_addr equal to the faulting instruction RIP.
    let Some(path) = fixture("CARRICK_BHYVE_SIGFPE") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGFPE to the sigfpe ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "sigfpe guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("sigfpe-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn sigsegv_gp_handler_receives_linux_siginfo() {
    // SP4.4 non-#PF oracle: Docker linux/amd64 reports a user-mode privileged
    // instruction (#GP via CLI) as SIGSEGV/SI_KERNEL with si_addr == NULL.
    let Some(path) = fixture("CARRICK_BHYVE_SIGSEGV_GP") else {
        eprintln!("skip: set CARRICK_BHYVE_SIGSEGV_GP to the sigsegv-gp ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "sigsegv-gp guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("sigsegv-gp-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn async_signal_interrupts_tight_loop() {
    // SP4.1: a guest spins in a tight ALU loop with NO syscalls while a SIBLING
    // guest thread tgkills it. The signal must interrupt the running vCPU at an
    // ARBITRARY ring-3 PC (kick -> Ok(None) -> deliver at interrupted_pc), run
    // the handler, rt_sigreturn, and resume the loop -> exit 0. Proves async
    // host->guest delivery (vs SP3's syscall-boundary delivery).
    let Some(path) = fixture("CARRICK_BHYVE_ASYNCSIG") else {
        eprintln!("skip: set CARRICK_BHYVE_ASYNCSIG to the asyncsig ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "async-signal guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("asyncsig-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn cross_process_kill_delivers_with_sender_pid() {
    // SP4.2: a guest parent forks a child; the child installs an SA_SIGINFO SIGUSR1
    // handler and pauses; the parent kill(child, SIGUSR1)s it. The handler must run
    // with si_signo==SIGUSR1 AND si_pid == the parent's (ns-)pid, proving the
    // cross-process host-kill path carries the correct sender identity. Exercises
    // the FreeBSD linux<->host signum table (Linux SIGUSR1 10 -> FreeBSD 30), the
    // mirrored host routed handler, and the signal pump turning the host signal
    // into a guest-delivered SIGUSR1. RED before the bhyve cross-process host layer
    // (no-op nudge/disposition/pump + identity signum table).
    let Some(path) = fixture("CARRICK_BHYVE_CROSSSIG") else {
        eprintln!("skip: set CARRICK_BHYVE_CROSSSIG to the crosssig ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "cross-process kill guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    // The forked CHILD's "crosssig-ok" marker writes to the raw terminal fd 1 (a
    // separate guest process — captured-stdout gotcha), so we assert on the PARENT's
    // marker. The parent only prints "crosssig-parent-ok" + exits 0 if its wait4 saw
    // the child exit 0, which the child does ONLY after its handler validated
    // si_signo == SIGUSR1 AND si_pid == the parent's pid (else it _exit(15|16)s and
    // the parent dies with "crosssig-child-nonzero"). So this is the full proof.
    let out = String::from_utf8_lossy(&result.stdout);
    assert!(
        out.contains("crosssig-parent-ok"),
        "parent must wait4 the cross-process-signalled child to exit 0; stdout: {out:?}, stderr: {:?}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn cross_process_kill_sigusr2_delivers_with_sender_pid() {
    // SP4.2: a SECOND host-kill cross-process proof on a DIFFERENT signum-table
    // entry than the SIGUSR1 test. A guest parent forks a child that installs an
    // SA_SIGINFO SIGUSR2 handler + waits; the parent kill(child, SIGUSR2)s it. The
    // handler must run with si_signo == SIGUSR2 AND si_pid == the parent's pid.
    // SIGUSR2 is Linux 12 -> FreeBSD 31 (vs SIGUSR1 Linux 10 -> FreeBSD 30), so a
    // one-off mistranslation of the FreeBSD linux<->host signum table that a single
    // signal would miss is caught here. Same mechanism as the SIGUSR1 test: the
    // mirrored host routed handler + the signal pump.
    let Some(path) = fixture("CARRICK_BHYVE_CROSSSIG_USR2") else {
        eprintln!("skip: set CARRICK_BHYVE_CROSSSIG_USR2 to the crosssig-usr2 ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "cross-process SIGUSR2 guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    // The child's "crossusr2-ok" marker writes to the raw terminal fd 1 (separate
    // guest process). Assert on the PARENT marker: it only prints + exits 0 if its
    // wait4 saw the child exit 0, which the child does ONLY after its handler
    // validated si_signo == SIGUSR2 AND si_pid == the parent (else _exit(15|16)).
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("crossusr2-parent-ok"),
        "parent must wait4 the cross-process-SIGUSR2'd child to exit 0; stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn fp_preserved_across_signal() {
    // The FP-fidelity acceptance (SP3.2): the guest seeds known XMM values, then
    // `raise`s a signal whose handler CLOBBERS XMM, then after rt_sigreturn
    // asserts its XMM survived. RED on the Option-C baseline (zeroed/leaked FP),
    // GREEN once `inject_signal`/`restore_from_sigframe` round-trip FP via the
    // guest-side FXSAVE/FXRSTOR stub. Prints "fp-ok" + exit 0 on success.
    let Some(path) = fixture("CARRICK_BHYVE_FPSIGNAL") else {
        eprintln!("skip: set CARRICK_BHYVE_FPSIGNAL to the fp-signal ELF");
        return;
    };
    let result = carrick_runtime::runtime::run_elf_bhyve_dispatch(&path).expect("dispatch run");
    assert_eq!(
        result.exit_code,
        0,
        "fp-signal guest must exit 0 (stderr: {:?})",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("fp-ok"),
        "stdout: {:?}",
        String::from_utf8_lossy(&result.stdout)
    );
}
