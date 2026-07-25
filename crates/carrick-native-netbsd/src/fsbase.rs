//! NetBSD/amd64 FS-base host body for the shared x86 DSR gateway's
//! host-abstracted fsbase-swap seam.
//!
//! ## Why this exists
//!
//! The shared `carrick-dsr-x86` gateway (`gateway_x86_64.S`) swaps the hardware
//! FS base on every guest↔host crossing with the FSGSBASE instructions
//! (`rdfsbase`/`wrfsbase`). FreeBSD and Linux enable ring-3 `CR4.FSGSBASE`, so
//! those instructions work in userland. **NetBSD 10.1/amd64 does NOT** enable
//! ring-3 FSGSBASE (there is no sysctl toggle), so the first gateway
//! `rdfsbase` raises `#UD` → SIGILL before any guest code runs.
//!
//! NetBSD keeps the per-LWP FS base in the PCB and exposes it only through the
//! `sysarch(2)` syscall (the value is reloaded from the PCB on every kernel
//! entry/exit, so a userland `wrfsbase` would be reverted anyway). This module
//! is the host body the runtime injects into `X86DsrContext::set_fsbase_fn`; the
//! `#if defined(__NetBSD__)` gateway path calls [`set`] at install/restore and
//! the runtime calls [`get`] once per host thread to prime `host_fsbase`.
//!
//! ## Clean-room ABI (from the box headers on NetBSD 10.1/amd64, VM 201)
//!
//! - `/usr/include/x86/sysarch.h` (`$NetBSD: sysarch.h,v 1.15 2020/06/19`):
//!   `X86_GET_FSBASE = 15`, `X86_SET_FSBASE = 17` (the `X86_64_*` aliases map to
//!   these on amd64). `int sysarch(int number, void *args)` — for GET/SET
//!   FSBASE, `args` points at a single `void`-pointer-sized slot: SET reads the
//!   new base from `*args`; GET writes the current base into `*args`.
//! - `/usr/include/sys/syscall.h`: `SYS_sysarch = 165`.
//!
//! Nothing here reads Linux/UAPI source: the numbers are the NetBSD box's own
//! machine headers.

// sysarch(2) selectors and syscall number, grounded from the box headers above.
const SYS_SYSARCH: usize = 165;
const X86_64_GET_FSBASE: usize = 15;
const X86_64_SET_FSBASE: usize = 17;

/// Install `base` as this host thread's hardware FS base via
/// `sysarch(X86_64_SET_FSBASE, &base)`.
///
/// **This is the pointer the runtime injects into
/// `X86DsrContext::set_fsbase_fn`, and it runs at gateway exit site 3 with the
/// GUEST FS base still installed — so host TLS is poison.** It is therefore a
/// naked, TLS-free leaf: a raw `syscall` with no libc wrapper, no `errno`
/// (which is TLS-backed), and no compiler-generated prologue/stack canary that
/// could deref the poisoned base. `errno`/failure is deliberately ignored:
/// `sysarch(SET_FSBASE)` with a caller-owned slot does not fail in practice, and
/// a fail-open store of a bad base is no worse than the `wrfsbase` it replaces.
///
/// SysV entry: `%rdi = base`. Returns `()`.
#[unsafe(naked)]
pub extern "C" fn set(base: u64) {
    // `sysarch(number, args)`: %rax = SYS_sysarch, %rdi = number, %rsi = args.
    // Stash the incoming base (%rdi) on the stack so %rsi can point at it, then
    // overwrite %rdi with the selector. `push`/`pop` balance, so the leaf keeps
    // the caller's 16-byte alignment invariant and touches no TLS.
    core::arch::naked_asm!(
        "push rdi",                 // args slot on the stack = base
        "mov rsi, rsp",             // %rsi = &base
        "mov edi, {set_fsbase}",    // %rdi = X86_64_SET_FSBASE (number)
        "mov eax, {sys_sysarch}",   // %rax = SYS_sysarch
        "syscall",
        "pop rdi",                  // discard the slot (restore %rsp)
        "ret",
        set_fsbase = const X86_64_SET_FSBASE,
        sys_sysarch = const SYS_SYSARCH,
    );
}

/// Read this host thread's current hardware FS base via
/// `sysarch(X86_64_GET_FSBASE, &mut base)`.
///
/// Called ONCE per host thread at run-loop setup — never on the hot path — with
/// host TLS live, so an ordinary `asm!` is fine here (no naked/TLS-free
/// constraint). The host FS base is invariant per host thread (it is that
/// thread's libc/pthread TLS pointer; the runtime never sets its OWN threads'
/// base, only guest bases inside the gateway), so one capture primes
/// `X86DsrContext::host_fsbase` for the whole thread and eliminates the
/// enter-time GET the FreeBSD/Linux `rdfsbase` performs.
pub fn get() -> u64 {
    let mut base: u64 = 0;
    // SAFETY: `sysarch(X86_64_GET_FSBASE, &mut base)` writes this thread's FS
    // base into `base`; %rcx/%r11 are the architectural `syscall` clobbers and
    // %rdx may carry a second return value, so all three are marked clobbered.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") SYS_SYSARCH => _,
            in("rdi") X86_64_GET_FSBASE,
            in("rsi") &mut base as *mut u64,
            out("rcx") _,
            out("rdx") _,
            out("r11") _,
        );
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live NetBSD LWP always has a non-null FS base (its libpthread TLS
    /// pointer), so `get()` returning zero would mean the syscall path is wrong.
    #[test]
    fn get_returns_a_plausible_nonzero_base() {
        assert_ne!(get(), 0, "a live NetBSD LWP must have a non-null FS base");
    }

    /// `set(x); get() == x` round-trips through the PCB. Run on a DEDICATED
    /// thread and, crucially, restore the real base BEFORE any assertion: while
    /// the scratch base is installed, host TLS is poison, so a panic (or any
    /// TLS-using code) between `set(scratch)` and `set(original)` would crash the
    /// whole process instead of failing the test. All reads in that window use
    /// the TLS-free `get()`.
    #[test]
    fn set_then_get_round_trips_a_scratch_base() {
        std::thread::spawn(|| {
            // A page-aligned, mapped, canonical user VA to name as a base. We
            // never DEREFERENCE `fs:` here — only round-trip the register value —
            // but a real mapped page guarantees the kernel accepts it.
            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(page, libc::MAP_FAILED, "map scratch base page");
            let scratch = page as u64;

            let original = get();
            // --- poison-TLS window: NO TLS, NO panic paths until restored ---
            set(scratch);
            let read_back = get();
            set(original);
            // --- host TLS is valid again below; assertions are safe ---

            unsafe { libc::munmap(page, 4096) };

            assert_eq!(read_back, scratch, "sysarch SET/GET must round-trip");
            assert_eq!(get(), original, "the real host base restores exactly");
        })
        .join()
        .expect("fsbase round-trip thread");
    }
}
