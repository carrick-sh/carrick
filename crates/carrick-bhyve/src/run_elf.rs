//! `run_elf_bhyve` — the M2 static-ELF startup service loop.
//!
//! Mirrors [`carrick_linux::run_elf_kvm`] exactly in structure: no
//! `carrick-runtime` dependency (the crate stays cycle-free and FreeBSD-
//! compilable).  Services the x86_64 musl-static startup syscall set
//! discovered trap-driven on the FreeBSD box.
//!
//! # Syscall number contract
//!
//! [`BhyveTrapEngine::next_syscall`] returns **canonical**
//! (aarch64/asm-generic) numbers for `SyscallRemap::Direct` entries.  The
//! handlers below dispatch on those canonical numbers.  `arch_prctl`
//! (`SyscallRemap::Native`, raw x86_64 158) is serviced engine-side inside
//! `next_syscall` via the shared `carrick_hal::x8664_arch::service_arch_prctl`
//! policy and never surfaces here.
//!
//! # Memory model (M2, run-to-exit only)
//!
//! `bring_up_x86_elf` maps each region from `AddressSpace::regions()` as a
//! bhyve window with a compact GPA.  Large runtime windows (heap 128 MiB,
//! mmap arena 32 GiB, shared/private apertures) are capped to M2-grade sizes
//! so they fit within bhyve's 64 MiB lowmem.  The brk/mmap handlers below
//! use the same caps as upper bounds for their bump allocators.

#![cfg(target_arch = "x86_64")]

use std::path::Path;

use carrick_guest_mem::GuestMemory as _;
use carrick_hal::SyscallTrap as _;
use carrick_mem::memory::{AddressSpace, LINUX_HEAP_BASE, LINUX_MMAP_BASE};

use crate::guest_setup_x86::{M2_HEAP_CAP, M2_MMAP_CAP, bring_up_x86_elf};
use crate::trap_engine::BhyveTrapEngine;

// ─── canonical syscall numbers (aarch64/asm-generic, post-remap) ─────────────
//
// Source: carrick_abi::syscall::AARCH64_SYSCALLS (canonical table).

/// `read` — asm-generic 63.
const SYS_READ: u64 = 63;
/// `write` — asm-generic 64.
const SYS_WRITE: u64 = 64;
/// `writev` — asm-generic 66.
const SYS_WRITEV: u64 = 66;
/// `brk` — asm-generic 214.
const SYS_BRK: u64 = 214;
/// `munmap` — asm-generic 215.
const SYS_MUNMAP: u64 = 215;
/// `mprotect` — asm-generic 226.
const SYS_MPROTECT: u64 = 226;
/// `mmap` — asm-generic 222.
const SYS_MMAP: u64 = 222;
/// `rt_sigaction` — asm-generic 134.
const SYS_RT_SIGACTION: u64 = 134;
/// `rt_sigprocmask` — asm-generic 135.
const SYS_RT_SIGPROCMASK: u64 = 135;
/// `set_tid_address` — asm-generic 96.
const SYS_SET_TID_ADDRESS: u64 = 96;
/// `exit` — asm-generic 93.
const SYS_EXIT: u64 = 93;
/// `exit_group` — asm-generic 94.
const SYS_EXIT_GROUP: u64 = 94;
/// `ppoll` — asm-generic 73. x86_64 `poll`=7 remaps here.
/// musl calls `poll(fds, 3, 0)` non-blocking at startup to probe fd validity.
const SYS_PPOLL: u64 = 73;
/// `sigaltstack` — asm-generic 132. x86_64 `sigaltstack`=131 remaps here.
/// musl calls sigaltstack at startup to establish an alternate signal stack.
const SYS_SIGALTSTACK: u64 = 132;
/// `tkill` — asm-generic 130. x86_64 `tkill`=200 remaps here.
/// musl calls `tkill(tid, SIGABRT)` when poll returns -ENOSYS; we map to exit.
const SYS_TKILL: u64 = 130;

// ─── signal numbers (signal(7) man7.org) ─────────────────────────────────────

/// `SIGABRT = 6` (signal(7) man7.org).  musl calls `tkill(tid, SIGABRT)` to
/// abort; we map it to `exit(134)` (128 + signal number, shell convention).
const SIGABRT: u64 = 6;

// ─── mmap flags (mmap(2) man7.org) ───────────────────────────────────────────

/// `MAP_PRIVATE = 0x02` (mmap(2) man7.org).
const MAP_PRIVATE: u64 = 0x02;
/// `MAP_ANONYMOUS = 0x20` (mmap(2) man7.org).
const MAP_ANONYMOUS: u64 = 0x20;
/// `MAP_FIXED = 0x10` (mmap(2) man7.org).
const MAP_FIXED: u64 = 0x10;

// ─── errno stubs ──────────────────────────────────────────────────────────────

/// `-ENOSYS` — unhandled syscall (Linux errno 38).
const NEG_ENOSYS: i64 = -38;
/// `-EINVAL` — invalid argument (Linux errno 22).
const NEG_EINVAL: i64 = -22;
/// `-ENOMEM` — out of memory (Linux errno 12).
const NEG_ENOMEM: i64 = -12;

// ─── build_x86_engine ─────────────────────────────────────────────────────────

/// Build a fully-brought-up x86_64 bhyve trap engine from a static ELF on disk.
/// Shared by `run_elf_bhyve` (the single-threaded `CARRICK_NO_THREADS` fallback)
/// and `run_threaded_bhyve_loop` (carrick-runtime, the canonical loop).
pub fn build_x86_engine(path: impl AsRef<std::path::Path>) -> Result<BhyveTrapEngine, String> {
    let path = path.as_ref();

    // ── Load the ELF ─────────────────────────────────────────────────────────
    //
    // `load_elf_for` accepts EM_X86_64 = 62 (X8664GuestArch::elf_machine()).
    // `with_linux_initial_stack`: builds argc/argv/envp/auxv on the stack.
    // `with_vdso_auxv(false)`: strips AT_SYSINFO_EHDR (no vDSO in Phase 2;
    //   musl falls back to real SYSCALL instructions, spec §4.6).
    use carrick_hal::guest_arch::GuestArch as _;
    use carrick_hal::x8664_arch::X8664GuestArch;

    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_for: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()], // argv[0] = ELF path
            std::iter::empty::<&[u8]>(),           // no env
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?
        .with_vdso_auxv(false);

    let entry_rip = image.entry();
    let initial_rsp = image
        .initial_stack_pointer()
        .ok_or_else(|| "no initial stack pointer (with_linux_initial_stack failed?)".to_string())?;

    // ── Bring up the vCPU ────────────────────────────────────────────────────

    let bux = bring_up_x86_elf(&image, entry_rip, initial_rsp)
        .map_err(|e| format!("bring_up_x86_elf: {e}"))?;
    let engine = BhyveTrapEngine::new(bux);

    Ok(engine)
}

/// Build a fully-brought-up x86_64 bhyve engine on the SHARED `carrick-x86`
/// scaffold (`X86EngineCore<BhyveVmm>`) — the Stage-4 default path. Mirrors
/// [`build_x86_engine`] (legacy) but wraps the `BroughtUpX86` into the generic
/// engine via `bhyve_x86_engine::engine_from_brought_up`. Drives the SAME
/// `run_threaded_bhyve_loop` (the runtime function is generic over any
/// `ThreadedEngine<KickHandle = BhyveKickHandle>`).
pub fn build_x86_engine_shared(
    path: impl AsRef<std::path::Path>,
) -> Result<carrick_x86::X86EngineCore<crate::bhyve_x86_engine::BhyveVmm>, String> {
    use carrick_hal::guest_arch::GuestArch as _;
    use carrick_hal::x8664_arch::X8664GuestArch;

    let path = path.as_ref();
    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_for: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()],
            std::iter::empty::<&[u8]>(),
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?
        .with_vdso_auxv(false);

    let entry_rip = image.entry();
    let initial_rsp = image
        .initial_stack_pointer()
        .ok_or_else(|| "no initial stack pointer (with_linux_initial_stack failed?)".to_string())?;

    let bux = bring_up_x86_elf(&image, entry_rip, initial_rsp)
        .map_err(|e| format!("bring_up_x86_elf: {e}"))?;
    Ok(crate::bhyve_x86_engine::engine_from_brought_up(bux))
}

// ─── run_elf_bhyve ────────────────────────────────────────────────────────────

/// Boot the static x86_64 ELF at `path` under bhyve and run it to exit.
///
/// Returns the guest's exit code on success, or a diagnostic string on
/// bring-up failure.  Mirrors `run_elf_kvm` in structure.
///
/// # Startup-syscall service set (trap-driven, discovered on FreeBSD box)
///
/// | Canonical | x86_64 | Handler |
/// |---|---|---|
/// | 214 | 12 brk | bump over `LINUX_HEAP_BASE` window |
/// | 222 | 9 mmap | anon-private bump over `LINUX_MMAP_BASE` window |
/// | 215 | 11 munmap | no-op (run-to-exit) |
/// | 226 | 10 mprotect | `0` (PML4 already correct) |
/// | 134 | 13 rt_sigaction | `0` (no signals in M2) |
/// | 135 | 14 rt_sigprocmask | `0` (no signals) |
/// | 96 | 218 set_tid_address | host `getpid()` |
/// | 64 | 1 write | guest buffer → host `write(2)` |
/// | 66 | 20 writev | guest iovec → host writes |
/// | 63 | 0 read | host `read(2)` → guest buffer |
/// | 93/94 | 60/231 exit/exit_group | return code |
/// | 132 | 131 sigaltstack | `0` (no signals in M2) |
/// | 73 | 7 poll | `0` (no fds ready — non-blocking musl startup probe) |
/// | 130 | 200 tkill | `exit(134)` on SIGABRT, else `0` |
/// | default | — | `-ENOSYS` + x86_64 name logged |
pub fn run_elf_bhyve(path: impl AsRef<Path>) -> Result<i32, String> {
    let mut engine = build_x86_engine(path)?;

    // ── brk / mmap bump state ─────────────────────────────────────────────────
    //
    // brk(2) man7.org: on success returns the new break; on failure returns the
    // unchanged old break (NOT -errno).
    // mmap(2) man7.org: returns the mapped address or MAP_FAILED (-1) on error.

    let mut current_brk: u64 = LINUX_HEAP_BASE;
    let heap_limit: u64 = LINUX_HEAP_BASE + M2_HEAP_CAP as u64;

    let mut mmap_cursor: u64 = LINUX_MMAP_BASE;
    let mmap_limit: u64 = LINUX_MMAP_BASE + M2_MMAP_CAP as u64;

    // ── Dispatch loop ─────────────────────────────────────────────────────────

    loop {
        let raw = match engine.next_syscall().map_err(|e| format!("trap: {e}"))? {
            Some(r) => r,
            None => return Ok(0),
        };

        let canonical = raw.number;
        let args = raw.args;

        // NOTE: arch_prctl (x86_64 158) is serviced engine-side inside
        // BhyveTrapEngine::next_syscall via the shared carrick-hal policy
        // (service_arch_prctl) and never surfaces here.

        let ret: i64 = match canonical {
            // ── write(fd, buf, count) ─────────────────────────────────────────
            SYS_WRITE => match engine.read_bytes(args[1], args[2] as usize) {
                Ok(buf) => host_write(args[0] as i32, &buf),
                Err(e) => {
                    eprintln!("write: guest read error: {e}");
                    NEG_EINVAL
                }
            },

            // ── writev(fd, iov, iovcnt) ───────────────────────────────────────
            SYS_WRITEV => sys_writev(&engine, args[0], args[1], args[2])?,

            // ── read(fd, buf, count) ──────────────────────────────────────────
            SYS_READ => sys_read(&mut engine, args[0], args[1], args[2])?,

            // ── brk(addr) — bump over LINUX_HEAP_BASE window ─────────────────
            // brk(2) man7.org: on error returns the unchanged program break
            // (NOT -errno). brk(0) = query the current break.
            SYS_BRK => {
                let requested = args[0];
                if requested == 0 || (requested >= LINUX_HEAP_BASE && requested <= heap_limit) {
                    if requested != 0 {
                        current_brk = requested;
                    }
                    current_brk as i64
                } else {
                    // Past window (or below base): return old break unchanged.
                    current_brk as i64
                }
            }

            // ── mmap(addr, len, prot, flags, fd, off) ─────────────────────────
            // Anonymous-private only (musl startup uses anon mmaps for TLS etc.).
            // MAP_FIXED / MAP_SHARED / file-backed → -ENOSYS so musl treats it
            // as a feature gap (ENOMEM would abort).
            SYS_MMAP => {
                let length = args[1];
                let flags = args[3];

                let is_anon = flags & MAP_ANONYMOUS != 0;
                let is_private = flags & MAP_PRIVATE != 0;
                let is_fixed = flags & MAP_FIXED != 0;

                if is_fixed || !is_anon || !is_private || length == 0 {
                    NEG_ENOSYS
                } else {
                    let aligned = (length + 0xFFF) & !0xFFF; // page-round up
                    let va = mmap_cursor;
                    let next = va.saturating_add(aligned);
                    if next > mmap_limit {
                        NEG_ENOMEM
                    } else {
                        mmap_cursor = next;
                        va as i64
                    }
                }
            }

            // ── munmap(addr, len) — no-op for run-to-exit ────────────────────
            SYS_MUNMAP => 0,

            // ── mprotect(addr, len, prot) — 0 (PML4 already correct) ─────────
            // Decision (trap-driven): musl calls mprotect after mmap to tighten
            // permissions; the pre-built PML4 already has the right bits.
            SYS_MPROTECT => 0,

            // ── rt_sigaction(sig, act, oact, sigsetsize) ──────────────────────
            // No signals in M2; write empty oldact if non-null so musl doesn't
            // read stale bytes.
            SYS_RT_SIGACTION => {
                let oact = args[2];
                if oact != 0 {
                    // struct sigaction on x86_64 >= 32 bytes; zero it.
                    let _ = engine.write_bytes(oact, &[0u8; 32]);
                }
                0
            }

            // ── rt_sigprocmask(how, set, oldset, sigsetsize) ─────────────────
            // No signals; write empty oldset if non-null (sigset_t = 8 bytes
            // on x86_64 — 64 signals, 1 bit each, man7.org signal(7)).
            SYS_RT_SIGPROCMASK => {
                let oldset = args[2];
                if oldset != 0 {
                    let _ = engine.write_bytes(oldset, &[0u8; 8]);
                }
                0
            }

            // ── set_tid_address(tidptr) — return host getpid() ───────────────
            // set_tid_address(2) man7.org: "always returns the caller's TID".
            // For a single-threaded M2 run, host getpid() is the stand-in
            // (mirrors run_elf_kvm's "single-thread tid" comment).
            SYS_SET_TID_ADDRESS => {
                // SAFETY: getpid(2) is always safe on FreeBSD.
                let tid = unsafe { libc::getpid() };
                i64::from(tid)
            }

            // ── sigaltstack(ss, oss) — no-op (no signals in M2) ──────────────
            // musl calls sigaltstack at startup to register an alternate signal
            // stack.  0 = success; the old-ss pointer (args[1]) is not written
            // (no signals have ever fired, so old-ss is null/irrelevant).
            SYS_SIGALTSTACK => 0,

            // ── poll(fds, nfds, timeout_ms) — return 0 (no fds ready) ────────
            // musl calls `poll(fds, 3, 0)` non-blocking at startup to probe
            // stdin/stdout/stderr validity.  0 = timeout, no ready fds (safe;
            // musl continues startup normally on this return value).
            SYS_PPOLL => 0,

            // ── tkill(tid, sig) — convert abort to exit(134) ─────────────────
            // musl calls `tkill(tid, SIGABRT)` to abort.  We cannot deliver
            // signals in M2; map SIGABRT to an exit with the shell-convention
            // code 128+6=134.  Any other signal in this single-threaded M2 run
            // is a no-op (return 0).
            SYS_TKILL => {
                let sig = args[1];
                if sig == SIGABRT {
                    eprintln!("carrick-bhyve: guest called tkill(SIGABRT) → exit(134)");
                    return Ok(134);
                }
                0
            }

            // ── exit / exit_group ─────────────────────────────────────────────
            // No fork in Phase 2 — return the code directly.
            SYS_EXIT | SYS_EXIT_GROUP => {
                let code = args[0] as i32;
                return Ok(code);
            }

            // ── default: -ENOSYS + trap-driven discovery log ──────────────────
            other => {
                use carrick_hal::guest_arch::SyscallTable as _;
                use carrick_hal::x8664_arch::X8664SyscallTable;
                let name = X8664SyscallTable::name(other).unwrap_or("<unknown>");
                eprintln!(
                    "carrick-bhyve run-elf: unhandled canonical={other} \
                     x86_name={name} args={:x?} → -ENOSYS",
                    &args
                );
                NEG_ENOSYS
            }
        };

        engine
            .complete_syscall(ret)
            .map_err(|e| format!("complete_syscall: {e}"))?;
    }
}

// ─── I/O helpers ─────────────────────────────────────────────────────────────

/// `writev(fd, iov, iovcnt)` — walk the guest `struct iovec[]` and write each.
///
/// `struct iovec` on x86_64 LP64: `{ void *iov_base; size_t iov_len }` = 16 B
/// (psABI §4.1: pointers and `size_t` are both 8 bytes).
fn sys_writev(engine: &BhyveTrapEngine, fd: u64, iov_va: u64, iovcnt: u64) -> Result<i64, String> {
    const IOVEC_SIZE: u64 = 16; // x86_64 LP64: iov_base(8) + iov_len(8)
    let mut total: i64 = 0;
    for i in 0..iovcnt as usize {
        let ent = engine
            .read_bytes(iov_va + (i as u64) * IOVEC_SIZE, IOVEC_SIZE as usize)
            .map_err(|e| format!("writev iov[{i}]: {e}"))?;
        let base = u64::from_le_bytes(ent[0..8].try_into().map_err(|_| "writev: iov_base")?);
        let len =
            u64::from_le_bytes(ent[8..16].try_into().map_err(|_| "writev: iov_len")?) as usize;
        if len == 0 {
            continue;
        }
        let buf = engine
            .read_bytes(base, len)
            .map_err(|e| format!("writev buf[{i}]: {e}"))?;
        let n = host_write(fd as i32, &buf);
        if n < 0 {
            return Ok(n);
        }
        total += n;
    }
    Ok(total)
}

/// `read(fd, buf, count)` — host `read(2)`, write bytes into guest buffer.
fn sys_read(engine: &mut BhyveTrapEngine, fd: u64, buf_va: u64, count: u64) -> Result<i64, String> {
    let mut buf = vec![0u8; count as usize];
    // SAFETY: `buf` is a valid host allocation of `count` bytes; FreeBSD read(2).
    let n = unsafe { libc::read(fd as i32, buf.as_mut_ptr().cast(), count as usize) };
    if n < 0 {
        // SAFETY: FreeBSD errno accessor.
        let e = unsafe { *libc::__error() };
        return Ok(-i64::from(e));
    }
    engine
        .write_bytes(buf_va, &buf[..n as usize])
        .map_err(|e| format!("read: guest write: {e}"))?;
    Ok(n as i64)
}

fn host_write(fd: i32, buf: &[u8]) -> i64 {
    // SAFETY: `buf` is a host-owned slice; write(2) on a host fd.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        // SAFETY: FreeBSD errno accessor.
        let e = unsafe { *libc::__error() };
        -i64::from(e)
    } else {
        n as i64
    }
}
