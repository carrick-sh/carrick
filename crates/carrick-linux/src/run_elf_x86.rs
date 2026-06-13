//! Thin MVP run path: boot a static x86_64 Linux ELF under KVM on Linux x86_64
//! and service its syscalls directly.
//!
//! Mirrors `run_elf_bhyve` (carrick-bhyve) in structure: no `carrick-runtime`
//! dependency — keeps the crate cycle-free and container-104-compilable.
//!
//! # Syscall number contract
//!
//! `KvmX86TrapEngine::next_syscall` returns **canonical** (aarch64/asm-generic)
//! numbers for `SyscallRemap::Direct` entries.  The handlers below dispatch on
//! those canonical numbers.  `arch_prctl` is `SyscallRemap::Native` and arrives
//! as raw x86_64 158 — handled explicitly before the canonical dispatch arm.
//!
//! # Startup-syscall service set (trap-driven, from bhyve oracle + live run)
//!
//! | Canonical | x86_64 | Handler |
//! |---|---|---|
//! | 158 (Native) | arch_prctl | `set_fs_base` via `KVM_SET_SREGS` |
//! | 214 | 12 brk | bump over `LINUX_HEAP_BASE` window |
//! | 222 | 9 mmap | anon-private bump over `LINUX_MMAP_BASE` window |
//! | 215 | 11 munmap | no-op (run-to-exit) |
//! | 226 | 10 mprotect | `0` (PML4 already correct) |
//! | 134 | 13 rt_sigaction | `0` (no signals in M0–M2) |
//! | 135 | 14 rt_sigprocmask | `0` / write empty oldset |
//! | 96 | 218 set_tid_address | host `getpid()` |
//! | 64 | 1 write | guest buffer → host `write(2)` |
//! | 66 | 20 writev | guest iovec → host writes |
//! | 63 | 0 read | host `read(2)` → guest buffer |
//! | 57 | 3 close | `0` (best-effort; no fd tracking in MVP) |
//! | 93/94 | 60/231 exit/exit_group | return code |
//! | 132 | 131 sigaltstack | `0` (no signals in M2) |
//! | 73 | 7 poll | `0` (non-blocking musl startup probe) |
//! | 130 | 200 tkill | `exit(134)` on SIGABRT, else `0` |
//! | default | — | `-ENOSYS` + x86_64 name logged |

use std::path::Path;

use carrick_guest_mem::GuestMemory as _;
use carrick_hal::SyscallTrap as _;
use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::{AddressSpace, LINUX_HEAP_BASE, LINUX_MMAP_BASE};

use crate::trap_engine_x86::KvmX86TrapEngine;

// ─── Canonical syscall numbers (aarch64/asm-generic, post-remap) ─────────────
//
// Source: man7.org syscall(2) / syscalls(2); carrick_abi canonical table.

/// `read` — asm-generic 63.
const SYS_READ: u64 = 63;
/// `write` — asm-generic 64.
const SYS_WRITE: u64 = 64;
/// `close` — asm-generic 57.
const SYS_CLOSE: u64 = 57;
/// `writev` — asm-generic 66.
const SYS_WRITEV: u64 = 66;
/// `exit` — asm-generic 93.
const SYS_EXIT: u64 = 93;
/// `exit_group` — asm-generic 94.
const SYS_EXIT_GROUP: u64 = 94;
/// `brk` — asm-generic 214.
const SYS_BRK: u64 = 214;
/// `mmap` — asm-generic 222.
const SYS_MMAP: u64 = 222;
/// `munmap` — asm-generic 215.
const SYS_MUNMAP: u64 = 215;
/// `mprotect` — asm-generic 226.
const SYS_MPROTECT: u64 = 226;
/// `set_tid_address` — asm-generic 96.
const SYS_SET_TID_ADDRESS: u64 = 96;
/// `rt_sigprocmask` — asm-generic 135.
const SYS_RT_SIGPROCMASK: u64 = 135;
/// `rt_sigaction` — asm-generic 134.
const SYS_RT_SIGACTION: u64 = 134;
/// `sigaltstack` — asm-generic 132. x86_64 `sigaltstack`=131 remaps here.
const SYS_SIGALTSTACK: u64 = 132;
/// `ppoll` — asm-generic 73. x86_64 `poll`=7 remaps here.
const SYS_PPOLL: u64 = 73;
/// `tkill` — asm-generic 130. x86_64 `tkill`=200 remaps here.
const SYS_TKILL: u64 = 130;

// ─── x86_64-private syscall (Native remap — returned untranslated) ────────────

/// `arch_prctl` x86_64 number 158.  Arrives from `next_syscall` as 158
/// (`SyscallRemap::Native` — not remapped to a canonical number).
/// Source: arch_prctl(2) man7.org.
const X86_ARCH_PRCTL: u64 = 158;

// ─── arch_prctl codes (arch_prctl(2) man7.org) ───────────────────────────────

/// `ARCH_SET_FS = 0x1002` — set FS.base (musl TLS pointer).
const ARCH_SET_FS: u64 = 0x1002;
/// `ARCH_GET_FS = 0x1003` — read FS.base.
const ARCH_GET_FS: u64 = 0x1003;
/// `ARCH_SET_GS = 0x1001` — set GS.base.
const ARCH_SET_GS: u64 = 0x1001;
/// `ARCH_GET_GS = 0x1004` — read GS.base.
const ARCH_GET_GS: u64 = 0x1004;

// ─── mmap flags (mmap(2) man7.org) ───────────────────────────────────────────

const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;

// ─── signal numbers (signal(7) man7.org) ─────────────────────────────────────

/// `SIGABRT = 6` — musl calls `tkill(tid, SIGABRT)` to abort.
const SIGABRT: u64 = 6;

// ─── errno stubs ──────────────────────────────────────────────────────────────

/// `-ENOSYS` — unhandled syscall (Linux errno 38).
const NEG_ENOSYS: i64 = -38;
/// `-EINVAL` — invalid argument (Linux errno 22).
const NEG_EINVAL: i64 = -22;
/// `-ENOMEM` — out of memory (Linux errno 12).
const NEG_ENOMEM: i64 = -12;

// ─── heap / mmap caps ────────────────────────────────────────────────────────

/// Maximum bump-allocator heap size for the M2 run-elf loop (8 MiB).
/// Mirrors M2_HEAP_CAP from carrick-bhyve (the KVM identity-map has no
/// lowmem constraint, so a larger cap is fine; 8 MiB covers musl startup).
const M2_HEAP_CAP: u64 = 8 * 1024 * 1024; // 8 MiB

/// Maximum bump-allocator mmap arena for the M2 run-elf loop (64 MiB).
const M2_MMAP_CAP: u64 = 64 * 1024 * 1024; // 64 MiB

// ─── run_elf_kvm_x86 ─────────────────────────────────────────────────────────

/// Boot the static x86_64 ELF at `path` under KVM and run it to exit.
///
/// Returns the guest's exit code on success, or a diagnostic string on failure.
/// Mirrors `run_elf_bhyve` in structure: no `carrick-runtime` dependency.
pub fn run_elf_kvm_x86(path: impl AsRef<Path>) -> Result<i32, String> {
    let path = path.as_ref();

    // ── Load the ELF ─────────────────────────────────────────────────────────
    //
    // `load_elf_for` accepts `EM_X86_64 = 62` (`X8664GuestArch::elf_machine()`).
    // `with_linux_initial_stack`: builds argc/argv/envp/auxv on the guest stack.
    // `with_vdso_auxv(false)`: strips `AT_SYSINFO_EHDR` (no vDSO in Phase 2;
    //   musl falls back to real SYSCALL instructions; spec N3).

    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_x86: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()], // argv[0] = ELF path
            std::iter::empty::<&[u8]>(),           // no env vars
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?
        .with_vdso_auxv(false);

    // ── Bring up the vCPU ────────────────────────────────────────────────────

    let mut engine = KvmX86TrapEngine::new(&image).map_err(|e| format!("kvm-x86 bring-up: {e}"))?;

    // ── brk / mmap bump state ─────────────────────────────────────────────────

    let mut current_brk: u64 = LINUX_HEAP_BASE;
    let heap_limit: u64 = LINUX_HEAP_BASE + M2_HEAP_CAP;

    let mut mmap_cursor: u64 = LINUX_MMAP_BASE;
    let mmap_limit: u64 = LINUX_MMAP_BASE + M2_MMAP_CAP;

    // ── Dispatch loop ─────────────────────────────────────────────────────────

    loop {
        let raw = match engine.next_syscall().map_err(|e| format!("trap: {e}"))? {
            Some(r) => r,
            None => return Ok(0),
        };

        let canonical = raw.number;
        let args = raw.args;

        // arch_prctl: Native remap — arrives as raw x86_64 158.
        if canonical == X86_ARCH_PRCTL {
            let ret = sys_arch_prctl(&mut engine, args[0], args[1])
                .map_err(|e| format!("arch_prctl: {e}"))?;
            engine
                .complete_syscall(ret)
                .map_err(|e| format!("complete_syscall(arch_prctl): {e}"))?;
            continue;
        }

        let ret: i64 = match canonical {
            // ── write(fd, buf, count) ─────────────────────────────────────────
            SYS_WRITE => match engine.read_bytes(args[1], args[2] as usize) {
                Ok(buf) => host_write(args[0] as i32, &buf),
                Err(e) => {
                    eprintln!("kvm-x86 write: guest read error: {e}");
                    NEG_EINVAL
                }
            },

            // ── writev(fd, iov, iovcnt) ───────────────────────────────────────
            SYS_WRITEV => sys_writev(&engine, args[0], args[1], args[2])?,

            // ── read(fd, buf, count) ──────────────────────────────────────────
            SYS_READ => sys_read(&mut engine, args[0], args[1], args[2])?,

            // ── close(fd) — best-effort no-op (no fd tracking in MVP) ─────────
            SYS_CLOSE => 0,

            // ── brk(addr) — bump allocator over LINUX_HEAP_BASE window ────────
            // brk(2) man7.org: on error returns the UNCHANGED program break (not
            // -errno).  brk(0) = query the current break.
            SYS_BRK => {
                let requested = args[0];
                if requested == 0 || (requested >= LINUX_HEAP_BASE && requested <= heap_limit) {
                    if requested != 0 {
                        current_brk = requested;
                    }
                    current_brk as i64
                } else {
                    current_brk as i64 // past window: return old break unchanged
                }
            }

            // ── mmap(addr, len, prot, flags, fd, off) ─────────────────────────
            // Anonymous-private only (musl startup uses anon mmaps for TLS etc.).
            // MAP_FIXED / MAP_SHARED / file-backed → -ENOSYS so musl treats it
            // as unsupported (ENOMEM would abort).
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

            // ── munmap(addr, len) — no-op for run-to-exit ─────────────────────
            SYS_MUNMAP => 0,

            // ── mprotect(addr, len, prot) — 0 (PML4 already correct) ──────────
            // musl calls mprotect after mmap to tighten permissions; the
            // pre-built PML4 already carries the right bits for the static ELF.
            SYS_MPROTECT => 0,

            // ── rt_sigaction(sig, act, oact, sigsetsize) ───────────────────────
            // No signals in M0–M2; write empty oldact if non-null.
            SYS_RT_SIGACTION => {
                let oact = args[2];
                if oact != 0 {
                    // struct sigaction on x86_64 >= 32 bytes; zero it out.
                    let _ = engine.write_bytes(oact, &[0u8; 32]);
                }
                0
            }

            // ── rt_sigprocmask(how, set, oldset, sigsetsize) ──────────────────
            // No signals; write empty oldset if non-null.
            // sigset_t = 8 bytes on x86_64 (signal(7) man7.org: 64 signals).
            SYS_RT_SIGPROCMASK => {
                let oldset = args[2];
                if oldset != 0 {
                    let _ = engine.write_bytes(oldset, &[0u8; 8]);
                }
                0
            }

            // ── set_tid_address(tidptr) — return host getpid() ────────────────
            // set_tid_address(2) man7.org: "always returns the caller's TID".
            // For a single-threaded M2 run, host getpid() is the stand-in.
            SYS_SET_TID_ADDRESS => {
                // SAFETY: getpid(2) is always safe.
                let tid = unsafe { libc::getpid() };
                i64::from(tid)
            }

            // ── sigaltstack(ss, oss) — no-op (no signals in M2) ───────────────
            SYS_SIGALTSTACK => 0,

            // ── poll / ppoll (asm-generic 73) — return 0 (no fds ready) ───────
            // musl calls `poll(fds, 3, 0)` non-blocking at startup to probe
            // stdin/stdout/stderr validity.  0 = timeout, no ready fds.
            SYS_PPOLL => 0,

            // ── tkill(tid, sig) — convert SIGABRT to exit(134) ────────────────
            // musl calls `tkill(tid, SIGABRT)` to abort.  We cannot deliver
            // signals in M2; map SIGABRT to exit code 128+6=134 (shell convention).
            SYS_TKILL => {
                let sig = args[1];
                if sig == SIGABRT {
                    eprintln!("kvm-x86: guest called tkill(SIGABRT) → exit(134)");
                    return Ok(134);
                }
                0
            }

            // ── exit / exit_group ─────────────────────────────────────────────
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
                    "kvm-x86 run-elf: unhandled canonical={other} x86_name={name} \
                     args={:x?} → -ENOSYS",
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

// ─── arch_prctl (Native — x86_64 158) ────────────────────────────────────────

/// Service `arch_prctl(code, addr)` via `KvmX86TrapEngine::set/get_fs_base`.
///
/// On KVM x86_64, FS.base is directly accessible through `sregs.fs.base` via
/// `KVM_GET_SREGS` / `KVM_SET_SREGS` — simpler than bhyve's `vm_set_desc` path.
///
/// arch_prctl(2) man7.org: `ARCH_SET_FS=0x1002`, `ARCH_GET_FS=0x1003`,
/// `ARCH_SET_GS=0x1001`, `ARCH_GET_GS=0x1004`.  Unknown code → `-EINVAL`.
fn sys_arch_prctl(
    engine: &mut KvmX86TrapEngine,
    code: u64,
    addr: u64,
) -> Result<i64, carrick_hal::TrapError> {
    match code {
        ARCH_SET_FS => engine.set_fs_base(addr),
        ARCH_GET_FS => {
            let val = engine.get_fs_base()?;
            // Write the current FS.base value to the user pointer (8 bytes LE).
            let _ = engine.write_bytes(addr, &val.to_le_bytes());
            Ok(0)
        }
        ARCH_SET_GS => {
            // GS.base: same mechanism as FS.base via KVM_GET/SET_SREGS.
            let mut sregs = engine
                .vcpu_fd()
                .get_sregs()
                .map_err(|e| carrick_hal::TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
            sregs.gs.base = addr;
            engine
                .vcpu_fd()
                .set_sregs(&sregs)
                .map_err(|e| carrick_hal::TrapError::Hypervisor(format!("KVM_SET_SREGS: {e}")))?;
            Ok(0)
        }
        ARCH_GET_GS => {
            let sregs = engine
                .vcpu_fd()
                .get_sregs()
                .map_err(|e| carrick_hal::TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
            let _ = engine.write_bytes(addr, &sregs.gs.base.to_le_bytes());
            Ok(0)
        }
        _ => {
            eprintln!("kvm-x86 arch_prctl: unknown code={code:#x} addr={addr:#x} → -EINVAL");
            Ok(NEG_EINVAL)
        }
    }
}

// ─── I/O helpers ─────────────────────────────────────────────────────────────

/// `writev(fd, iov, iovcnt)` — walk the guest `struct iovec[]` and write each.
///
/// `struct iovec` on x86_64 LP64: `{ void *iov_base; size_t iov_len }` = 16 B.
/// Source: psABI §4.1 — pointers and `size_t` are both 8 bytes on LP64.
fn sys_writev(engine: &KvmX86TrapEngine, fd: u64, iov_va: u64, iovcnt: u64) -> Result<i64, String> {
    const IOVEC_SIZE: u64 = 16; // iov_base(8) + iov_len(8)
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

/// `read(fd, buf, count)` — host `read(2)`, copy result into guest buffer.
fn sys_read(
    engine: &mut KvmX86TrapEngine,
    fd: u64,
    buf_va: u64,
    count: u64,
) -> Result<i64, String> {
    let mut buf = vec![0u8; count as usize];
    // SAFETY: `buf` is a valid host allocation; `read(2)` on a host fd.
    let n = unsafe { libc::read(fd as i32, buf.as_mut_ptr().cast(), count as usize) };
    if n < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Ok(-i64::from(e));
    }
    engine
        .write_bytes(buf_va, &buf[..n as usize])
        .map_err(|e| format!("read: guest write: {e}"))?;
    Ok(n as i64)
}

/// Host `write(2)` helper — returns bytes written (>= 0) or `-errno`.
fn host_write(fd: i32, buf: &[u8]) -> i64 {
    // SAFETY: `buf` is a host-owned slice; `write(2)` on a host fd.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        -i64::from(e)
    } else {
        n as i64
    }
}
