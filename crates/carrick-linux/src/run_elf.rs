//! Thin MVP run path: boot a freestanding aarch64 Linux ELF under KVM and
//! service its syscalls directly.
//!
//! This is the spec's **R4 fallback**. "Reuse the real `carrick-runtime`
//! dispatch" would require porting ~200 macOS-isms (kqueue `EV_*`/`NOTE_*`,
//! `__error`, `xucred`, ptrace `PT_*`, `siginfo_t` field-vs-method, u32/u64
//! flag mismatches) out of the dispatch layer onto Linux — that is the
//! full-Linux-backend spec's job, not this MVP's. The MVP instead proves the
//! `carrick-hal` seam end-to-end (HAL traits + MMIO-sentinel trap vehicle +
//! `carrick-mem` bring-up) by servicing the freestanding fixture's syscalls
//! (`write`/`writev`, `exit`/`exit_group`) here, with no `carrick-runtime`
//! dependency (which keeps this crate cycle-free and Linux-compilable).
use std::path::Path;

use carrick_guest_mem::{Aarch64SyscallFrame, GuestMemory};
use carrick_hal::{ForkOutcome, SyscallTrap};
use carrick_mem::memory::AddressSpace;

use crate::trap_engine::KvmTrapEngine;

// asm-generic / aarch64 Linux syscall numbers (the only ABI carrick supports).
const SYS_WRITE: u64 = 64;
const SYS_WRITEV: u64 = 66;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_CLONE: u64 = 220; // aarch64 has no `fork`; libc `fork()` -> clone(SIGCHLD)
const SYS_WAIT4: u64 = 260;
/// `-ENOSYS` (Linux). Returned for any syscall the MVP doesn't service.
const NEG_ENOSYS: i64 = -38;
/// `CLONE_VM` — set in `clone`'s flags for thread/vfork creation. The thin shim
/// only services the plain `fork()` shape (no CLONE_VM); threads are Task 5.
const CLONE_VM: u64 = 0x0000_0100;

/// Boot the freestanding aarch64 ELF at `path` under KVM and run it to exit.
/// Returns the guest's exit code.
pub fn run_elf_kvm(path: impl AsRef<Path>) -> Result<i32, String> {
    let image = AddressSpace::load_elf(path).map_err(|e| format!("load_elf: {e}"))?;
    let mut engine = KvmTrapEngine::new(&image).map_err(|e| format!("kvm bring-up: {e}"))?;
    let trace = std::env::var_os("CARRICK_TRACE_TRAPS").is_some();

    loop {
        let frame = match engine.next_syscall().map_err(|e| format!("trap: {e}"))? {
            Some(frame) => frame,
            // A bare kick/halt with no pending syscall: nothing left to do.
            None => return Ok(0),
        };
        if trace {
            // SAFETY: getpid(2) is always-safe; used only for trace correlation.
            let pid = unsafe { libc::getpid() };
            eprintln!(
                "[trap pid={pid} child={}] x8={} x0=0x{:x} x1=0x{:x} x2=0x{:x}",
                engine.is_forked_child(),
                frame.x8,
                frame.x0,
                frame.x1,
                frame.x2
            );
        }
        let ret: i64 = match frame.x8 {
            SYS_WRITE => sys_write(&engine, &frame)?,
            SYS_WRITEV => sys_writev(&engine, &frame)?,
            SYS_CLONE => sys_clone(&mut engine, &frame)?,
            SYS_WAIT4 => sys_wait4(&mut engine, &frame)?,
            // exit/exit_group: a forked CHILD must terminate the real host
            // process with this code so the parent's host wait4 reaps it (the
            // exit code travels via the OS, not a Rust return). The top-level
            // process returns the code to its caller instead.
            SYS_EXIT | SYS_EXIT_GROUP => {
                let code = frame.x0 as i32;
                if engine.is_forked_child() {
                    // SAFETY: _exit(2) terminates this forked child immediately
                    // (no atexit/stdio flush — guest stdio already drained).
                    unsafe { libc::_exit(code & 0xff) };
                }
                return Ok(code);
            }
            _ => NEG_ENOSYS,
        };
        engine
            .complete_syscall(ret)
            .map_err(|e| format!("complete_syscall: {e}"))?;
    }
}

/// `clone(flags, child_stack, ...)` — the thin shim only handles the plain
/// `fork()` shape (`clone(SIGCHLD)`, no `CLONE_VM`). On the PARENT side, returns
/// the child pid; on the CHILD side, `engine.fork()` already set x0 = 0 and swapped
/// in the rebuilt VM, so `complete_syscall(0)` is a harmless re-write of 0. Any
/// thread/`CLONE_VM` clone is ENOSYS here (threads are Task 5; the full dispatcher
/// drives them in Task 7).
fn sys_clone(engine: &mut KvmTrapEngine, frame: &Aarch64SyscallFrame) -> Result<i64, String> {
    if frame.x0 & CLONE_VM != 0 {
        return Ok(NEG_ENOSYS);
    }
    match engine.fork().map_err(|e| format!("fork: {e}"))? {
        ForkOutcome::Parent { child_pid } => Ok(i64::from(child_pid)),
        // x0 is already 0 in the child; report 0 so complete_syscall keeps it 0.
        ForkOutcome::Child => Ok(0),
    }
}

/// `wait4(pid, *status, options, *rusage)` — a real host `wait4`. The forked
/// child is a genuine host process, so the host reaps it directly; the exit
/// status is copied back into the guest's `*status` word.
fn sys_wait4(engine: &mut KvmTrapEngine, frame: &Aarch64SyscallFrame) -> Result<i64, String> {
    let pid = frame.x0 as i32;
    let status_ptr = frame.x1;
    let options = frame.x2 as i32;
    let mut status: libc::c_int = 0;
    // SAFETY: a host wait4 with a host-owned `&mut status`; rusage is null.
    let reaped = unsafe { libc::wait4(pid, &mut status, options, std::ptr::null_mut()) };
    if reaped < 0 {
        let e = unsafe { *libc::__errno_location() };
        return Ok(-i64::from(e));
    }
    if status_ptr != 0 {
        engine
            .write_bytes(status_ptr, &status.to_le_bytes())
            .map_err(|e| format!("wait4 status write: {e}"))?;
    }
    Ok(i64::from(reaped))
}

/// `write(fd, buf, count)` — copy the guest buffer to a host fd.
fn sys_write(engine: &KvmTrapEngine, frame: &Aarch64SyscallFrame) -> Result<i64, String> {
    let buf = engine
        .read_guest(frame.x1, frame.x2 as usize)
        .map_err(|e| format!("write: {e}"))?;
    Ok(host_write(frame.x0 as i32, &buf))
}

/// `writev(fd, iov, iovcnt)` — walk the guest `struct iovec[]` and write each.
/// (musl's buffered stdio uses `writev`; supports the bounded musl-stretch.)
fn sys_writev(engine: &KvmTrapEngine, frame: &Aarch64SyscallFrame) -> Result<i64, String> {
    const IOVEC_SIZE: u64 = 16; // aarch64: { void *iov_base; size_t iov_len; }
    let fd = frame.x0 as i32;
    let iov_base = frame.x1;
    let iovcnt = frame.x2 as usize;
    let mut total: i64 = 0;
    for i in 0..iovcnt {
        let ent = engine
            .read_guest(iov_base + (i as u64) * IOVEC_SIZE, IOVEC_SIZE as usize)
            .map_err(|e| format!("writev iov[{i}]: {e}"))?;
        let to_u64 = |b: &[u8]| -> Result<u64, String> {
            b.try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| "writev: short iovec".to_string())
        };
        let base = to_u64(&ent[0..8])?;
        let len = to_u64(&ent[8..16])? as usize;
        if len == 0 {
            continue;
        }
        let buf = engine
            .read_guest(base, len)
            .map_err(|e| format!("writev buf[{i}]: {e}"))?;
        let n = host_write(fd, &buf);
        if n < 0 {
            return Ok(n);
        }
        total += n;
    }
    Ok(total)
}

fn host_write(fd: i32, buf: &[u8]) -> i64 {
    // SAFETY: `buf` is a host-owned slice; we hand its pointer + length to
    // write(2) on a host fd. On error, return -errno (Linux errno == host errno).
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        let e = unsafe { *libc::__errno_location() };
        -i64::from(e)
    } else {
        n as i64
    }
}
