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

use carrick_guest_mem::Aarch64SyscallFrame;
use carrick_hal::SyscallTrap;
use carrick_mem::memory::AddressSpace;

use crate::trap_engine::KvmTrapEngine;

// asm-generic / aarch64 Linux syscall numbers (the only ABI carrick supports).
const SYS_WRITE: u64 = 64;
const SYS_WRITEV: u64 = 66;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
/// `-ENOSYS` (Linux). Returned for any syscall the MVP doesn't service.
const NEG_ENOSYS: i64 = -38;

/// Boot the freestanding aarch64 ELF at `path` under KVM and run it to exit.
/// Returns the guest's exit code.
pub fn run_elf_kvm(path: impl AsRef<Path>) -> Result<i32, String> {
    let image = AddressSpace::load_elf(path).map_err(|e| format!("load_elf: {e}"))?;
    let mut engine = KvmTrapEngine::new(&image).map_err(|e| format!("kvm bring-up: {e}"))?;

    loop {
        let frame = match engine.next_syscall().map_err(|e| format!("trap: {e}"))? {
            Some(frame) => frame,
            // A bare kick/halt with no pending syscall: nothing left to do.
            None => return Ok(0),
        };
        let ret: i64 = match frame.x8 {
            SYS_WRITE => sys_write(&engine, &frame)?,
            SYS_WRITEV => sys_writev(&engine, &frame)?,
            SYS_EXIT | SYS_EXIT_GROUP => return Ok(frame.x0 as i32),
            _ => NEG_ENOSYS,
        };
        engine
            .complete_syscall(ret)
            .map_err(|e| format!("complete_syscall: {e}"))?;
    }
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
