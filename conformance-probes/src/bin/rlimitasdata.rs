//! RLIMIT_AS and RLIMIT_DATA are enforced at the SOFT limit by mmap(2), brk(2)
//! and mremap(2) with ENOMEM (setrlimit(2)); brk reports it by returning the
//! unchanged break. RLIMIT_DATA charges the heap plus private writable
//! non-stack mappings (proc(5) VmData): PROT_NONE reservations and MAP_SHARED
//! mappings are address space but not data. Both limits are inherited by a
//! fork child. carrick stored both and enforced neither.
//!
//! Sizes leave wide margins so the baseline VmSize/VmData of a static musl
//! probe (a few MiB on Linux; the visible boot regions under carrick) sits
//! well below every threshold. Raw syscalls throughout; no sizes, addresses or
//! pids are printed.

use conformance_probes::errno;

const MIB: u64 = 1024 * 1024;

fn set_limit(resource: i64, cur: u64) -> bool {
    let rl = libc::rlimit {
        rlim_cur: cur,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            0i64,
            resource,
            &rl as *const libc::rlimit as i64,
            0i64,
        ) == 0
    }
}

/// Raw brk(2): returns the (possibly unchanged) break.
fn brk(addr: u64) -> u64 {
    unsafe { libc::syscall(libc::SYS_brk, addr) as u64 }
}

/// Raw anonymous mmap: Ok(addr) or Err(errno).
fn map(len: u64, prot: i32, flags: i32) -> Result<u64, i32> {
    let r = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            0u64,
            len,
            prot as i64,
            (flags | libc::MAP_ANONYMOUS) as i64,
            -1i64,
            0i64,
        )
    };
    if r == -1 { Err(errno()) } else { Ok(r as u64) }
}

fn unmap(addr: u64, len: u64) -> bool {
    unsafe { libc::syscall(libc::SYS_munmap, addr, len) == 0 }
}

/// Raw mremap(MREMAP_MAYMOVE): Ok(new_addr) or Err(errno).
fn remap(addr: u64, old: u64, new: u64) -> Result<u64, i32> {
    let r = unsafe {
        libc::syscall(
            libc::SYS_mremap,
            addr,
            old,
            new,
            libc::MREMAP_MAYMOVE as i64,
            0u64,
        )
    };
    if r == -1 { Err(errno()) } else { Ok(r as u64) }
}

fn main() {
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let rlimit_data = libc::RLIMIT_DATA as i64;
    let rlimit_as = libc::RLIMIT_AS as i64;

    // ---- RLIMIT_DATA: heap + private writable mappings; not PROT_NONE, not shared.
    println!("data_limit_set={}", set_limit(rlimit_data, 64 * MIB));
    let initial = brk(0);
    let grown = brk(initial + 16 * MIB);
    println!("brk_16mib_ok={}", grown == initial + 16 * MIB);
    // 16 + 56 = 72 MiB > 64 MiB: the break must not move.
    println!(
        "brk_past_data_unchanged={}",
        brk(grown + 56 * MIB) == grown
    );
    // 16 MiB heap + 56 MiB private RW = 72 > 64.
    println!(
        "mmap_rw_private_past_data_enomem={}",
        map(56 * MIB, rw, libc::MAP_PRIVATE) == Err(libc::ENOMEM)
    );
    let reserve = map(128 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE);
    println!("mmap_prot_none_not_data={}", reserve.is_ok());
    let shared = map(16 * MIB, rw, libc::MAP_SHARED);
    println!("mmap_shared_rw_not_data={}", shared.is_ok());
    println!("brk_shrink_ok={}", brk(initial) == initial);
    let data = map(32 * MIB, rw, libc::MAP_PRIVATE);
    println!("mmap_rw_private_within_data_ok={}", data.is_ok());

    // ---- RLIMIT_AS: everything mapped counts; mremap growth counts.
    // Mapped now: 128 (PROT_NONE) + 16 (shared) + 32 (RW) = 176 MiB + baseline.
    println!("as_limit_set={}", set_limit(rlimit_as, 320 * MIB));
    let within = map(96 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE);
    println!("mmap_within_as_ok={}", within.is_ok());
    // 272 + 96 = 368 MiB > 320.
    println!(
        "mmap_past_as_enomem={}",
        map(96 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE) == Err(libc::ENOMEM)
    );
    let (remap_past, remap_within) = match data {
        Ok(addr) => (
            // 272 + (200 - 32) = 440 MiB > 320.
            remap(addr, 32 * MIB, 200 * MIB) == Err(libc::ENOMEM),
            // 272 + (48 - 32) = 288 MiB <= 320.
            remap(addr, 32 * MIB, 48 * MIB).is_ok(),
        ),
        Err(_) => (false, false),
    };
    println!("mremap_past_as_enomem={remap_past}");
    println!("mremap_within_as_ok={remap_within}");

    // ---- Fork inheritance: the child sees the same RLIMIT_AS.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let refused = map(96 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE) == Err(libc::ENOMEM);
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }
    let mut status = 0i32;
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) } == pid;
    println!(
        "child_inherits_as_limit={}",
        pid > 0 && reaped && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    );

    if let Ok(addr) = within {
        let _ = unmap(addr, 96 * MIB);
    }
}
