//! COARSE clocks through the vDSO, compared with the raw clock syscalls.
//!
//! Linux serves `CLOCK_REALTIME_COARSE` and `CLOCK_MONOTONIC_COARSE` from the
//! vDSO. clock_getres(2) is one answer per clock, so the vDSO's
//! `__kernel_clock_getres` must report what the `clock_getres` syscall
//! reports for every clock it serves. clock_gettime(2) says a COARSE clock is
//! a faster, less precise version of its base clock: it is never ahead of a
//! fine read of that base clock taken after it, and MONOTONIC_COARSE never
//! goes backwards, whichever path (vDSO or syscall) answers the read.
//!
//! The vDSO functions are called directly (not through libc), so a negative
//! return is the raw kernel errno. Every reading loop is bounded by a count.

use std::ptr;

const AT_SYSINFO_EHDR: u64 = 33;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
/// Reads per ordering check.
const ROUNDS: usize = 2_000;
/// A clock id Linux does not define (it never had a static clock 10 on arm64).
const INVALID_CLOCK: libc::clockid_t = 10;

unsafe fn read_u16(address: u64) -> u16 {
    ptr::read_unaligned(address as *const u16)
}

unsafe fn read_u32(address: u64) -> u32 {
    ptr::read_unaligned(address as *const u32)
}

unsafe fn read_u64(address: u64) -> u64 {
    ptr::read_unaligned(address as *const u64)
}

unsafe fn read_i64(address: u64) -> i64 {
    ptr::read_unaligned(address as *const i64)
}

unsafe fn c_string_equals(address: u64, expected: &str) -> bool {
    for (index, byte) in expected.as_bytes().iter().copied().enumerate() {
        if *((address + index as u64) as *const u8) != byte {
            return false;
        }
    }
    *((address + expected.len() as u64) as *const u8) == 0
}

unsafe fn vdso_symbol(expected: &str) -> u64 {
    let base = libc::getauxval(AT_SYSINFO_EHDR);
    if base == 0 {
        return 0;
    }

    let program_offset = read_u64(base + 0x20);
    let program_size = u64::from(read_u16(base + 0x36));
    let program_count = u64::from(read_u16(base + 0x38));
    let mut dynamic = 0;
    for index in 0..program_count {
        let header = base + program_offset + index * program_size;
        if read_u32(header) == PT_DYNAMIC {
            dynamic = base + read_u64(header + 16);
        }
    }
    if dynamic == 0 {
        return 0;
    }

    let (mut symbols, mut strings, mut hash) = (0, 0, 0);
    loop {
        let tag = read_i64(dynamic);
        let value = read_u64(dynamic + 8);
        match tag {
            DT_SYMTAB => symbols = base + value,
            DT_STRTAB => strings = base + value,
            DT_HASH => hash = base + value,
            _ => {}
        }
        if tag == DT_NULL {
            break;
        }
        dynamic += 16;
    }
    if symbols == 0 || strings == 0 || hash == 0 {
        return 0;
    }

    let symbol_count = u64::from(read_u32(hash + 4));
    for index in 0..symbol_count {
        let symbol = symbols + index * 24;
        let name = u64::from(read_u32(symbol));
        let section = read_u16(symbol + 6);
        if name != 0 && section != 0 && c_string_equals(strings + name, expected) {
            return base + read_u64(symbol + 8);
        }
    }
    0
}

type ClockFn = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int;

fn zero() -> libc::timespec {
    libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }
}

fn nanoseconds(value: libc::timespec) -> i128 {
    i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec)
}

unsafe fn vdso_read(function: ClockFn, clock: libc::clockid_t) -> Option<i128> {
    let mut value = zero();
    (function(clock, &mut value) == 0).then(|| nanoseconds(value))
}

unsafe fn syscall_read(clock: libc::clockid_t) -> Option<i128> {
    let mut value = zero();
    (libc::syscall(libc::SYS_clock_gettime, clock, &mut value) == 0).then(|| nanoseconds(value))
}

/// Both getres paths succeed and agree exactly.
unsafe fn getres_agrees(getres: ClockFn, clock: libc::clockid_t) -> bool {
    let mut vdso = zero();
    let mut raw = zero();
    let vdso_rc = getres(clock, &mut vdso);
    let raw_rc = libc::syscall(libc::SYS_clock_getres, clock, &mut raw);
    vdso_rc == 0 && raw_rc == 0 && vdso.tv_sec == raw.tv_sec && vdso.tv_nsec == raw.tv_nsec
}

/// Consecutive vDSO reads of `clock` never decrease.
unsafe fn vdso_nondecreasing(gettime: ClockFn, clock: libc::clockid_t) -> bool {
    let Some(mut previous) = vdso_read(gettime, clock) else {
        return false;
    };
    for _ in 0..ROUNDS {
        let Some(next) = vdso_read(gettime, clock) else {
            return false;
        };
        if next < previous {
            return false;
        }
        previous = next;
    }
    true
}

/// Reads of `clock` alternating vDSO and syscall never decrease.
unsafe fn mixed_nondecreasing(gettime: ClockFn, clock: libc::clockid_t) -> bool {
    let Some(mut previous) = syscall_read(clock) else {
        return false;
    };
    for round in 0..ROUNDS {
        let next = if round % 2 == 0 {
            vdso_read(gettime, clock)
        } else {
            syscall_read(clock)
        };
        let Some(next) = next else {
            return false;
        };
        if next < previous {
            return false;
        }
        previous = next;
    }
    true
}

/// A COARSE read is never ahead of a fine read of its base clock taken after
/// it, through the vDSO and through the syscall.
unsafe fn coarse_not_after_fine(
    gettime: ClockFn,
    coarse: libc::clockid_t,
    fine: libc::clockid_t,
) -> bool {
    for round in 0..ROUNDS {
        let Some(coarse_value) = vdso_read(gettime, coarse) else {
            return false;
        };
        let fine_value = if round % 2 == 0 {
            vdso_read(gettime, fine)
        } else {
            syscall_read(fine)
        };
        let Some(fine_value) = fine_value else {
            return false;
        };
        if coarse_value > fine_value {
            return false;
        }
    }
    true
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    unsafe {
        let gettime_address = vdso_symbol("__kernel_clock_gettime");
        let getres_address = vdso_symbol("__kernel_clock_getres");
        println!("vdso_clock_gettime_resolved={}", gettime_address != 0);
        println!("vdso_clock_getres_resolved={}", getres_address != 0);
        if gettime_address == 0 || getres_address == 0 {
            std::process::exit(1);
        }
        let gettime: ClockFn = std::mem::transmute(gettime_address);
        let getres: ClockFn = std::mem::transmute(getres_address);

        for (name, clock) in [
            ("realtime", libc::CLOCK_REALTIME),
            ("monotonic", libc::CLOCK_MONOTONIC),
            ("monotonic_raw", libc::CLOCK_MONOTONIC_RAW),
            ("realtime_coarse", libc::CLOCK_REALTIME_COARSE),
            ("monotonic_coarse", libc::CLOCK_MONOTONIC_COARSE),
            ("boottime", libc::CLOCK_BOOTTIME),
        ] {
            println!(
                "getres_vdso_matches_syscall_{name}={}",
                getres_agrees(getres, clock)
            );
        }

        let mut coarse_res = zero();
        let coarse_res_rc = getres(libc::CLOCK_MONOTONIC_COARSE, &mut coarse_res);
        println!(
            "monotonic_coarse_res_subsecond_nonzero={}",
            coarse_res_rc == 0 && coarse_res.tv_sec == 0 && coarse_res.tv_nsec > 0
        );
        println!(
            "getres_vdso_null_coarse_rc={}",
            getres(libc::CLOCK_MONOTONIC_COARSE, ptr::null_mut())
        );

        println!(
            "monotonic_coarse_vdso_nondecreasing={}",
            vdso_nondecreasing(gettime, libc::CLOCK_MONOTONIC_COARSE)
        );
        println!(
            "monotonic_coarse_mixed_nondecreasing={}",
            mixed_nondecreasing(gettime, libc::CLOCK_MONOTONIC_COARSE)
        );
        println!(
            "realtime_coarse_vdso_nondecreasing={}",
            vdso_nondecreasing(gettime, libc::CLOCK_REALTIME_COARSE)
        );
        println!(
            "realtime_coarse_mixed_nondecreasing={}",
            mixed_nondecreasing(gettime, libc::CLOCK_REALTIME_COARSE)
        );
        println!(
            "monotonic_coarse_not_after_monotonic={}",
            coarse_not_after_fine(gettime, libc::CLOCK_MONOTONIC_COARSE, libc::CLOCK_MONOTONIC)
        );
        println!(
            "realtime_coarse_not_after_realtime={}",
            coarse_not_after_fine(gettime, libc::CLOCK_REALTIME_COARSE, libc::CLOCK_REALTIME)
        );

        let mut scratch = zero();
        println!(
            "vdso_gettime_invalid_rc={}",
            gettime(INVALID_CLOCK, &mut scratch)
        );
        let raw_rc = libc::syscall(libc::SYS_clock_gettime, INVALID_CLOCK, &mut scratch);
        println!("syscall_gettime_invalid_rc={raw_rc} errno={}", last_errno());
        println!(
            "vdso_getres_invalid_rc={}",
            getres(INVALID_CLOCK, &mut scratch)
        );
        let raw_rc = libc::syscall(libc::SYS_clock_getres, INVALID_CLOCK, &mut scratch);
        println!("syscall_getres_invalid_rc={raw_rc} errno={}", last_errno());
    }
}
