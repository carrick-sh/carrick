//! mlock2 and locked-memory `/proc` accounting probe. LTP mlock201/203 check
//! that `mlock2(MLOCK_ONFAULT)` succeeds and that `/proc/self/status` reports
//! the locked range exactly once. LTP mlock201 also checks `mincore` at Linux
//! page granularity, which must not leak the host page size.

use conformance_probes::{errno, report};
use std::ffi::c_void;

const PAGE: usize = 4096;
const MLOCK_ONFAULT: libc::c_long = 0x01;

#[cfg(target_arch = "aarch64")]
const SYS_MLOCK2: libc::c_long = 284;
#[cfg(target_arch = "x86_64")]
const SYS_MLOCK2: libc::c_long = 325;

fn mlock2_errno(addr: *const c_void, len: usize, flags: libc::c_long) -> i32 {
    let rc = unsafe { libc::syscall(SYS_MLOCK2, addr, len, flags) };
    if rc == 0 { 0 } else { errno() }
}

fn read_vmlck_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("VmLck:")?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

fn resident_pages(addr: *mut c_void, pages: usize) -> Option<usize> {
    let mut vec = vec![0u8; pages];
    let rc = unsafe { libc::mincore(addr, pages * PAGE, vec.as_mut_ptr()) };
    (rc == 0).then(|| vec.iter().filter(|byte| **byte & 1 != 0).count())
}

fn mlock2_mincore_counts() -> (Option<usize>, Option<usize>, Option<usize>) {
    const PAGES: usize = 8;

    let onfault_empty = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * PAGES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if onfault_empty == libc::MAP_FAILED {
        return (None, None, None);
    }
    let onfault_empty_count = if mlock2_errno(onfault_empty, PAGE * PAGES, MLOCK_ONFAULT) == 0 {
        resident_pages(onfault_empty, PAGES)
    } else {
        None
    };
    unsafe {
        libc::munmap(onfault_empty, PAGE * PAGES);
    }

    let onfault_half = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * PAGES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if onfault_half == libc::MAP_FAILED {
        return (onfault_empty_count, None, None);
    }
    for page in 0..(PAGES / 2) {
        unsafe {
            ((onfault_half as *mut u8).add(page * PAGE)).write_volatile(0);
        }
    }
    let onfault_half_count = if mlock2_errno(onfault_half, PAGE * PAGES, MLOCK_ONFAULT) == 0 {
        resident_pages(onfault_half, PAGES)
    } else {
        None
    };
    unsafe {
        libc::munmap(onfault_half, PAGE * PAGES);
    }

    let populated = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * PAGES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if populated == libc::MAP_FAILED {
        return (onfault_empty_count, onfault_half_count, None);
    }
    let populated_count = if mlock2_errno(populated, PAGE * PAGES, 0) == 0 {
        resident_pages(populated, PAGES)
    } else {
        None
    };
    unsafe {
        libc::munmap(populated, PAGE * PAGES);
    }

    (onfault_empty_count, onfault_half_count, populated_count)
}

fn main() {
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        report!(
            mlock2_onfault_ok = false,
            mlock2_vmlck_grew = false,
            mlock2_repeat_not_double = false,
            mlock2_invalid_flag_einval = false,
            mlock2_unmapped_enomem = false,
        );
        return;
    }

    let before = read_vmlck_kb();
    let onfault_errno = mlock2_errno(mapped, PAGE * 2, MLOCK_ONFAULT);
    let after_onfault = read_vmlck_kb();
    let repeat_errno = mlock2_errno(mapped, PAGE * 2, 0);
    let after_repeat = read_vmlck_kb();
    let invalid_errno = mlock2_errno(mapped, PAGE, !MLOCK_ONFAULT);

    unsafe {
        libc::munlock(mapped, PAGE * 2);
        libc::munmap(mapped, PAGE * 2);
    }
    let unmapped_errno = mlock2_errno(mapped, PAGE, 0);

    let expected_kb = (PAGE * 2 / 1024) as u64;
    let vmlck_grew = matches!(
        (before, after_onfault),
        (Some(before), Some(after)) if after.saturating_sub(before) == expected_kb
    );
    let repeat_not_double = matches!(
        (after_onfault, after_repeat),
        (Some(after_onfault), Some(after_repeat)) if after_repeat == after_onfault
    );
    let (mincore_onfault_empty, mincore_onfault_half, mincore_populated) =
        mlock2_mincore_counts();

    report!(
        mlock2_onfault_ok = onfault_errno == 0,
        mlock2_vmlck_grew = vmlck_grew,
        mlock2_repeat_not_double = repeat_errno == 0 && repeat_not_double,
        mlock2_invalid_flag_einval = invalid_errno == libc::EINVAL,
        mlock2_unmapped_enomem = unmapped_errno == libc::ENOMEM,
        mlock2_mincore_onfault_empty_pages = mincore_onfault_empty.unwrap_or(usize::MAX),
        mlock2_mincore_onfault_half_pages = mincore_onfault_half.unwrap_or(usize::MAX),
        mlock2_mincore_populated_pages = mincore_populated.unwrap_or(usize::MAX),
        mlock2_mincore_onfault_empty = mincore_onfault_empty == Some(0),
        mlock2_mincore_onfault_half = mincore_onfault_half == Some(4),
        mlock2_mincore_populated = mincore_populated == Some(8),
    );
}
