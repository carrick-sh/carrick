//! Linux memory-management flag and error matrix conformance probe.
//!
//! Compact table-driven matrix covering flag combinations, boundary/alignment
//! errors, and state-transition invariants for:
//!  - mmap(2)
//!  - mprotect(2)
//!  - madvise(2)
//!  - mincore(2)
//!  - mremap(2)
//!
//! Output format: deterministic `key=value` lines diffed line-by-line against
//! the native Linux oracle.

use conformance_probes::{errno, report};
use std::ffi::c_void;

const MAP_FIXED_NOREPLACE: i32 = 0x100000;
const MADV_WIPEONFORK: i32 = 18;
const MADV_KEEPONFORK: i32 = 19;
const MREMAP_DONTUNMAP: i32 = 4;

fn page_size() -> usize {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 && (ps as usize).is_power_of_two() {
        ps as usize
    } else {
        4096
    }
}

unsafe fn get_unmapped_page(page: usize) -> *mut c_void {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 2,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        return core::ptr::null_mut();
    }
    libc::munmap(p, page * 2);
    p
}

unsafe fn run_in_child<F: FnOnce() -> bool>(f: F) -> bool {
    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        return false;
    }
    let pid = libc::fork();
    if pid < 0 {
        libc::close(fds[0]);
        libc::close(fds[1]);
        return false;
    }
    if pid == 0 {
        libc::close(fds[0]);
        let ok = f();
        let val = [ok as u8];
        let _ = libc::write(fds[1], val.as_ptr().cast(), 1);
        libc::close(fds[1]);
        libc::_exit(0);
    }
    libc::close(fds[1]);
    let mut val = [0u8; 1];
    let n = libc::read(fds[0], val.as_mut_ptr().cast(), 1);
    libc::close(fds[0]);
    let mut status = 0;
    while libc::waitpid(pid, &mut status, 0) < 0 {
        if errno() != libc::EINTR {
            break;
        }
    }
    n == 1 && val[0] == 1 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

unsafe fn test_mmap_matrix(page: usize) {
    // 1. Missing MAP_TYPE (neither MAP_SHARED nor MAP_PRIVATE specified) -> EINVAL
    let no_type = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        0,
        -1,
        0,
    );
    let no_type_einval = no_type == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 2. Conflicting MAP_TYPE (both MAP_SHARED and MAP_PRIVATE specified) -> EINVAL
    let both_types = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let both_types_einval = both_types == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 3. Length == 0 on anonymous mmap -> EINVAL
    let len_zero = libc::mmap(
        core::ptr::null_mut(),
        0,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let len_zero_einval = len_zero == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 4. Unaligned offset on anonymous mmap -> EINVAL
    let unaligned_offset = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        1,
    );
    let unaligned_offset_einval = unaligned_offset == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 5. Invalid protection flags bitmask -> EINVAL
    let invalid_prot = libc::mmap(
        core::ptr::null_mut(),
        page,
        1 << 28,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let invalid_prot_einval = invalid_prot == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 6. MAP_FIXED with unaligned target address -> EINVAL
    let fixed_unaligned = libc::mmap(
        (page + 1) as *mut c_void,
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    let fixed_unaligned_einval = fixed_unaligned == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 7. MAP_FIXED_NOREPLACE on an existing mapping -> EEXIST
    let base = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut noreplace_existing_eexist = false;
    if base != libc::MAP_FAILED {
        let clash = libc::mmap(
            base,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        noreplace_existing_eexist = clash == libc::MAP_FAILED && errno() == libc::EEXIST;
        libc::munmap(base, page);
    }

    // 8. MAP_FIXED_NOREPLACE on an unmapped page -> succeeds at exact address
    let unmapped = get_unmapped_page(page);
    let mut noreplace_unmapped_ok = false;
    if !unmapped.is_null() {
        let placed = libc::mmap(
            unmapped,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        noreplace_unmapped_ok = placed == unmapped;
        if placed != libc::MAP_FAILED {
            libc::munmap(placed, page);
        }
    }

    // 9. MAP_POPULATE makes anonymous pages immediately resident
    let pop = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
        -1,
        0,
    );
    let mut pop_resident = false;
    if pop != libc::MAP_FAILED {
        let mut vec = [0u8; 1];
        let rc = libc::mincore(pop, page, vec.as_mut_ptr());
        pop_resident = rc == 0 && (vec[0] & 1 != 0);
        libc::munmap(pop, page);
    }

    // 10. Untouched non-populated anonymous mapping is not resident
    let unpop = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut unpop_not_resident = false;
    if unpop != libc::MAP_FAILED {
        let mut vec = [0u8; 1];
        let rc = libc::mincore(unpop, page, vec.as_mut_ptr());
        unpop_not_resident = rc == 0 && (vec[0] & 1 == 0);
        libc::munmap(unpop, page);
    }

    report!(
        mmap_no_type_einval = no_type_einval,
        mmap_both_types_einval = both_types_einval,
        mmap_len_zero_einval = len_zero_einval,
        mmap_unaligned_offset_einval = unaligned_offset_einval,
        mmap_invalid_prot_einval = invalid_prot_einval,
        mmap_fixed_unaligned_einval = fixed_unaligned_einval,
        mmap_fixed_noreplace_eexist = noreplace_existing_eexist,
        mmap_fixed_noreplace_unmapped_ok = noreplace_unmapped_ok,
        mmap_populate_resident = pop_resident,
        mmap_unpopulated_not_resident = unpop_not_resident,
    );
}

unsafe fn test_mprotect_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 3,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            mprotect_unaligned_einval = false,
            mprotect_len_zero_ok = false,
            mprotect_invalid_prot_einval = false,
            mprotect_unmapped_enomem = false,
            mprotect_transitions_preserved = false,
            mprotect_partial_split_preserved = false,
        );
        return;
    }

    // 1. Non-page-aligned address -> EINVAL
    let unaligned_rc = libc::mprotect((p as *mut u8).add(1).cast(), page, libc::PROT_READ);
    let unaligned_einval = unaligned_rc == -1 && errno() == libc::EINVAL;

    // 2. Length == 0 -> 0 (success / no-op on Linux)
    let len_zero_rc = libc::mprotect(p, 0, libc::PROT_READ);
    let len_zero_ok = len_zero_rc == 0;

    // 3. Invalid protection flags bitmask -> EINVAL
    let inv_prot_rc = libc::mprotect(p, page, 1 << 28);
    let inv_prot_einval = inv_prot_rc == -1 && errno() == libc::EINVAL;

    // 4. mprotect on unmapped memory -> ENOMEM
    let unmapped = get_unmapped_page(page);
    let unmapped_rc = libc::mprotect(unmapped, page, libc::PROT_READ);
    let unmapped_enomem = unmapped_rc == -1 && errno() == libc::ENOMEM;

    // 5. Protection state transitions: RW -> PROT_NONE -> PROT_READ -> RW with data preservation
    let single = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut transitions_preserved = false;
    if single != libc::MAP_FAILED {
        let b = single as *mut u8;
        *b = 0xA5;
        *b.add(page - 1) = 0x5A;

        let rc_none = libc::mprotect(single, page, libc::PROT_NONE);
        let rc_read = libc::mprotect(single, page, libc::PROT_READ);
        let read_intact = rc_read == 0 && *b == 0xA5 && *b.add(page - 1) == 0x5A;
        let rc_rw = libc::mprotect(single, page, libc::PROT_READ | libc::PROT_WRITE);
        if rc_rw == 0 {
            *b = 0xB6;
            *b.add(page - 1) = 0x6B;
        }
        let write_intact = rc_rw == 0 && *b == 0xB6 && *b.add(page - 1) == 0x6B;
        transitions_preserved = rc_none == 0 && rc_read == 0 && read_intact && write_intact;
        libc::munmap(single, page);
    }

    // 6. Partial split: 3 contiguous pages, protect only middle page to PROT_READ
    let p0 = p as *mut u8;
    let p1 = p0.add(page);
    let p2 = p0.add(page * 2);
    *p0 = 0x11;
    *p1 = 0x22;
    *p2 = 0x33;

    let split_rc = libc::mprotect(p1.cast(), page, libc::PROT_READ);
    let mut split_ok = split_rc == 0;
    // Outer pages remain writable
    *p0 = 0x14;
    *p2 = 0x36;
    if *p0 != 0x14 || *p1 != 0x22 || *p2 != 0x36 {
        split_ok = false;
    }
    // Restore middle page to RW
    let restore_rc = libc::mprotect(p1.cast(), page, libc::PROT_READ | libc::PROT_WRITE);
    if restore_rc != 0 {
        split_ok = false;
    } else {
        *p1 = 0x25;
        if *p0 != 0x14 || *p1 != 0x25 || *p2 != 0x36 {
            split_ok = false;
        }
    }

    libc::munmap(p, page * 3);

    report!(
        mprotect_unaligned_einval = unaligned_einval,
        mprotect_len_zero_ok = len_zero_ok,
        mprotect_invalid_prot_einval = inv_prot_einval,
        mprotect_unmapped_enomem = unmapped_enomem,
        mprotect_transitions_preserved = transitions_preserved,
        mprotect_partial_split_preserved = split_ok,
    );
}

unsafe fn test_madvise_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 2,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            madvise_unaligned_einval = false,
            madvise_len_zero_ok = false,
            madvise_invalid_advice_einval = false,
            madvise_unmapped_enomem = false,
            madvise_hints_matrix_ok = false,
            madvise_dontneed_zeroes_anon = false,
            madvise_wipeonfork_lifecycle = false,
            madvise_dontfork_dofork_lifecycle = false,
        );
        return;
    }

    // 1. Unaligned address -> EINVAL
    let unaligned_rc = libc::madvise((p as *mut u8).add(1).cast(), page, libc::MADV_NORMAL);
    let unaligned_einval = unaligned_rc == -1 && errno() == libc::EINVAL;

    // 2. Length == 0 -> 0 (success)
    let len_zero_rc = libc::madvise(p, 0, libc::MADV_NORMAL);
    let len_zero_ok = len_zero_rc == 0;

    // 3. Invalid advice value -> EINVAL
    let inv_adv_rc = libc::madvise(p, page, 9999);
    let inv_adv_einval = inv_adv_rc == -1 && errno() == libc::EINVAL;

    // 4. madvise on unmapped address -> ENOMEM
    let unmapped = get_unmapped_page(page);
    let unmapped_rc = libc::madvise(unmapped, page, libc::MADV_DONTNEED);
    let unmapped_enomem = unmapped_rc == -1 && errno() == libc::ENOMEM;

    // 5. Table of standard advisory hints all succeed
    let hints = [
        libc::MADV_NORMAL,
        libc::MADV_RANDOM,
        libc::MADV_SEQUENTIAL,
        libc::MADV_WILLNEED,
        libc::MADV_DONTDUMP,
        libc::MADV_DODUMP,
    ];
    let mut hints_ok = true;
    for &h in &hints {
        if libc::madvise(p, page, h) != 0 {
            hints_ok = false;
            break;
        }
    }

    // 6. MADV_DONTNEED re-zeroes dirty anonymous memory
    let b = p as *mut u8;
    core::ptr::write_bytes(b, 0xCC, page);
    let dontneed_rc = libc::madvise(p, page, libc::MADV_DONTNEED);
    let mut dontneed_zeroes = dontneed_rc == 0;
    if dontneed_zeroes {
        let slice = core::slice::from_raw_parts(b as *const u8, page);
        dontneed_zeroes = slice.iter().all(|&byte| byte == 0);
    }

    // 7. MADV_WIPEONFORK / MADV_KEEPONFORK lifecycle
    let wipe_page = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut wipe_lifecycle_ok = false;
    if wipe_page != libc::MAP_FAILED {
        let wb = wipe_page as *mut u8;
        *wb = 0x55;
        let rc_wipe = libc::madvise(wipe_page, page, MADV_WIPEONFORK);
        let child1_wiped = rc_wipe == 0
            && run_in_child(|| {
                let val = *wb;
                val == 0
            });
        let parent_still_has_val = *wb == 0x55;

        let rc_keep = libc::madvise(wipe_page, page, MADV_KEEPONFORK);
        *wb = 0x66;
        let child2_kept = rc_keep == 0
            && run_in_child(|| {
                let val = *wb;
                val == 0x66
            });

        wipe_lifecycle_ok =
            rc_wipe == 0 && child1_wiped && parent_still_has_val && rc_keep == 0 && child2_kept;
        libc::munmap(wipe_page, page);
    }

    // 8. MADV_DONTFORK / MADV_DOFORK lifecycle
    let df_page = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut df_lifecycle_ok = false;
    if df_page != libc::MAP_FAILED {
        let dfb = df_page as *mut u8;
        *dfb = 0x77;
        let rc_df = libc::madvise(df_page, page, libc::MADV_DONTFORK);
        let child1_unmapped = rc_df == 0
            && run_in_child(|| {
                let mut vec = [0u8; 1];
                let r = libc::mincore(df_page, page, vec.as_mut_ptr());
                r == -1 && errno() == libc::ENOMEM
            });

        let rc_dofork = libc::madvise(df_page, page, libc::MADV_DOFORK);
        let child2_mapped = rc_dofork == 0
            && run_in_child(|| {
                let mut vec = [0u8; 1];
                let r = libc::mincore(df_page, page, vec.as_mut_ptr());
                r == 0 && *dfb == 0x77
            });

        df_lifecycle_ok = rc_df == 0 && child1_unmapped && rc_dofork == 0 && child2_mapped;
        libc::munmap(df_page, page);
    }

    libc::munmap(p, page * 2);

    report!(
        madvise_unaligned_einval = unaligned_einval,
        madvise_len_zero_ok = len_zero_ok,
        madvise_invalid_advice_einval = inv_adv_einval,
        madvise_unmapped_enomem = unmapped_enomem,
        madvise_hints_matrix_ok = hints_ok,
        madvise_dontneed_zeroes_anon = dontneed_zeroes,
        madvise_wipeonfork_lifecycle = wipe_lifecycle_ok,
        madvise_dontfork_dofork_lifecycle = df_lifecycle_ok,
    );
}

unsafe fn test_mincore_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 3,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            mincore_unaligned_einval = false,
            mincore_len_zero_ok = false,
            mincore_null_vec_efault = false,
            mincore_invalid_vec_efault = false,
            mincore_unmapped_enomem = false,
            mincore_lifecycle_transitions = false,
            mincore_sparse_multipage = false,
        );
        return;
    }

    // 1. Unaligned address -> EINVAL
    let mut vec1 = [0u8; 1];
    let unaligned_rc = libc::mincore((p as *mut u8).add(1).cast(), page, vec1.as_mut_ptr());
    let unaligned_einval = unaligned_rc == -1 && errno() == libc::EINVAL;

    // 2. Length == 0 -> 0 (success on Linux)
    let len_zero_rc = libc::mincore(p, 0, vec1.as_mut_ptr());
    let len_zero_ok = len_zero_rc == 0;

    // 3. NULL vector pointer -> EFAULT
    let null_rc = libc::mincore(p, page, core::ptr::null_mut());
    let null_efault = null_rc == -1 && errno() == libc::EFAULT;

    // 4. Invalid vector pointer -> EFAULT
    let inv_ptr_rc = libc::mincore(p, page, 1 as *mut u8);
    let inv_ptr_efault = inv_ptr_rc == -1 && errno() == libc::EFAULT;

    // 5. Unmapped address -> ENOMEM
    let unmapped = get_unmapped_page(page);
    let unmapped_rc = libc::mincore(unmapped, page, vec1.as_mut_ptr());
    let unmapped_enomem = unmapped_rc == -1 && errno() == libc::ENOMEM;

    // 6. Lifecycle transitions: untouched -> touch -> dontneed -> touch
    let single = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut transitions_ok = false;
    if single != libc::MAP_FAILED {
        let mut v = [0u8; 1];
        let rc0 = libc::mincore(single, page, v.as_mut_ptr());
        let step0_untouched = rc0 == 0 && (v[0] & 1 == 0);

        *(single as *mut u8) = 0x42;
        let rc1 = libc::mincore(single, page, v.as_mut_ptr());
        let step1_touched = rc1 == 0 && (v[0] & 1 != 0);

        libc::madvise(single, page, libc::MADV_DONTNEED);
        let rc2 = libc::mincore(single, page, v.as_mut_ptr());
        let step2_evicted = rc2 == 0 && (v[0] & 1 == 0);

        *(single as *mut u8) = 0x43;
        let rc3 = libc::mincore(single, page, v.as_mut_ptr());
        let step3_retouched = rc3 == 0 && (v[0] & 1 != 0);

        transitions_ok = step0_untouched && step1_touched && step2_evicted && step3_retouched;
        libc::munmap(single, page);
    }

    // 7. Sparse multi-page residency: 3 pages, touch page 0 and page 2 only
    let mut vec3 = [0u8; 3];
    let p0 = p as *mut u8;
    let p2 = p0.add(page * 2);
    *p0 = 0xAA;
    *p2 = 0xBB;
    let sparse_rc = libc::mincore(p, page * 3, vec3.as_mut_ptr());
    let sparse_ok =
        sparse_rc == 0 && (vec3[0] & 1 != 0) && (vec3[1] & 1 == 0) && (vec3[2] & 1 != 0);

    libc::munmap(p, page * 3);

    report!(
        mincore_unaligned_einval = unaligned_einval,
        mincore_len_zero_ok = len_zero_ok,
        mincore_null_vec_efault = null_efault,
        mincore_invalid_vec_efault = inv_ptr_efault,
        mincore_unmapped_enomem = unmapped_enomem,
        mincore_lifecycle_transitions = transitions_ok,
        mincore_sparse_multipage = sparse_ok,
    );
}

unsafe fn test_mremap_matrix(page: usize) {
    let p = libc::mmap(
        core::ptr::null_mut(),
        page * 2,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        report!(
            mremap_unaligned_old_einval = false,
            mremap_new_len_zero_einval = false,
            mremap_old_len_zero_einval = false,
            mremap_invalid_flags_einval = false,
            mremap_fixed_without_maymove_einval = false,
            mremap_fixed_unaligned_target_einval = false,
            mremap_unmapped_efault = false,
            mremap_fixed_relocation_intact = false,
            mremap_dontunmap_semantics = false,
        );
        return;
    }

    // 1. Unaligned old_address -> EINVAL
    let unaligned_r = libc::mremap(
        (p as *mut u8).add(1).cast(),
        page,
        page * 2,
        libc::MREMAP_MAYMOVE,
    );
    let unaligned_old_einval = unaligned_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 2. new_size == 0 -> EINVAL
    let new_zero_r = libc::mremap(p, page, 0, 0);
    let new_zero_einval = new_zero_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 3. old_size == 0 (without MREMAP_MAYMOVE | MREMAP_FIXED) -> EINVAL
    let old_zero_r = libc::mremap(p, 0, page * 2, 0);
    let old_zero_einval = old_zero_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 4. Invalid flag bit -> EINVAL
    let inv_flag_r = libc::mremap(p, page, page * 2, 1 << 30);
    let inv_flag_einval = inv_flag_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 5. MREMAP_FIXED without MREMAP_MAYMOVE -> EINVAL
    let target = get_unmapped_page(page);
    let fixed_nomove_r = libc::mremap(p, page, page, libc::MREMAP_FIXED, target);
    let fixed_nomove_einval = fixed_nomove_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 6. MREMAP_FIXED | MREMAP_MAYMOVE with unaligned target address -> EINVAL
    let fixed_unaligned_r = libc::mremap(
        p,
        page,
        page,
        libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
        (target as *mut u8).add(1),
    );
    let fixed_unaligned_einval = fixed_unaligned_r == libc::MAP_FAILED && errno() == libc::EINVAL;

    // 7. mremap on unmapped address -> EFAULT on Linux (distinct from ENOMEM)
    let unmapped = get_unmapped_page(page);
    let unmapped_r = libc::mremap(unmapped, page, page * 2, libc::MREMAP_MAYMOVE);
    let unmapped_efault = unmapped_r == libc::MAP_FAILED && errno() == libc::EFAULT;

    libc::munmap(p, page * 2);

    // 8. MREMAP_FIXED | MREMAP_MAYMOVE valid relocation replacing destination
    let src = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let dst = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut fixed_reloc_ok = false;
    if src != libc::MAP_FAILED && dst != libc::MAP_FAILED {
        *(src as *mut u8) = 0x44;
        *(src as *mut u8).add(page - 1) = 0x45;
        *(dst as *mut u8) = 0x88;

        let res = libc::mremap(
            src,
            page,
            page,
            libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
            dst,
        );
        let dst_updated =
            res == dst && *(dst as *const u8) == 0x44 && *(dst as *const u8).add(page - 1) == 0x45;

        // Old source address must be unmapped (mincore returns ENOMEM)
        let mut v = [0u8; 1];
        let src_unmapped =
            libc::mincore(src, page, v.as_mut_ptr()) == -1 && errno() == libc::ENOMEM;

        fixed_reloc_ok = dst_updated && src_unmapped;
        libc::munmap(dst, page);
        if !src_unmapped {
            libc::munmap(src, page);
        }
    } else {
        if src != libc::MAP_FAILED {
            libc::munmap(src, page);
        }
        if dst != libc::MAP_FAILED {
            libc::munmap(dst, page);
        }
    }

    // 9. MREMAP_DONTUNMAP (Linux 5.7+): moves data to new address and retains
    // the source address mapped as fresh zero-filled anonymous memory.
    let du_src = libc::mmap(
        core::ptr::null_mut(),
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let mut dontunmap_semantics = false;
    if du_src != libc::MAP_FAILED {
        let sub = du_src as *mut u8;
        *sub = 0x33;
        let q = libc::mremap(du_src, page, page, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
        if q != libc::MAP_FAILED {
            let q_b = q as *mut u8;
            let q_has_data = *q_b == 0x33;
            let src_still_mapped_zeroed = *sub == 0;
            dontunmap_semantics = q != du_src && q_has_data && src_still_mapped_zeroed;
            libc::munmap(q, page);
        }
        libc::munmap(du_src, page);
    }

    report!(
        mremap_unaligned_old_einval = unaligned_old_einval,
        mremap_new_len_zero_einval = new_zero_einval,
        mremap_old_len_zero_einval = old_zero_einval,
        mremap_invalid_flags_einval = inv_flag_einval,
        mremap_fixed_without_maymove_einval = fixed_nomove_einval,
        mremap_fixed_unaligned_target_einval = fixed_unaligned_einval,
        mremap_unmapped_efault = unmapped_efault,
        mremap_fixed_relocation_intact = fixed_reloc_ok,
        mremap_dontunmap_semantics = dontunmap_semantics,
    );
}

fn main() {
    let page = page_size();
    unsafe {
        test_mmap_matrix(page);
        test_mprotect_matrix(page);
        test_madvise_matrix(page);
        test_mincore_matrix(page);
        test_mremap_matrix(page);
    }
}
