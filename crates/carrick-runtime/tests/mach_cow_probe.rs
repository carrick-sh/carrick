//! Plan 5 — Darwin COW probe (spec §5 + open probe #2).
//!
//! Question: can `mach_vm_remap(copy=TRUE)` produce a CORRECT, isolated, sparse
//! private fork snapshot of a guest region — and is it cheaper than the current
//! explicit `mincore`-gated copy?
//!
//! Carrick backs guest RAM with host `mmap(MAP_ANON|MAP_SHARED|MAP_NORESERVE)`
//! (HVF coherence forces `MAP_SHARED`). The spec suspects Darwin COW may NOT
//! isolate such shared mappings the way a true fork snapshot must. This probe
//! settles it empirically: it measures both methods and, critically, checks
//! whether a write to the SOURCE after cloning leaks into the CLONE (it must
//! NOT, for a fork snapshot to be correct).
//!
//! Run: `cargo test -p carrick-runtime --test mach_cow_probe -- --nocapture`
//! It prints findings and asserts only the correctness verdict it discovers, so
//! the result is recorded in CI without prejudging the (platform-dependent)
//! COW behavior. The plan doc records the conclusion.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::ffi::c_int;
use std::time::Instant;

// mach_vm_remap is in libSystem; libc exposes the Mach types but not this fn.
unsafe extern "C" {
    fn mach_vm_remap(
        target_task: libc::vm_map_t,
        target_address: *mut libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        mask: libc::mach_vm_offset_t,
        flags: c_int,
        src_task: libc::vm_map_t,
        src_address: libc::mach_vm_address_t,
        copy: libc::boolean_t,
        cur_protection: *mut libc::vm_prot_t,
        max_protection: *mut libc::vm_prot_t,
        inheritance: libc::vm_inherit_t,
    ) -> libc::kern_return_t;
}

const VM_FLAGS_ANYWHERE: c_int = 0x0001;
const VM_INHERIT_NONE: libc::vm_inherit_t = 2;
const KERN_SUCCESS: libc::kern_return_t = 0;
const PAGE: usize = 16 * 1024; // HVF granule

/// A guest-region-like host buffer: MAP_ANON|MAP_SHARED|MAP_NORESERVE, exactly
/// how carrick backs private guest RAM.
fn map_guest_region(len: usize) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED, "mmap guest region");
    p.cast()
}

/// Explicit mincore-gated sparse copy — carrick's current `clone_region_for_child`.
fn explicit_sparse_copy(src: *mut u8, len: usize) -> *mut u8 {
    let dst = map_guest_region(len);
    let pages = len / PAGE;
    let mut resident = vec![0u8; pages];
    let rc = unsafe { libc::mincore(src.cast(), len, resident.as_mut_ptr().cast()) };
    if rc != 0 {
        unsafe { std::ptr::copy_nonoverlapping(src, dst, len) };
        return dst;
    }
    for (i, &flag) in resident.iter().enumerate() {
        if flag & 1 != 0 {
            let off = i * PAGE;
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst.add(off), PAGE) };
        }
    }
    dst
}

/// mach_vm_remap with copy=TRUE: a (claimed COW) clone of the source.
#[allow(deprecated)] // mach_task_self_ static; mach2 dep is overkill for a probe
fn mach_remap_copy(src: *mut u8, len: usize) -> Option<*mut u8> {
    let mut target: libc::mach_vm_address_t = 0;
    let mut cur: libc::vm_prot_t = 0;
    let mut max: libc::vm_prot_t = 0;
    // Read the constant self-task port directly (the `mach_task_self()` wrapper
    // is libc-deprecated; the static is the same value).
    let task = unsafe { libc::mach_task_self_ };
    let kr = unsafe {
        mach_vm_remap(
            task,
            &mut target,
            len as libc::mach_vm_size_t,
            0,
            VM_FLAGS_ANYWHERE,
            task,
            src as libc::mach_vm_address_t,
            1, // copy = TRUE
            &mut cur,
            &mut max,
            VM_INHERIT_NONE,
        )
    };
    if kr != KERN_SUCCESS {
        eprintln!("mach_vm_remap failed: kr={kr}");
        return None;
    }
    Some(target as *mut u8)
}

#[test]
fn mach_cow_vs_explicit_snapshot_probe() {
    // A 64 MiB region with a SPARSE dirty set (every 8th page touched) — the
    // realistic shape of a forked heap/stack.
    let len = 64 * 1024 * 1024;
    let pages = len / PAGE;
    let src = map_guest_region(len);
    for i in (0..pages).step_by(8) {
        unsafe { src.add(i * PAGE).write_volatile((i & 0xff) as u8) };
    }

    // --- Method A: explicit mincore copy ---
    let t = Instant::now();
    let a = explicit_sparse_copy(src, len);
    let a_ns = t.elapsed().as_nanos();
    // Verify it copied the dirty pages.
    for i in (0..pages).step_by(8) {
        assert_eq!(
            unsafe { a.add(i * PAGE).read_volatile() },
            (i & 0xff) as u8,
            "explicit copy preserved dirty page {i}"
        );
    }

    // --- Method B: mach_vm_remap(copy=TRUE) ---
    let t = Instant::now();
    let b = mach_remap_copy(src, len);
    let b_ns = t.elapsed().as_nanos();

    println!("PROBE explicit_mincore_copy: {a_ns} ns");
    match b {
        None => {
            println!("PROBE mach_vm_remap(copy): UNAVAILABLE/failed → keep explicit snapshot");
        }
        Some(b) => {
            println!("PROBE mach_vm_remap(copy):    {b_ns} ns");
            // Clone must reflect the source's current contents.
            for i in (0..pages).step_by(8) {
                assert_eq!(
                    unsafe { b.add(i * PAGE).read_volatile() },
                    (i & 0xff) as u8,
                    "remap clone saw source dirty page {i}"
                );
            }
            // CORRECTNESS GATE: mutate the SOURCE after cloning. For a valid
            // fork snapshot the clone MUST NOT observe it (write isolation).
            // On a MAP_SHARED source, COW may or may not hold — that's the
            // open question.
            let probe_page = 0usize;
            unsafe { src.add(probe_page * PAGE).write_volatile(0xAB) };
            let clone_sees_source_write =
                unsafe { b.add(probe_page * PAGE).read_volatile() } == 0xAB;
            println!(
                "PROBE write-isolation: source mutation {} into clone (isolated={})",
                if clone_sees_source_write {
                    "LEAKED"
                } else {
                    "did NOT leak"
                },
                !clone_sees_source_write,
            );
            // Record the verdict. If the clone is NOT isolated, mach_vm_remap is
            // unsuitable as a fork snapshot for MAP_SHARED guest RAM and the
            // explicit snapshot must remain (the spec's fallback). We assert the
            // probe RAN and produced a definitive verdict either way.
            println!(
                "PROBE VERDICT: mach_vm_remap COW {} for MAP_SHARED guest RAM ({}x vs explicit)",
                if clone_sees_source_write {
                    "is UNSUITABLE (no write isolation) → keep explicit snapshot"
                } else {
                    "ISOLATES correctly → candidate (needs HVF-coherence integration test next)"
                },
                if b_ns > 0 {
                    format!("{:.2}", a_ns as f64 / b_ns as f64)
                } else {
                    "inf".to_string()
                },
            );
            unsafe { libc::munmap(b.cast(), len) };
        }
    }

    unsafe {
        libc::munmap(a.cast(), len);
        libc::munmap(src.cast(), len);
    }
}
