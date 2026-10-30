//! Position-independent vDSO `__kernel_getrandom` blob (P2). Compiled to a flat,
//! zero-relocation aarch64 binary by build-vdso-getrandom.sh and embedded into
//! crates/carrick-mem/src/vdso.rs. The cryptographic core (ChaCha20 + the
//! reseed/ratchet state machine) is shared verbatim with carrick-mem's
//! host-tested module — see vdso_getrandom_chacha.rs — so the security logic is
//! KAT/property-verified, not re-implemented here.
//!
//! This wrapper supplies only the freestanding pieces a vDSO needs: the QUERY
//! protocol, the getrandom(2) reseed syscall, the published generation read from
//! carrick's vvar page, and freestanding mem* (the compiler may emit calls for
//! slice copies; they resolve PC-relative within the linked blob).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), allow(internal_features))]
#![cfg_attr(
    test,
    allow(
        clippy::missing_safety_doc,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::undocumented_unsafe_blocks
    )
)]

#[cfg(not(test))]
#[path = "../../carrick-mem/src/vdso_getrandom_chacha.rs"]
mod core_impl;
#[cfg(test)]
use super::vdso_getrandom_chacha::getrandom_fill;
#[cfg(not(test))]
use core_impl::getrandom_fill;

// --- freestanding mem* (resolved PC-relative within the blob after linking) ---
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        // SAFETY: freestanding libc primitive; caller guarantees valid ranges.
        unsafe {
            *dst.add(i) = *src.add(i);
        }
        i += 1;
    }
    dst
}
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        // SAFETY: freestanding libc primitive; caller guarantees valid range.
        unsafe {
            *dst.add(i) = c as u8;
        }
        i += 1;
    }
    dst
}
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            // SAFETY: freestanding libc primitive; caller guarantees valid ranges.
            unsafe {
                *dst.add(i) = *src.add(i);
            }
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            // SAFETY: freestanding libc primitive; caller guarantees valid ranges.
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
    }
    dst
}
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        // SAFETY: freestanding libc primitive; caller guarantees valid ranges.
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

/// getrandom(2) syscall (aarch64 __NR_getrandom = 278).
#[cfg(not(test))]
unsafe fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    // SAFETY: invokes the Linux aarch64 `getrandom(2)` syscall inside the guest.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 278usize,
            inout("x0") buf as usize => ret,
            in("x1") len,
            in("x2") flags as usize,
            options(nostack),
        );
    }
    ret
}

#[cfg(test)]
unsafe fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> isize {
    if flags != 0 {
        return -22; // -EINVAL
    }
    if len == 0 {
        return 0;
    }
    if buf.is_null() {
        return -14; // -EFAULT
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    for (i, byte) in slice.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(0xA5);
    }
    len as isize
}

/// carrick publishes a u64 RNG generation counter in its vvar page at
/// LINUX_VVAR_BASE (0x2E_0000_0000) + 24, bumping it on fork so a child's cached
/// ChaCha batch is invalidated. Read it relocation-free (movz immediate).
#[cfg(not(test))]
unsafe fn rng_generation() -> u64 {
    let g: u64;
    // SAFETY: reads the 8-byte generation counter from the mapped vvar page.
    unsafe {
        core::arch::asm!(
            "movz {t}, #0x2E, lsl #32",
            "ldr {g}, [{t}, #24]",
            t = out(reg) _,
            g = out(reg) g,
            options(nostack, readonly),
        );
    }
    g
}

#[cfg(test)]
unsafe fn rng_generation() -> u64 {
    1
}

/// Construct a mutable byte slice from C `(ptr, len)` arguments.
///
/// In C, `(NULL, 0)` is a valid zero-length buffer, whereas
/// `core::slice::from_raw_parts_mut(ptr, 0)` requires a non-null pointer and
/// aborts under `ub_checks` / `debug_assertions`. Returns `Some(&mut [])` when
/// `len == 0` without touching `ptr`, and `None` when `ptr` is null (or `len`
/// exceeds `isize::MAX`) so the caller can fall back to the kernel syscall
/// (`-EFAULT`).
#[inline]
unsafe fn slice_from_c_parts_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() || len > isize::MAX as usize {
        return None;
    }
    // SAFETY: `ptr` is non-null, `u8` has alignment 1, and `len <= isize::MAX`.
    Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

/// `ssize_t __kernel_getrandom(void *buffer, size_t len, unsigned int flags,
///                             void *opaque_state, size_t opaque_len)`.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn __kernel_getrandom(
    buffer: *mut u8,
    len: usize,
    flags: u32,
    opaque_state: *mut u8,
    opaque_len: usize,
) -> isize {
    // QUERY mode: opaque_len == ~0UL. Fill struct vgetrandom_opaque_params.
    if opaque_len == usize::MAX {
        let p = opaque_state as *mut u32;
        // SAFETY: caller in QUERY mode passes a valid `vgetrandom_opaque_params` pointer.
        unsafe {
            *p.add(0) = 144; // size_of_opaque_state
            *p.add(1) = 3; // mmap_prot  = PROT_READ|PROT_WRITE
            *p.add(2) = 0x28; // mmap_flags = MAP_ANONYMOUS|MAP_DROPPABLE
            let mut i = 3;
            while i < 16 {
                *p.add(i) = 0; // reserved[13]
                i += 1;
            }
        }
        return 0;
    }

    // Punt to the kernel for: any nonzero flag (GRND_NONBLOCK must trap; be
    // conservative and punt GRND_RANDOM/INSECURE too), and a missing/short state.
    if flags != 0 || opaque_state.is_null() || opaque_len < 144 {
        // SAFETY: forwards raw C arguments to the kernel `getrandom(2)` syscall.
        return unsafe { sys_getrandom(buffer, len, flags) };
    }

    // Userspace ChaCha fast path. carrick stamps a per-process generation (host
    // PID) into the vvar — in populate_vdso_data_page AND, critically, in the
    // fork-child branch of HvfTrapEngine::fork (so a forked child reads its OWN
    // generation, not the parent's COW-inherited one) — which makes getrandom_fill
    // reseed on fork instead of reusing the parent's keystream. Verified
    // fork-safe by conformance-probes/getrandomvdsofork (child_reused=false).
    const FAST_PATH: bool = true;
    if FAST_PATH {
        // SAFETY: `slice_from_c_parts_mut` handles `(NULL, 0)` without building
        // a slice from a null pointer and returns `None` for `(NULL, len > 0)`.
        if let Some(buf) = unsafe { slice_from_c_parts_mut(buffer, len) } {
            if buf.is_empty() {
                return 0;
            }
            // SAFETY: `opaque_state` is non-null and `opaque_len >= 144`.
            let state = unsafe { &mut *(opaque_state as *mut [u8; 144]) };
            // SAFETY: reads the vvar generation counter mapped by carrick.
            let generation = unsafe { rng_generation() };
            if getrandom_fill(state, buf, generation, |key| {
                // SAFETY: `key` is a stack-allocated 32-byte array.
                unsafe { sys_getrandom(key.as_mut_ptr(), 32, 0) == 32 }
            }) {
                return len as isize;
            }
            // else: reseed failed → fall through to the syscall (buf untouched).
        }
    }
    // SAFETY: forwards raw C arguments to the kernel `getrandom(2)` syscall.
    unsafe { sys_getrandom(buffer, len, flags) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_getrandom_null_zero_len_does_not_trip_ub_checks() {
        const {
            assert!(
                cfg!(debug_assertions),
                "unit test must build with debug assertions enabled"
            );
        }
        let mut state = [0u8; 144];
        let ret = unsafe {
            __kernel_getrandom(core::ptr::null_mut(), 0, 0, state.as_mut_ptr(), state.len())
        };
        assert_eq!(ret, 0);
        assert_eq!(
            state, [0u8; 144],
            "zero-length call must not mutate or seed opaque state"
        );

        let empty = unsafe { slice_from_c_parts_mut(core::ptr::null_mut(), 0) }
            .expect("zero-length null pointer must yield an empty slice");
        assert!(empty.is_empty());
    }

    #[test]
    fn kernel_getrandom_null_nonzero_len_falls_back_to_syscall_efault() {
        let mut state = [0u8; 144];
        let ret = unsafe {
            __kernel_getrandom(
                core::ptr::null_mut(),
                32,
                0,
                state.as_mut_ptr(),
                state.len(),
            )
        };
        assert_eq!(ret, -14);
        assert!(unsafe { slice_from_c_parts_mut(core::ptr::null_mut(), 32) }.is_none());
    }

    #[test]
    fn kernel_getrandom_valid_buffer_fills_bytes() {
        let mut state = [0u8; 144];
        let mut buf = [0u8; 32];
        let ret = unsafe {
            __kernel_getrandom(
                buf.as_mut_ptr(),
                buf.len(),
                0,
                state.as_mut_ptr(),
                state.len(),
            )
        };
        assert_eq!(ret, 32);
        assert_ne!(buf, [0u8; 32]);
    }
}
