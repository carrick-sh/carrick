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
#![no_std]
#![no_main]
#![allow(internal_features)]

#[path = "../../carrick-mem/src/vdso_getrandom_chacha.rs"]
mod core_impl;
use core_impl::getrandom_fill;

// --- freestanding mem* (resolved PC-relative within the blob after linking) ---
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    dst
}
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dst.add(i) = c as u8;
        i += 1;
    }
    dst
}
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = (*a.add(i), *b.add(i));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

/// getrandom(2) syscall (aarch64 __NR_getrandom = 278).
unsafe fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    core::arch::asm!(
        "svc #0",
        in("x8") 278usize,
        inout("x0") buf as usize => ret,
        in("x1") len,
        in("x2") flags as usize,
        options(nostack),
    );
    ret
}

/// carrick publishes a u64 RNG generation counter in its vvar page at
/// LINUX_VVAR_BASE (0x2E_0000_0000) + 24, bumping it on fork so a child's cached
/// ChaCha batch is invalidated. Read it relocation-free (movz immediate).
unsafe fn rng_generation() -> u64 {
    let g: u64;
    core::arch::asm!(
        "movz {t}, #0x2E, lsl #32",
        "ldr {g}, [{t}, #24]",
        t = out(reg) _,
        g = out(reg) g,
        options(nostack, readonly),
    );
    g
}

/// `ssize_t __kernel_getrandom(void *buffer, size_t len, unsigned int flags,
///                             void *opaque_state, size_t opaque_len)`.
#[no_mangle]
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
        *p.add(0) = 144; // size_of_opaque_state
        *p.add(1) = 3; // mmap_prot  = PROT_READ|PROT_WRITE
        *p.add(2) = 0x28; // mmap_flags = MAP_ANONYMOUS|MAP_DROPPABLE
        let mut i = 3;
        while i < 16 {
            *p.add(i) = 0; // reserved[13]
            i += 1;
        }
        return 0;
    }

    // Punt to the kernel for: any nonzero flag (GRND_NONBLOCK must trap; be
    // conservative and punt GRND_RANDOM/INSECURE too), and a missing/short state.
    if flags != 0 || opaque_state.is_null() || opaque_len < 144 {
        return sys_getrandom(buffer, len, flags);
    }

    // Userspace ChaCha fast path. carrick stamps a per-process generation (host
    // PID) into the vvar — in populate_vdso_data_page AND, critically, in the
    // fork-child branch of HvfTrapEngine::fork (so a forked child reads its OWN
    // generation, not the parent's COW-inherited one) — which makes getrandom_fill
    // reseed on fork instead of reusing the parent's keystream. Verified
    // fork-safe by conformance-probes/getrandomvdsofork (child_reused=false).
    const FAST_PATH: bool = true;
    if FAST_PATH {
        let state = &mut *(opaque_state as *mut [u8; 144]);
        let buf = core::slice::from_raw_parts_mut(buffer, len);
        let generation = rng_generation();
        if getrandom_fill(state, buf, generation, |key| {
            sys_getrandom(key.as_mut_ptr(), 32, 0) == 32
        }) {
            return len as isize;
        }
        // else: reseed failed → fall through to the syscall (buf untouched).
    }
    sys_getrandom(buffer, len, flags)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
