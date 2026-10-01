//! A fresh executable page runs exactly the code written into it, even when
//! its frame previously held code that was executed.
//!
//! The contract (`kernel.mm.exec-publication-icache`): arm64 Linux makes a
//! newly mapped executable page coherent with the instruction cache
//! (`set_pte_at` -> `__sync_icache_dcache`), so a program may write
//! instructions into a page it just mapped and call them without its own
//! `ic ivau`, as mprotectexec does. A frame recycled from earlier executed
//! code must not leak those instructions.
//!
//! Each round maps a 16 KiB RWX region, writes `mov w0,#A; ret` with the
//! full JIT protocol (`dc cvau; ic ivau`) into every page, runs every page
//! (so its lines are in the instruction cache), and unmaps it. Then it maps
//! a fresh RWX region (the frame pool hands back recently released frames),
//! writes `mov w0,#B; ret` WITHOUT cache maintenance, and calls every page:
//! each must return B. `cross` runs the first half in a child that exits.
//!
//! `icache-reuse [rounds [cross]]` prints `icache_reuse_ok ...` or
//! `icache_reuse_failed ...` (with the stale count) and exits 1.

const PAGE: usize = 4096;
const LEN: usize = 4 * PAGE;
const RET: u32 = 0xd65f_03c0;

const fn mov_w0(imm: u32) -> u32 {
    0x5280_0000 | ((imm & 0xffff) << 5)
}

unsafe fn map_rwx() -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        println!("icache_reuse_failed mmap");
        std::process::exit(1);
    }
    p.cast()
}

unsafe fn write_code(p: *mut u8, value: u32) {
    for page in 0..LEN / PAGE {
        let words = unsafe { p.add(page * PAGE).cast::<u32>() };
        unsafe {
            words.write_volatile(mov_w0(value + page as u32));
            words.add(1).write_volatile(RET);
        }
    }
}

/// The full user-space JIT protocol: clean to PoU, invalidate I-cache.
unsafe fn sync_code(p: *mut u8) {
    let mut address = p as usize;
    while address < p as usize + LEN {
        unsafe {
            core::arch::asm!("dc cvau, {a}", "ic ivau, {a}", a = in(reg) address, options(nostack));
        }
        address += 64;
    }
    unsafe { core::arch::asm!("dsb ish", "isb", options(nostack)) };
}

unsafe fn call(p: *mut u8, page: usize) -> u32 {
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(p.add(page * PAGE)) };
    f()
}

/// Map, write A with maintenance, execute every page, unmap.
unsafe fn run_old_code(a: u32) {
    unsafe {
        let p = map_rwx();
        write_code(p, a);
        sync_code(p);
        for page in 0..LEN / PAGE {
            let _ = call(p, page);
        }
        libc::munmap(p.cast(), LEN);
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let rounds: u32 = args.next().and_then(|v| v.parse().ok()).unwrap_or(200);
    let cross = args.next().as_deref() == Some("cross");
    let (mut stale, mut wrong) = (0u32, 0u32);
    let mut first = None;
    for round in 0..rounds {
        let a = 0x100 + (round % 64) * 8;
        let b = 0x800 + (round % 64) * 8;
        unsafe {
            if cross {
                let pid = libc::fork();
                if pid == 0 {
                    run_old_code(a);
                    libc::_exit(0);
                }
                let mut status = 0;
                while libc::waitpid(pid, &mut status, 0) < 0 {}
            } else {
                run_old_code(a);
            }
            let q = map_rwx();
            write_code(q, b);
            core::arch::asm!("dsb ish", "isb", options(nostack));
            for page in 0..LEN / PAGE {
                let got = call(q, page);
                let expected = b + page as u32;
                if got != expected {
                    if (0x100..0x800).contains(&got) {
                        stale += 1;
                    } else {
                        wrong += 1;
                    }
                    first.get_or_insert((round, page, got, expected));
                }
            }
            libc::munmap(q.cast(), LEN);
        }
    }
    if stale + wrong == 0 {
        println!("icache_reuse_ok rounds={rounds} cross={cross}");
    } else {
        println!(
            "icache_reuse_failed rounds={rounds} cross={cross} stale={stale} wrong={wrong} first={first:?}"
        );
        std::process::exit(1);
    }
}
