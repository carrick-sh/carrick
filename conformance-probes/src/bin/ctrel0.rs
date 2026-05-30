//! EL0 cache-geometry & cache-maintenance conformance probe.
//!
//! glibc 2.41 (Debian trixie / python:3.12-slim) reads `CTR_EL0` at startup to
//! learn the i/d cache line sizes, and uses `DC ZVA` (sized via `DCZID_EL0`)
//! for `memset`/`bzero` plus `DC CVAU`/`IC IVAU` for `__clear_cache`. On real
//! Linux all of these are unprivileged at EL0 (the kernel sets SCTLR_EL1.UCT,
//! DZE and UCI). carrick previously left those bits clear, so the very first
//! `mrs CTR_EL0` trapped to EL1 (EC=0x18) and — unemulated — killed the process
//! with SIGSEGV before it printed a byte. This reducer reproduces that exact
//! interaction in ~30 instructions.
//!
//! Deterministic & machine-independent: the RAW cache line / block sizes differ
//! across CPUs, so they are NEVER printed. Every observation is reduced to a
//! boolean invariant (a field lies in a sane range; DC ZVA actually zeroes its
//! block; a maintenance op executes without faulting) that holds on ANY correct
//! aarch64 Linux, whatever the geometry. A carrick that traps these prints
//! nothing (it crashes) → the line-diff vs Docker flags it immediately.

use std::arch::asm;

/// log2(words) field → line/block size in bytes (4 bytes per word).
fn pow_field_in_range(pow: u32) -> bool {
    // 2 → 16 bytes, 11 → 16 KiB. Real caches sit comfortably inside this.
    (2..=11).contains(&(pow + 2))
}

fn main() {
    // --- CTR_EL0: cache type register (EL0 read needs SCTLR_EL1.UCT) ---
    let ctr: u64;
    // SAFETY: unprivileged system-register read once UCT is set; the whole point
    // of the probe is to prove it does not trap.
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    println!("ctr_read_ok=true"); // reached only if the MRS did not fault
    let imin = (ctr & 0xf) as u32; // IminLine: log2 words, smallest icache line
    let dmin = ((ctr >> 16) & 0xf) as u32; // DminLine: smallest dcache line
    println!("icache_line_in_range={}", pow_field_in_range(imin));
    println!("dcache_line_in_range={}", pow_field_in_range(dmin));

    // --- DCZID_EL0: DC ZVA block id (EL0 read needs SCTLR_EL1.DZE) ---
    let dczid: u64;
    // SAFETY: unprivileged read once DZE is set.
    unsafe { asm!("mrs {}, dczid_el0", out(reg) dczid, options(nomem, nostack)) };
    println!("dczid_read_ok=true");
    let dzp = (dczid >> 4) & 1; // 1 = DC ZVA prohibited
    let bs = (dczid & 0xf) as u32; // block size: log2 words
    println!("dc_zva_permitted={}", dzp == 0);
    println!("dc_zva_block_in_range={}", pow_field_in_range(bs));

    // --- DC ZVA actually zeroes its block (needs SCTLR_EL1.DZE) ---
    // Allocate generously, find a block-aligned region, poison it, DC ZVA the
    // first byte's block, and confirm the whole block reads back zero.
    if dzp == 0 {
        let block = 1usize << (bs + 2); // bytes
        let mut buf = vec![0xAAu8; block * 4];
        let base = buf.as_mut_ptr() as usize;
        let aligned = (base + block) & !(block - 1); // a block-aligned addr inside buf
        // SAFETY: `aligned` and `aligned+block` lie within `buf` (we allocated
        // 4×block and skipped at most one block for alignment).
        unsafe {
            asm!("dc zva, {addr}", addr = in(reg) aligned, options(nostack));
        }
        let zeroed = (0..block).all(|i| unsafe { *((aligned + i) as *const u8) } == 0);
        println!("dc_zva_zeroes_block={}", zeroed);
    } else {
        // Keep the line set identical across platforms even if a CPU prohibits
        // DC ZVA (none of ours do); the value then tracks the gated branch.
        println!("dc_zva_zeroes_block=false");
    }

    // --- Cache maintenance to point-of-unification (needs SCTLR_EL1.UCI) ---
    // glibc's __clear_cache issues DC CVAU then IC IVAU over a code range. They
    // change no observable memory; we only prove they execute at EL0 instead of
    // trapping. Reaching the final print is the success signal.
    let probe = main as *const () as usize;
    // SAFETY: clean/invalidate the cache line containing this function's entry —
    // a mapped, valid address; the ops have no architectural memory effect.
    unsafe {
        asm!("dc cvau, {a}", a = in(reg) probe, options(nostack));
        asm!("dsb ish", options(nostack));
        asm!("ic ivau, {a}", a = in(reg) probe, options(nostack));
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));
    }
    println!("cache_maintenance_ok=true");
}
