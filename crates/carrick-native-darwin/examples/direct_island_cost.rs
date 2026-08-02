//! What does a tier-D syscall cost?
//!
//! Direct execution needs no measurement for ordinary instructions — they ARE
//! the host's instructions, executed unmodified, so they run at native speed
//! by construction. The one cost the tier introduces is the island round-trip
//! at a patched `svc`: save the guest register file, call a Rust handler,
//! restore, branch back.
//!
//! This measures that round-trip against the translated lane's syscall floor
//! (0.29 µs, `docs/perf-results/`), which is the number it has to beat to be
//! worth doing.
//!
//! Run: cargo run --release -p carrick-native-darwin --example direct_island_cost

#[cfg(target_arch = "aarch64")]
fn main() {
    use carrick_native_darwin::direct::{DirectImage, GuestContext, SVC_0};
    use std::sync::atomic::{AtomicU64, Ordering};

    static CALLS: AtomicU64 = AtomicU64::new(0);

    extern "C" fn count_only(ctx: *mut GuestContext) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the island passes the context this image was built with.
        unsafe { (*ctx).set_return(0) };
    }

    // movz/movk/sub/cbnz encodings, kept local so the fixture is readable.
    const fn movz(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn mov_reg(rd: u32, rm: u32) -> u32 {
        0xaa00_03e0 | (rm << 16) | rd
    }
    /// `sub xd, xn, #imm`
    const fn sub_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0xd100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    /// `cbnz xt, <pc + offset>`
    fn cbnz(rt: u32, offset: i64) -> u32 {
        0xb500_0000 | ((((offset >> 2) as u32) & 0x7ffff) << 5) | rt
    }

    const ITERS: u64 = 200_000;

    // x21 = counter; loop { svc; x21 -= 1; if x21 != 0 goto loop }
    let loop_body: Vec<u32> = vec![
        movz(8, 64, 0),
        SVC_0,
        sub_imm(21, 21, 1),
        cbnz(21, -12), // back to the movz
    ];
    let mut code: Vec<u32> = vec![
        mov_reg(20, 30), // save the incoming link register
        movz(21, (ITERS & 0xffff) as u32, 0),
        0xf2a0_0000 | (((ITERS >> 16) & 0xffff) as u32) << 5 | 21, // movk x21, hi, lsl #16
    ];
    code.extend_from_slice(&loop_body);
    code.push(mov_reg(30, 20));
    code.push(0xd65f_03c0); // ret

    let elf = elf_with_code(&code);
    let image = match DirectImage::load(&elf, count_only) {
        Ok(Ok(image)) => image,
        Ok(Err(reason)) => {
            eprintln!("ineligible: {reason}");
            return;
        }
        Err(error) => {
            eprintln!("load failed: {error}");
            return;
        }
    };
    println!("patched {} svc site(s)", image.svc_sites());
    let entry = image.entry();
    let started = std::time::Instant::now();
    // SAFETY: patched image, entry inside it, fixture returns via `ret`.
    unsafe { image.enter(entry) };
    let elapsed = started.elapsed();

    let calls = CALLS.load(Ordering::Relaxed);
    let per = elapsed.as_secs_f64() / calls as f64;
    println!(
        "island round-trips: {calls}  total: {:?}  per-syscall: {:.0} ns",
        elapsed,
        per * 1e9
    );
    println!("translated-lane syscall floor for comparison: ~290 ns");
    println!();
    println!("Read this as the MECHANISM's cost, not a syscall's: the handler here");
    println!("only bumps a counter, so the number is the island's register save/");
    println!("restore plus the call. A real syscall adds the dispatcher on top,");
    println!("the same dispatcher the translated lane already pays for. The point");
    println!("is that the island is far enough below the floor to never be the");
    println!("bottleneck - not that syscalls become 7 ns.");
}

#[cfg(target_arch = "aarch64")]
fn elf_with_code(code: &[u32]) -> Vec<u8> {
    let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
    let entry: u64 = 0x1000;
    let mut elf = vec![0_u8; 0x40 + 56];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[0x10..0x12].copy_from_slice(&3_u16.to_le_bytes());
    elf[0x12..0x14].copy_from_slice(&183_u16.to_le_bytes());
    elf[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
    elf[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
    elf[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
    elf[0x38..0x3a].copy_from_slice(&1_u16.to_le_bytes());
    let ph = 0x40;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    elf[ph + 0x08..ph + 0x10].copy_from_slice(&entry.to_le_bytes());
    elf[ph + 0x10..ph + 0x18].copy_from_slice(&entry.to_le_bytes());
    elf[ph + 0x20..ph + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
    elf[ph + 0x28..ph + 0x30].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
    elf.resize(entry as usize, 0);
    elf.extend_from_slice(&code_bytes);
    elf
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("tier D is aarch64-only: the premise is same-ISA execution");
}
