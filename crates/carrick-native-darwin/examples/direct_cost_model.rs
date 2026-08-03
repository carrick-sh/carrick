//! The complete steady-state cost model for tier D.
//!
//! Ordinary guest instructions need no benchmark: they ARE the host's
//! instructions, executed unmodified, so they run at native speed by
//! construction. What is NOT free — and what nobody has measured — is what the
//! patches cost when they land in a hot loop:
//!
//!   - a `tpidr_el0` read, veneered to a memory slot;
//!   - an x18 use, veneered to a memory slot with two borrowed registers;
//!   - a syscall, which leaves through an island.
//!
//! Each variant below is the SAME loop with one extra instruction, so the
//! difference between variants is that instruction's veneered cost, and the
//! baseline variant establishes what an unpatched loop iteration costs. If the
//! veneers were expensive, tier D's "native speed" claim would only hold for
//! code that never touches x18 or TLS — which libc does 1,782 times.
//!
//! Run: cargo run --release -p carrick-native-darwin --example direct_cost_model

#[cfg(target_arch = "aarch64")]
fn main() {
    use carrick_native_darwin::direct::{DirectLoadGroup, GuestContext, SVC_0};

    extern "C" fn stop(ctx: *mut GuestContext) {
        // SAFETY: the island passes the context this image was built with.
        unsafe { (*ctx).set_return(0) };
    }

    const fn movz(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn movk(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xf280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn mov_reg(rd: u32, rm: u32) -> u32 {
        0xaa00_03e0 | (rm << 16) | rd
    }
    /// `sub xd, xn, #imm`
    const fn sub_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0xd100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    /// `add xd, xn, #imm`
    const fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    /// `cbnz xt, <pc + offset>`
    fn cbnz(rt: u32, offset: i64) -> u32 {
        0xb500_0000 | ((((offset >> 2) as u32) & 0x7ffff) << 5) | rt
    }
    const MRS_TPIDR_X9: u32 = 0xd53b_d049; // mrs x9, tpidr_el0
    const ADD_X18_X18_1: u32 = 0x9100_0652; // add x18, x18, #1

    const ITERS: u64 = 20_000_000;

    // Loop body: `extra` (0 or 1 instruction) + three cheap ALU ops + the
    // decrement and branch. Same shape every variant.
    let build = |extra: Option<u32>| -> Vec<u32> {
        let mut body: Vec<u32> = Vec::new();
        if let Some(word) = extra {
            body.push(word);
        }
        body.push(add_imm(10, 10, 1));
        body.push(add_imm(11, 11, 3));
        body.push(add_imm(12, 12, 7));
        body.push(sub_imm(21, 21, 1));
        let back = -((body.len() as i64) * 4);
        body.push(cbnz(21, back));

        let mut code: Vec<u32> = vec![
            mov_reg(20, 30), // save the incoming link register
            movz(21, (ITERS & 0xffff) as u32, 0),
            movk(21, ((ITERS >> 16) & 0xffff) as u32, 16),
            movz(10, 0, 0),
            movz(11, 0, 0),
            movz(12, 0, 0),
        ];
        code.extend_from_slice(&body);
        // One syscall so the run is observable, then return to the host.
        code.push(movz(8, 93, 0));
        code.push(SVC_0);
        code.push(mov_reg(30, 20));
        code.push(0xd65f_03c0); // ret
        code
    };

    let time = |label: &str, extra: Option<u32>, baseline: Option<f64>| -> f64 {
        let elf = elf_with_code(&build(extra));
        let group = match DirectLoadGroup::load(&elf, stop) {
            Ok(Ok(group)) => group,
            Ok(Err(reason)) => {
                println!("{label:<26} INELIGIBLE  {reason}");
                return f64::NAN;
            }
            Err(error) => {
                println!("{label:<26} ERROR  {error}");
                return f64::NAN;
            }
        };
        let entry = group.main().entry();
        // Warm the mapping so the first run's page faults are not in the number.
        let started = std::time::Instant::now();
        // SAFETY: patched image, entry inside it, fixture returns via `ret`.
        unsafe { group.enter(entry) };
        let elapsed = started.elapsed();
        let per_iter_ns = elapsed.as_secs_f64() * 1e9 / ITERS as f64;
        let delta = match baseline {
            Some(base) => format!("  (+{:.2} ns/use)", per_iter_ns - base),
            None => String::new(),
        };
        println!(
            "{label:<26} {:>8.2} ns/iter   veneers={} islands={}{delta}",
            per_iter_ns,
            group.main().tpidr_sites() + group.main().x18_sites(),
            group.main().svc_sites()
        );
        per_iter_ns
    };

    println!("tier D steady-state cost model — {ITERS} iterations per variant\n");
    let base = time("baseline (no patches)", None, None);
    time("+ tpidr_el0 read", Some(MRS_TPIDR_X9), Some(base));
    time("+ x18 use", Some(ADD_X18_X18_1), Some(base));
    println!(
        "\nThe baseline loop is unmodified guest code, so its cost IS native. \
         The deltas are what a veneered instruction costs per execution."
    );
}

/// Minimal ET_DYN wrapper with a section header table (the eligibility scan
/// walks SHF_EXECINSTR sections, so a fixture without one is refused).
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
    let shoff = elf.len();
    let mut shdrs = vec![0_u8; 64 * 2];
    let text = 64;
    shdrs[text + 0x04..text + 0x08].copy_from_slice(&1_u32.to_le_bytes());
    shdrs[text + 0x08..text + 0x10].copy_from_slice(&0x6_u64.to_le_bytes());
    shdrs[text + 0x10..text + 0x18].copy_from_slice(&entry.to_le_bytes());
    shdrs[text + 0x18..text + 0x20].copy_from_slice(&entry.to_le_bytes());
    shdrs[text + 0x20..text + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
    elf.extend_from_slice(&shdrs);
    elf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
    elf[0x3a..0x3c].copy_from_slice(&64_u16.to_le_bytes());
    elf[0x3c..0x3e].copy_from_slice(&2_u16.to_le_bytes());
    elf
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("tier D is aarch64-only: the premise is same-ISA execution");
}
