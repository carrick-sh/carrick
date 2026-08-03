//! Does tier D's patch actually land inside THIS crate's binary?
//!
//! The bridge loops here while identical code passes in
//! `carrick-native-darwin`. The cheapest discriminator: load an image and read
//! the patched word back. If it is still `svc #0`, the write silently did not
//! stick and the guest executes a real Darwin syscall — which explains a wild
//! x30 and a non-balancing SP far better than a mis-aimed branch.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use carrick_native_darwin::direct::{DirectLoadGroup, SVC_0};
    static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    extern "C" fn noop(ctx: *mut carrick_native_darwin::direct::GuestContext) {
        HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if HITS.load(std::sync::atomic::Ordering::Relaxed) > 5 {
            println!("LOOPING: handler entered >5 times");
            std::process::exit(3);
        }
        // SAFETY: the island passes the context this image was built with.
        unsafe { (*ctx).set_return(0) };
    }

    const fn movz(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn mov_reg(rd: u32, rm: u32) -> u32 {
        0xaa00_03e0 | (rm << 16) | rd
    }
    let code = vec![
        mov_reg(20, 30),
        movz(8, 93, 0),
        SVC_0,
        mov_reg(30, 20),
        0xd65f_03c0,
    ];
    let elf = elf_with_code(&code);
    let group = match DirectLoadGroup::load(&elf, noop) {
        Ok(Ok(group)) => group,
        Ok(Err(reason)) => {
            println!("ineligible: {reason}");
            return;
        }
        Err(error) => {
            println!("load failed: {error}");
            return;
        }
    };
    println!("svc_sites = {}", group.main().svc_sites());
    // The single PT_LOAD is lowest, so text sits at bias-relative 0.
    // SAFETY: reading back the mapping this image owns.
    let words = unsafe { std::slice::from_raw_parts(group.main().base() as *const u32, 6) };
    println!("word[0] = {:#010x}   (expect movz x8,#93)", words[0]);
    println!("word[1] = {:#010x}", words[1]);
    let site = words[2];
    println!("word[2] = {site:#010x}   (the svc site)");
    if site == SVC_0 {
        println!("\nVERDICT: the patch did NOT land — the guest would execute a real svc.");
    } else if site & 0xfc00_0000 == 0x1400_0000 {
        println!("\nVERDICT: the patch DID land as an unconditional branch.");
    } else {
        println!("\nVERDICT: word is neither svc nor a branch — mapping is not what we think.");
    }

    // Does the island resolve the PER-THREAD context (TSD chain) rather
    // than a baked address? Follow the patched branch rather than guessing
    // where the island is: the svc site holds `b <island>`, so its imm26
    // gives the offset.
    let mapped = unsafe {
        std::slice::from_raw_parts(
            group.main().base() as *const u32,
            group.main().mapped_len() / 4,
        )
    };
    let site_word_index = 2_usize; // the svc in this fixture
    let branch = mapped[site_word_index];
    let imm26 = (branch & 0x03ff_ffff) as i64;
    let island_word_index = site_word_index as i64 + imm26;
    println!(
        "island at word {island_word_index} (byte {})",
        island_word_index * 4
    );
    let island_word = |i: usize| mapped[island_word_index as usize + i];
    println!(
        "island[0] = {:#010x}  (expect str x0,[sp,#-16]!)",
        island_word(0)
    );
    println!(
        "island[1] = {:#010x}  (expect mrs x0,tpidrro_el0 — the per-thread resolve)",
        island_word(1)
    );
    println!(
        "TSD RESOLVE: {}",
        if island_word(1) == 0xd53b_d060 {
            "yes — the island addresses this thread's slots"
        } else {
            "NO — the island does not begin with the TSD chain"
        }
    );

    println!("\nentering the guest on the MAIN thread...");
    let entry = group.main().entry();
    let slots = match group.install_thread_slots() {
        Ok(slots) => slots,
        Err(error) => {
            println!("install main-thread slots failed: {error}");
            return;
        }
    };
    // SAFETY: patched image, entry inside it, fixture returns via `ret`.
    if let Err(error) = unsafe { group.enter(entry) } {
        println!("enter failed: {error}");
        return;
    }
    drop(slots);
    println!(
        "returned; handler hits = {}",
        HITS.load(std::sync::atomic::Ordering::Relaxed)
    );

    // Same binary, same image, SPAWNED thread. libtest runs every test on a
    // spawned thread, so this is the discriminator between "the crate" and
    // "the thread".
    println!("\nentering the guest on a SPAWNED thread...");
    HITS.store(0, std::sync::atomic::Ordering::Relaxed);
    let handle = std::thread::spawn(move || {
        let entry = group.main().entry();
        let run_guest = std::env::var_os("CARRICK_NO_RUN").is_none();
        println!("  spawned: about to enter (run_guest={run_guest})");
        if !run_guest {
            // SAFETY: patched image, entry inside it. `enter` arms this thread for
            // MAP_JIT execution, which is the whole point of the experiment.
        } else {
            match group.install_thread_slots() {
                Ok(slots) => {
                    // SAFETY: patched image, entry inside it.
                    if let Err(error) = unsafe { group.enter(entry) } {
                        println!("  spawned: enter failed: {error}");
                    }
                    drop(slots);
                }
                Err(error) => println!("  spawned: install slots failed: {error}"),
            }
        }
        println!("  spawned: guest returned");
        if std::env::var_os("CARRICK_NO_RUN").is_some() {
            println!("  spawned: (guest was skipped)");
        }
        println!("  spawned: dropping image on this thread...");
        drop(group);
        println!("  spawned: drop survived");
    });
    match handle.join() {
        Ok(()) => println!(
            "spawned thread returned; handler hits = {}",
            HITS.load(std::sync::atomic::Ordering::Relaxed)
        ),
        Err(_) => println!("spawned thread PANICKED/aborted"),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
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

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {}
