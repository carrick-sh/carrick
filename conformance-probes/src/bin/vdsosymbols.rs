//! The vDSO exposed via `AT_SYSINFO_EHDR` exports the complete canonical
//! aarch64 symbol set. Real Linux aarch64 (`arch/arm64/kernel/vdso/vdso.lds.S`,
//! version `LINUX_2.6.39`) exports exactly four `__kernel_*` symbols:
//! `__kernel_clock_gettime`, `__kernel_gettimeofday`, `__kernel_clock_getres`,
//! `__kernel_rt_sigreturn`. carrick must export all four so libc/Go resolve the
//! fast clock path AND so unwinders/debuggers recognise the signal-return
//! trampoline by name. This probe hand-walks the vDSO's `.dynsym` (no goblin in
//! the probe crate) and prints one boolean per symbol — no addresses/times — so
//! it diffs byte-for-byte carrick-vs-Linux.

use std::ptr;

const AT_SYSINFO_EHDR: u64 = 33;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;

unsafe fn rd_u16(p: u64) -> u16 {
    ptr::read_unaligned(p as *const u16)
}
unsafe fn rd_u32(p: u64) -> u32 {
    ptr::read_unaligned(p as *const u32)
}
unsafe fn rd_u64(p: u64) -> u64 {
    ptr::read_unaligned(p as *const u64)
}
unsafe fn rd_i64(p: u64) -> i64 {
    ptr::read_unaligned(p as *const i64)
}

/// True if the NUL-terminated C string at `p` equals `want`.
unsafe fn cstr_eq(p: u64, want: &str) -> bool {
    for (i, &b) in want.as_bytes().iter().enumerate() {
        if *((p + i as u64) as *const u8) != b {
            return false;
        }
    }
    *((p + want.len() as u64) as *const u8) == 0
}

fn main() {
    // Order is fixed so the output is deterministic across machines.
    let names = [
        "__kernel_clock_gettime",
        "__kernel_gettimeofday",
        "__kernel_clock_getres",
        "__kernel_rt_sigreturn",
    ];
    let mut found = [false; 4];

    unsafe {
        let base = libc::getauxval(AT_SYSINFO_EHDR);
        println!("vdso_present={}", base != 0);
        if base != 0 {
            // ELF64 header: e_phoff@0x20, e_phentsize@0x36, e_phnum@0x38.
            let e_phoff = rd_u64(base + 0x20);
            let e_phentsize = rd_u16(base + 0x36) as u64;
            let e_phnum = rd_u16(base + 0x38) as u64;

            // The vDSO's single PT_LOAD has p_vaddr == 0, so the load bias is
            // simply `base` and every dynamic d_ptr is `base + d_val`.
            let mut dyn_addr = 0u64;
            for i in 0..e_phnum {
                let ph = base + e_phoff + i * e_phentsize;
                if rd_u32(ph) == PT_DYNAMIC {
                    dyn_addr = base + rd_u64(ph + 16); // p_vaddr@16
                }
            }

            let (mut symtab, mut strtab, mut hash) = (0u64, 0u64, 0u64);
            if dyn_addr != 0 {
                let mut d = dyn_addr;
                loop {
                    let tag = rd_i64(d);
                    let val = rd_u64(d + 8);
                    match tag {
                        DT_SYMTAB => symtab = base + val,
                        DT_STRTAB => strtab = base + val,
                        DT_HASH => hash = base + val,
                        _ => {}
                    }
                    if tag == DT_NULL {
                        break;
                    }
                    d += 16;
                }
            }

            // SysV hash: word[1] = nchain = number of .dynsym entries.
            let nchain = if hash != 0 { rd_u32(hash + 4) } else { 0 };
            if symtab != 0 && strtab != 0 {
                for s in 0..nchain as u64 {
                    let sym = symtab + s * 24; // sizeof(Elf64_Sym)
                    let st_name = rd_u32(sym) as u64; // st_name@0
                    let st_shndx = rd_u16(sym + 6); // st_shndx@6
                    // Match by name + "defined" (st_shndx != 0) ONLY. Do NOT
                    // filter on st_info type: real Linux marks
                    // __kernel_rt_sigreturn as STT_NOTYPE, so a STT_FUNC filter
                    // would falsely miss it on the oracle (a false DIFF).
                    if st_name == 0 || st_shndx == 0 {
                        continue;
                    }
                    let np = strtab + st_name;
                    for (i, want) in names.iter().enumerate() {
                        if cstr_eq(np, want) {
                            found[i] = true;
                        }
                    }
                }
            }
        }
    }

    println!("has_clock_gettime={}", found[0]);
    println!("has_gettimeofday={}", found[1]);
    println!("has_clock_getres={}", found[2]);
    println!("has_rt_sigreturn={}", found[3]);
    println!("all_four_present={}", found.iter().all(|&b| b));
}
