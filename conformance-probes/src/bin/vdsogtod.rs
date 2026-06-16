//! Differential probe for the x86_64 `__vdso_gettimeofday` + `__vdso_time` fast
//! paths: resolve them from AT_SYSINFO_EHDR, call them, and compare to the raw
//! syscall / the (already-verified) vDSO clock. Prints deterministic booleans so
//! it diffs line-exact carrick-vs-Linux. musl routes its own gettimeofday/time
//! through clock_gettime, so this is the only thing that exercises the new
//! symbols directly.

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
unsafe fn cstr_eq(p: u64, want: &str) -> bool {
    for (i, &b) in want.as_bytes().iter().enumerate() {
        if *((p + i as u64) as *const u8) != b {
            return false;
        }
    }
    *((p + want.len() as u64) as *const u8) == 0
}

unsafe fn vdso_sym(want: &str) -> u64 {
    let base = libc::getauxval(AT_SYSINFO_EHDR);
    if base == 0 {
        return 0;
    }
    let e_phoff = rd_u64(base + 0x20);
    let e_phentsize = rd_u16(base + 0x36) as u64;
    let e_phnum = rd_u16(base + 0x38) as u64;
    let mut dynaddr = 0u64;
    for i in 0..e_phnum {
        let ph = base + e_phoff + i * e_phentsize;
        if rd_u32(ph) == PT_DYNAMIC {
            dynaddr = base + rd_u64(ph + 16);
        }
    }
    if dynaddr == 0 {
        return 0;
    }
    let (mut symtab, mut strtab, mut hash) = (0u64, 0u64, 0u64);
    let mut d = dynaddr;
    loop {
        let tag = rd_i64(d);
        let v = rd_u64(d + 8);
        match tag {
            DT_SYMTAB => symtab = base + v,
            DT_STRTAB => strtab = base + v,
            DT_HASH => hash = base + v,
            _ => {}
        }
        if tag == DT_NULL {
            break;
        }
        d += 16;
    }
    let nchain = if hash != 0 { rd_u32(hash + 4) } else { 0 };
    if symtab == 0 || strtab == 0 {
        return 0;
    }
    for s in 0..nchain as u64 {
        let sym = symtab + s * 24;
        let st_name = rd_u32(sym) as u64;
        let st_shndx = rd_u16(sym + 6);
        let st_value = rd_u64(sym + 8);
        if st_name == 0 || st_shndx == 0 {
            continue;
        }
        if cstr_eq(strtab + st_name, want) {
            return base + st_value;
        }
    }
    0
}

type GtodFn = unsafe extern "C" fn(*mut libc::timeval, *mut libc::c_void) -> i32;
type TimeFn = unsafe extern "C" fn(*mut libc::time_t) -> libc::time_t;

const SANE_EPOCH: i64 = 1_700_000_000; // 2023-11

fn main() {
    unsafe {
        let gaddr = vdso_sym("__vdso_gettimeofday");
        let taddr = vdso_sym("__vdso_time");
        println!("gettimeofday_resolved={}", gaddr != 0);
        println!("time_resolved={}", taddr != 0);
        if gaddr == 0 || taddr == 0 {
            println!("gtod_close=false");
            println!("gtod_usec_valid=false");
            println!("time_close=false");
            println!("gtod_time_agree=false");
            return;
        }
        let gf: GtodFn = std::mem::transmute(gaddr);
        let tf: TimeFn = std::mem::transmute(taddr);

        // __vdso_gettimeofday vs the raw SYS_gettimeofday syscall.
        let mut tv_v = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let gret = gf(&mut tv_v, ptr::null_mut());
        let mut tv_s = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        libc::syscall(
            libc::SYS_gettimeofday,
            &mut tv_s as *mut libc::timeval,
            0usize,
        );
        let gdsec = (tv_v.tv_sec - tv_s.tv_sec).abs();
        println!(
            "gtod_close={}",
            gret == 0 && gdsec <= 2 && tv_v.tv_sec > SANE_EPOCH
        );
        println!(
            "gtod_usec_valid={}",
            tv_v.tv_usec >= 0 && tv_v.tv_usec < 1_000_000
        );

        // __vdso_time vs the (already-verified) vDSO clock via libc time().
        let t_v = tf(ptr::null_mut());
        let t_s = libc::time(ptr::null_mut());
        println!(
            "time_close={}",
            (t_v - t_s).abs() <= 2 && t_v > SANE_EPOCH as libc::time_t
        );
        println!("gtod_time_agree={}", (tv_v.tv_sec - t_v as i64).abs() <= 2);
    }
}
