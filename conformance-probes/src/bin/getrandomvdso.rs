//! __kernel_getrandom vDSO (Linux 6.11+): resolve the symbol from
//! AT_SYSINFO_EHDR and exercise both modes the way glibc does — QUERY
//! (opaque_len == ~0UL) must return vgetrandom_opaque_params{size,prot,flags},
//! then mmap the opaque state with those prot/flags and call GENERATE for 32
//! bytes. Prints deterministic booleans + the fixed query values (never the
//! random bytes), so it diffs line-exact carrick-vs-Linux.

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

/// Runtime address of vDSO function `want`, or 0 if absent.
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

#[repr(C)]
#[derive(Default)]
struct Params {
    size: u32,
    prot: u32,
    flags: u32,
    reserved: [u32; 13],
}

type GrFn = unsafe extern "C" fn(*mut u8, usize, u32, *mut u8, usize) -> isize;

fn main() {
    unsafe {
        let addr = vdso_sym("__kernel_getrandom");
        println!("getrandom_resolved={}", addr != 0);
        if addr == 0 {
            println!("query_ret_zero=false");
            println!("query_size=0");
            println!("query_prot=0");
            println!("query_flags=0");
            println!("state_mmap_ok=false");
            println!("generate_ret_32=false");
            return;
        }
        let f: GrFn = std::mem::transmute(addr);

        // QUERY mode: opaque_len == ~0UL, buffer NULL, len 0.
        let mut params = Params::default();
        let qret = f(
            ptr::null_mut(),
            0,
            0,
            &mut params as *mut Params as *mut u8,
            usize::MAX,
        );
        println!("query_ret_zero={}", qret == 0);
        println!("query_size={}", params.size);
        println!("query_prot={}", params.prot);
        println!("query_flags={}", params.flags);

        // mmap the per-thread opaque state with the prot/flags the query gave us
        // (MAP_ANONYMOUS|MAP_DROPPABLE), one page — exactly as glibc does.
        let state = libc::mmap(
            ptr::null_mut(),
            4096,
            params.prot as i32,
            params.flags as i32,
            -1,
            0,
        );
        let state_ok = state != libc::MAP_FAILED;
        println!("state_mmap_ok={}", state_ok);

        // GENERATE: request 32 bytes through the vDSO.
        let mut buf = [0u8; 32];
        let gret = if state_ok {
            f(
                buf.as_mut_ptr(),
                32,
                0,
                state as *mut u8,
                params.size as usize,
            )
        } else {
            -1
        };
        println!("generate_ret_32={}", gret == 32);
    }
}
