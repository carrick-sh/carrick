//! P2 fork-safety: a forked child must NOT reuse its parent's userspace vDSO
//! getrandom keystream. The parent seeds + draws (ratcheting its key), forks,
//! and the child draws from the COW-inherited state and pipes its bytes back;
//! the parent then draws again. With correct fork handling the child reseeds (a
//! different generation), so its bytes differ from the parent's NEXT bytes —
//! `child_reused=false`. A broken impl would reproduce them (`true`). Real Linux
//! is also false, so this diffs line-exact AND is a security regression gate.

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
        if addr == 0 {
            println!("resolved=false");
            println!("child_reused=true");
            return;
        }
        println!("resolved=true");
        let f: GrFn = std::mem::transmute(addr);

        let mut params = Params::default();
        f(
            ptr::null_mut(),
            0,
            0,
            &mut params as *mut Params as *mut u8,
            usize::MAX,
        );
        let state = libc::mmap(
            ptr::null_mut(),
            4096,
            params.prot as i32,
            params.flags as i32,
            -1,
            0,
        );
        if state == libc::MAP_FAILED {
            println!("child_reused=true");
            return;
        }
        let state = state as *mut u8;
        let slen = params.size as usize;

        // Parent seeds + draws once (ratchets the key).
        let mut warm = [0u8; 32];
        f(warm.as_mut_ptr(), 32, 0, state, slen);

        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            // Child: draw from the COW-inherited state, pipe the bytes up.
            let mut bc = [0u8; 32];
            f(bc.as_mut_ptr(), 32, 0, state, slen);
            libc::write(fds[1], bc.as_ptr() as *const _, 32);
            libc::_exit(0);
        }
        // Parent: draw the NEXT bytes, then read the child's.
        let mut bp = [0u8; 32];
        f(bp.as_mut_ptr(), 32, 0, state, slen);
        let mut bc = [0u8; 32];
        let mut got = 0usize;
        while got < 32 {
            let n = libc::read(fds[0], bc.as_mut_ptr().add(got) as *mut _, 32 - got);
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);

        // Reuse == the child reproduced the parent's next keystream.
        println!("child_reused={}", got == 32 && bc == bp);
    }
}
