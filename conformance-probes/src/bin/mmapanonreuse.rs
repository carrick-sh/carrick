use std::os::raw::c_void;

const LEN: usize = 256 * 1024; // 64 pages

fn emit(s: &'static str) {
    unsafe {
        libc::write(1, s.as_ptr() as *const c_void, s.len());
    }
}

fn main() {
    let code = unsafe { run() };
    unsafe { libc::_exit(code) };
}

unsafe fn run() -> i32 {
    // 1) First mapping
    let a = libc::mmap(
        std::ptr::null_mut(),
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if a == libc::MAP_FAILED {
        emit("mmapanonreuse=ERR_MMAP1\n");
        return 43;
    }
    // 2) Write dirty bytes
    for i in 0..LEN {
        std::ptr::write_volatile((a as *mut u8).add(i), 0x5a);
    }

    // 3) Partial munmap in the middle of a compound (4 KiB at offset 4096)
    let sub_off = 4096;
    let sub_len = 8192;
    let sub_ptr = (a as *mut u8).add(sub_off);
    if libc::munmap(sub_ptr as *mut c_void, sub_len) != 0 {
        emit("mmapanonreuse=ERR_MUNMAP_PARTIAL\n");
        return 43;
    }

    // 4) Remap that partial hole with MAP_FIXED
    let b = libc::mmap(
        sub_ptr as *mut c_void,
        sub_len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    if b == libc::MAP_FAILED {
        emit("mmapanonreuse=ERR_MMAP2\n");
        return 43;
    }

    // 5) Reading zeros in the remapped sub-range
    let mut off = 0usize;
    let mut stale = false;
    while off < sub_len {
        let val = std::ptr::read_volatile((b as *const u8).add(off));
        if val != 0 {
            stale = true;
            break;
        }
        off += 4096;
    }
    if stale {
        emit("mmapanonreuse=STALE_NONZERO_PARTIAL\n");
        return 42;
    }

    // 6) Clean up the rest
    libc::munmap(a, LEN);

    // 7) Whole munmap & remap test
    let c = libc::mmap(
        a,
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    if c == libc::MAP_FAILED {
        emit("mmapanonreuse=ERR_MMAP3\n");
        return 43;
    }
    off = 0;
    while off < LEN {
        let val = std::ptr::read_volatile((c as *const u8).add(off));
        if val != 0 {
            emit("mmapanonreuse=STALE_NONZERO_FULL\n");
            return 42;
        }
        off += 4096;
    }

    // 8) Writing new bytes
    for i in 0..LEN {
        std::ptr::write_volatile((c as *mut u8).add(i), 0xa5);
    }

    // 9) Reading back
    let mut corrupt = false;
    off = 0;
    while off < LEN {
        let val = std::ptr::read_volatile((c as *const u8).add(off));
        if val != 0xa5 {
            corrupt = true;
            break;
        }
        off += 4096;
    }
    if corrupt {
        emit("mmapanonreuse=CORRUPT_READBACK\n");
        return 44;
    }
    // 10) MAP_FIXED overwrite directly without prior munmap
    let d = libc::mmap(
        c,
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    if d == libc::MAP_FAILED {
        emit("mmapanonreuse=ERR_MMAP4\n");
        return 43;
    }
    off = 0;
    while off < LEN {
        let val = std::ptr::read_volatile((d as *const u8).add(off));
        if val != 0 {
            emit("mmapanonreuse=STALE_NONZERO_OVERWRITE\n");
            return 45;
        }
        off += 4096;
    }

    emit("mmapanonreuse=CLEAN\n");
    0
}
