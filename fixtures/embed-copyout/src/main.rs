//! Host copyout into, and out of, never-touched anonymous memory.
//!
//! The contract (`kernel.el1.anonymous-reservations.host-copyout`): a fresh
//! private anonymous mapping is EL1-reserved metadata with no frame behind
//! its untouched pages. A syscall that writes such a page from the host
//! (`read`, `pread64`, `recvfrom`) must back it exactly as an EL0 first
//! touch would, and a syscall that reads one (`write`) sees zero. With the
//! reservation root admitted, both returned EFAULT (cpython's first
//! `read()` of `locale.py` into a fresh arena).
//!
//! Every syscall is raw (`svc #0`): the destination is a raw mapping a
//! second thread writes concurrently, never a Rust reference.
//!
//! `copyout` prints `copyout_ok` or `copyout_failed <case> <detail>` and
//! exits 1.

use std::sync::atomic::{AtomicU32, Ordering};

const PAGE: usize = 4096;
const SYS_PIPE2: u64 = 59;
const SYS_OPENAT: u64 = 56;
const SYS_CLOSE: u64 = 57;
const SYS_READ: u64 = 63;
const SYS_WRITE: u64 = 64;
const SYS_PREAD64: u64 = 67;
const SYS_SOCKETPAIR: u64 = 199;
const SYS_SENDTO: u64 = 206;
const SYS_RECVFROM: u64 = 207;
const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const AT_FDCWD: u64 = -100_i64 as u64;
const O_RDWR_CREAT_TRUNC: u64 = 0o2 | 0o100 | 0o1000;
const PROT_RW: u64 = 3;
const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
const MAP_PRIVATE_FILE: u64 = 0x02;
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;

/// aarch64 Linux `svc #0` with up to six arguments.
unsafe fn sys(nr: u64, a: [u64; 6]) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a[0] => ret,
            in("x1") a[1],
            in("x2") a[2],
            in("x3") a[3],
            in("x4") a[4],
            in("x5") a[5],
            options(nostack),
        );
    }
    ret
}

fn call(nr: u64, a: [u64; 6]) -> i64 {
    // SAFETY: every caller passes pointers into live mappings it owns.
    unsafe { sys(nr, a) }
}

/// Print `line` with one raw write from a stack buffer: the verdict must not
/// depend on the host reading heap pages, which is part of what is tested.
fn say(line: std::fmt::Arguments<'_>) {
    struct Stack {
        bytes: [u8; 256],
        len: usize,
    }
    impl std::fmt::Write for Stack {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let take = text.len().min(self.bytes.len() - 1 - self.len);
            self.bytes[self.len..self.len + take].copy_from_slice(&text.as_bytes()[..take]);
            self.len += take;
            Ok(())
        }
    }
    let mut stack = Stack {
        bytes: [0; 256],
        len: 0,
    };
    let _ = std::fmt::write(&mut stack, line);
    stack.bytes[stack.len] = b'\n';
    call(SYS_WRITE, [1, stack.bytes.as_ptr() as u64, stack.len as u64 + 1, 0, 0, 0]);
}

fn fail(case: &str, detail: std::fmt::Arguments<'_>) -> ! {
    say(format_args!("copyout_failed {case} {detail}"));
    std::process::exit(1);
}

/// A fresh private anonymous mapping of `pages` pages, never touched.
fn fresh(pages: usize) -> *mut u8 {
    let address = call(SYS_MMAP, [0, (pages * PAGE) as u64, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0]);
    if address < 0 {
        fail("mmap", format_args!("errno={}", -address));
    }
    address as *mut u8
}

fn unmap(map: *mut u8, pages: usize) {
    call(SYS_MUNMAP, [map as u64, (pages * PAGE) as u64, 0, 0, 0, 0]);
}

/// Byte `i` of the pattern every source carries.
fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(131) % 251) as u8 + 1
}

fn byte(map: *mut u8, offset: usize) -> u8 {
    // SAFETY: offset lies inside the caller's live mapping.
    unsafe { std::ptr::read_volatile(map.add(offset)) }
}

/// `map[at..at + len]` holds the pattern from `from`, and the bytes around
/// it within `pages` are still zero.
fn verify(case: &str, map: *mut u8, pages: usize, at: usize, len: usize, from: usize) {
    for offset in 0..pages * PAGE {
        let expected = if offset >= at && offset < at + len {
            pattern(from + offset - at)
        } else {
            0
        };
        let actual = byte(map, offset);
        if actual != expected {
            fail(case, format_args!("offset={offset} expected={expected} actual={actual}"));
        }
    }
}

fn source_file(len: usize) -> i64 {
    let path = b"/tmp/copyout-source\0";
    let fd = call(SYS_OPENAT, [AT_FDCWD, path.as_ptr() as u64, O_RDWR_CREAT_TRUNC, 0o600, 0, 0]);
    if fd < 0 {
        fail("open", format_args!("errno={}", -fd));
    }
    let bytes: Vec<u8> = (0..len).map(pattern).collect();
    let wrote = call(SYS_WRITE, [fd as u64, bytes.as_ptr() as u64, len as u64, 0, 0, 0]);
    if wrote != len as i64 {
        fail("write-source", format_args!("ret={wrote}"));
    }
    fd
}

fn main() {
    if std::env::args().any(|arg| arg == "overlap") {
        overlapping_file_mapping();
        return;
    }
    if std::env::args().any(|arg| arg == "reuse") {
        reused_mapping_two_live_processes();
        return;
    }
    const LEN: usize = 5 * PAGE + 123;
    let fd = source_file(LEN + 4 * PAGE);

    // read(2) into a fresh mapping, unaligned, across six untouched pages.
    let map = fresh(8);
    let rewind = call(62 /* lseek */, [fd as u64, 0, 0, 0, 0, 0]);
    if rewind != 0 {
        fail("lseek", format_args!("ret={rewind}"));
    }
    let got = call(SYS_READ, [fd as u64, map as u64 + 100, LEN as u64, 0, 0, 0]);
    if got != LEN as i64 {
        fail("read", format_args!("ret={got}"));
    }
    verify("read", map, 8, 100, LEN, 0);
    unmap(map, 8);

    // pread64(2) at a file offset, into the middle of a fresh mapping.
    let map = fresh(8);
    let got = call(SYS_PREAD64, [fd as u64, map as u64 + 3 * PAGE as u64 + 7, 9000, 50, 0, 0]);
    if got != 9000 {
        fail("pread", format_args!("ret={got}"));
    }
    verify("pread", map, 8, 3 * PAGE + 7, 9000, 50);
    unmap(map, 8);

    // recvfrom(2) from a socket into a fresh mapping.
    let mut pair = [0_i32; 2];
    let ret = call(SYS_SOCKETPAIR, [AF_UNIX, SOCK_STREAM, 0, pair.as_mut_ptr() as u64, 0, 0]);
    if ret != 0 {
        fail("socketpair", format_args!("ret={ret}"));
    }
    let sent: Vec<u8> = (0..3 * PAGE).map(pattern).collect();
    let ret = call(SYS_SENDTO, [pair[0] as u64, sent.as_ptr() as u64, sent.len() as u64, 0, 0, 0]);
    if ret != sent.len() as i64 {
        fail("send", format_args!("ret={ret}"));
    }
    let map = fresh(4);
    let mut have = 0_usize;
    while have < sent.len() {
        let got = call(SYS_RECVFROM, [
            pair[1] as u64,
            map as u64 + 5 + have as u64,
            (sent.len() - have) as u64,
            0,
            0,
            0,
        ]);
        if got <= 0 {
            fail("recv", format_args!("ret={got} have={have}"));
        }
        have += got as usize;
    }
    verify("recv", map, 4, 5, sent.len(), 0);
    unmap(map, 4);

    // write(2) FROM untouched pages: the host reads them as zero.
    let mut pipe = [0_i32; 2];
    if call(SYS_PIPE2, [pipe.as_mut_ptr() as u64, 0, 0, 0, 0, 0]) != 0 {
        fail("pipe", format_args!(""));
    }
    let map = fresh(4);
    let wrote = call(SYS_WRITE, [pipe[1] as u64, map as u64 + PAGE as u64 + 9, 2 * PAGE as u64, 0, 0, 0]);
    if wrote != 2 * PAGE as i64 {
        fail("write-untouched", format_args!("ret={wrote}"));
    }
    let mut back = vec![0xff_u8; 2 * PAGE];
    let mut have = 0_usize;
    while have < back.len() {
        let got = call(SYS_READ, [pipe[0] as u64, back.as_mut_ptr() as u64 + have as u64, (back.len() - have) as u64, 0, 0, 0]);
        if got <= 0 {
            fail("write-untouched-readback", format_args!("ret={got}"));
        }
        have += got as usize;
    }
    if let Some(offset) = back.iter().position(|&b| b != 0) {
        fail("write-untouched", format_args!("nonzero at {offset}"));
    }
    verify("write-untouched-source", map, 4, 0, 0, 0);
    unmap(map, 4);

    // A copyout racing an EL0 first touch of the SAME page from another
    // thread: one frame must back the page, so neither store is lost.
    const ROUNDS: usize = 300;
    static GO: AtomicU32 = AtomicU32::new(0);
    for round in 0..ROUNDS {
        let map = fresh(1);
        let base = map as usize;
        GO.store(0, Ordering::SeqCst);
        let toucher = std::thread::spawn(move || {
            while GO.load(Ordering::Acquire) == 0 {
                std::hint::spin_loop();
            }
            // SAFETY: the page is live until the main thread joins us.
            unsafe { std::ptr::write_volatile((base + 3000) as *mut u8, 0x5a) };
        });
        GO.store(1, Ordering::Release);
        let got = call(SYS_PREAD64, [fd as u64, map as u64, 2048, 0, 0, 0]);
        toucher.join().unwrap();
        if got != 2048 {
            fail("race", format_args!("round={round} ret={got}"));
        }
        for offset in 0..2048 {
            if byte(map, offset) != pattern(offset) {
                fail("race", format_args!("round={round} copyout byte {offset} lost"));
            }
        }
        if byte(map, 3000) != 0x5a {
            fail("race", format_args!("round={round} first-touch store lost"));
        }
        unmap(map, 1);
    }

    call(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
    say(format_args!("copyout_ok"));
}

/// Replace one page of a live EL1-granted anonymous extent with file bytes.
fn overlapping_file_mapping() {
    let path = b"/etc/ld.so.cache\0";
    let fd = call(SYS_OPENAT, [AT_FDCWD, path.as_ptr() as u64, 0, 0, 0, 0]);
    if fd < 0 {
        fail("overlap-open", format_args!("errno={}", -fd));
    }
    let mut expected = [0_u8; 32];
    let got = call(SYS_PREAD64, [fd as u64, expected.as_mut_ptr() as u64, expected.len() as u64, 0x10d2, 0, 0]);
    if got != expected.len() as i64 {
        fail("overlap-pread", format_args!("ret={got}"));
    }
    let anon = fresh(2);
    // SAFETY: the first page is mapped; touching it forces the EL1 extent
    // grant before the next file mmap occupies a gap inside that stock.
    unsafe { std::ptr::write_volatile(anon, 0xa5) };
    let mapped = call(SYS_MMAP, [0, 0x144f, 1, MAP_PRIVATE_FILE, fd as u64, 0]);
    if mapped < 0 {
        fail("overlap-mmap", format_args!("ret={mapped}"));
    }
    if mapped as u64 >= anon as u64 + 1024 * 1024 || (mapped as u64) < anon as u64 + 2 * PAGE as u64 {
        fail("overlap-place", format_args!("anon={:x} mapped={mapped:x}", anon as u64));
    }
    let target = mapped as *mut u8;
    let mut first_expected = [0_u8; 1];
    let got = call(SYS_PREAD64, [fd as u64, first_expected.as_mut_ptr() as u64, 1, 0, 0, 0]);
    if got != 1 || byte(target, 0) != first_expected[0] {
        fail("overlap-first", format_args!("ret={got}"));
    }
    for (offset, wanted) in expected.into_iter().enumerate() {
        let actual = byte(target, 0x10d2 + offset);
        if actual != wanted {
            fail("overlap-bytes", format_args!("offset={offset} expected={wanted} actual={actual}"));
        }
    }
    say(format_args!("overlap_ok"));
    unmap(anon, 2);
    unmap(target, 2);
    call(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
}

/// The child replaces a host-file VMA with an EL1-served anonymous VMA at
/// the same VA, while the parent's file VMA remains live. Checked host reads
/// and writes must follow each MM's live permissions, not old host masks.
fn reused_mapping_two_live_processes() {
    #[repr(C)]
    struct Timeval { seconds: i64, micros: i64 }
    #[repr(C)]
    struct Timer { interval: Timeval, value: Timeval }
    let arm = || {
        let timer = Timer {
            interval: Timeval { seconds: 0, micros: 0 },
            value: Timeval { seconds: 5, micros: 0 },
        };
        if call(103 /* setitimer */, [0, &timer as *const Timer as u64, 0, 0, 0, 0]) != 0 {
            fail("reuse-timer", format_args!("setitimer"));
        }
    };
    let fd = source_file(4 * PAGE);
    let map = fresh(4);
    unmap(map, 4);
    let file = call(SYS_MMAP, [map as u64, (4 * PAGE) as u64, PROT_RW, 0x12, fd as u64, 0]);
    if file != map as i64 {
        fail("reuse-file-map", format_args!("ret={file}"));
    }
    let path = unsafe { map.add(PAGE + 32) };
    let put_path = || {
        for (i, b) in b"/tmp/copyout-reused\0".iter().enumerate() {
            unsafe { path.add(i).write_volatile(*b) };
        }
    };
    let open = || call(SYS_OPENAT, [AT_FDCWD, path as u64, O_RDWR_CREAT_TRUNC, 0o600, 0, 0]);
    put_path();
    let mut ready = [-1_i32; 2];
    let mut ack = [-1_i32; 2];
    for pipe in [&mut ready, &mut ack] {
        if call(SYS_PIPE2, [pipe.as_mut_ptr() as u64, 0, 0, 0, 0, 0]) != 0 {
            fail("reuse-pipe", format_args!("pipe2"));
        }
    }
    arm();
    let child = call(220 /* clone: fork-shaped SIGCHLD */, [17, 0, 0, 0, 0, 0]);
    if child < 0 {
        fail("reuse-fork", format_args!("ret={child}"));
    }
    arm(); // Linux interval timers are not inherited by fork.
    if child == 0 {
        call(SYS_CLOSE, [ready[0] as u64, 0, 0, 0, 0, 0]);
        call(SYS_CLOSE, [ack[1] as u64, 0, 0, 0, 0, 0]);
        unmap(map, 4);
        // Prepare a grant while only the first page is mapped. The remaining
        // retired file pages are then first-touch stock, adopted by a later
        // EL1-only mmap without another host grant to refresh any mirror.
        let first = call(SYS_MMAP, [map as u64, PAGE as u64, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0]);
        if first != map as i64 {
            fail("reuse-first-map", format_args!("ret={first}"));
        }
        unsafe { map.write_volatile(0xa5) };
        let rest = call(SYS_MMAP, [map as u64 + PAGE as u64, (3 * PAGE) as u64, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0]);
        if rest != map as i64 + PAGE as i64 {
            fail("reuse-stock-map", format_args!("ret={rest}"));
        }
        put_path();
        let opened = open();
        if opened < 0 {
            fail("reuse-open", format_args!("ret={opened}"));
        }
        call(SYS_CLOSE, [opened as u64, 0, 0, 0, 0, 0]);
        let source = unsafe { map.add(2 * PAGE) };
        unsafe { source.write_volatile(0x5a) };
        let wrote = call(68 /* pwrite64 */, [fd as u64, source as u64, 1, 0, 0, 0]);
        let destination = unsafe { map.add(3 * PAGE) };
        let got = call(SYS_PREAD64, [fd as u64, destination as u64, 1, 0, 0, 0]);
        if wrote != 1 || got != 1 || byte(map, 3 * PAGE) != 0x5a {
            fail("reuse-copy", format_args!("write={wrote} read={got}"));
        }
        if call(226 /* mprotect */, [path as u64 & !4095, PAGE as u64, 0, 0, 0, 0]) != 0 || open() != -14 {
            fail("reuse-none", format_args!("host read must be EFAULT"));
        }
        if call(226, [destination as u64, PAGE as u64, 1, 0, 0, 0]) != 0
            || call(SYS_PREAD64, [fd as u64, destination as u64, 1, 0, 0, 0]) != -14
            || call(68, [fd as u64, destination as u64, 1, 0, 0, 0]) != 1
        {
            fail("reuse-readonly", format_args!("live read/write direction"));
        }
        unmap(map, 4);
        if open() != -14 {
            fail("reuse-hole", format_args!("host read must be EFAULT"));
        }
        let byte = [1_u8];
        if call(SYS_WRITE, [ready[1] as u64, byte.as_ptr() as u64, 1, 0, 0, 0]) != 1 {
            fail("reuse-ready", format_args!("write"));
        }
        let mut response = [0_u8];
        if call(SYS_READ, [ack[0] as u64, response.as_mut_ptr() as u64, 1, 0, 0, 0]) != 1 {
            fail("reuse-ack", format_args!("read"));
        }
        std::process::exit(0);
    }
    call(SYS_CLOSE, [ready[1] as u64, 0, 0, 0, 0, 0]);
    call(SYS_CLOSE, [ack[0] as u64, 0, 0, 0, 0, 0]);
    let mut response = [0_u8];
    if call(SYS_READ, [ready[0] as u64, response.as_mut_ptr() as u64, 1, 0, 0, 0]) != 1 {
        fail("reuse-parent-ready", format_args!("read"));
    }
    let opened = open();
    if opened < 0 {
        fail("reuse-parent-open", format_args!("child retirement changed parent: {opened}"));
    }
    call(SYS_CLOSE, [opened as u64, 0, 0, 0, 0, 0]);
    if call(SYS_WRITE, [ack[1] as u64, response.as_ptr() as u64, 1, 0, 0, 0]) != 1 {
        fail("reuse-parent-ack", format_args!("write"));
    }
    let mut status = -1_i32;
    if call(260 /* wait4 */, [child as u64, &mut status as *mut i32 as u64, 0, 0, 0, 0]) != child || status != 0 {
        fail("reuse-wait", format_args!("status={status}"));
    }
    say(format_args!("copyout_reuse_ok"));
}
