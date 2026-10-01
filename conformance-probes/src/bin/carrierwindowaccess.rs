//! A process reaches only what it mapped: Carrick's fixed windows are not
//! guest memory.
//!
//! Linux: an access to an address no VMA of the process covers is SIGSEGV
//! (SEGV_MAPERR), whatever another process maps there. Carrick reserves fixed
//! guest-virtual windows for its own use: a per-process info page, the
//! interpreter load base, the boot-mapped MAP_SHARED aperture and the private
//! overlay aperture behind it. Their stage-1 leaves were EL0 read/write in
//! every process, so a process that never mapped them could read and write
//! the carrier-wide shared aperture, the overlay, the info page, and (after
//! an exec) another process's loaded interpreter.
//!
//! The probe tries a load, a store and an instruction fetch at each window in
//! the first image, in a forked child, and after an execve of itself. A
//! window address the process mapped itself (a dynamic probe's own
//! interpreter) is moved to the next 2 MiB boundary past that mapping, so
//! every line asks the same question: "may I touch what I never mapped?". It
//! also unmaps a
//! MAP_SHARED mapping and touches it again. Each access is one instruction;
//! the SIGSEGV/SIGBUS/SIGILL handler records the signal and `si_code`, then
//! resumes after a data access or returns from an instruction fetch. Each
//! access runs in its own forked child so an access that kills the
//! process is reported rather than ending the probe. Output uses heap-free
//! `write(2)`; every fork wait is bounded at 5 s.

#[cfg(target_arch = "aarch64")]
mod probe {
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicI32, Ordering};

    const PAGE: u64 = 4096;

    /// Carrick's fixed windows, by the role they play there. On Linux none
    /// of them is mapped in this process.
    const WINDOWS: [(&str, u64); 4] = [
        ("info_page", 0x2c_ffff_0000),
        ("interpreter_window", 0x8c_0000_0000),
        ("shared_aperture", 0x90_0000_0000),
        ("private_overlay", 0x98_0000_0000),
    ];

    static SIGNO: AtomicI32 = AtomicI32::new(0);
    static CODE: AtomicI32 = AtomicI32::new(0);

    extern "C" fn handler(signo: i32, info: *mut libc::siginfo_t, context: *mut c_void) {
        unsafe {
            SIGNO.store(signo, Ordering::SeqCst);
            CODE.store((*info).si_code, Ordering::SeqCst);
            let context = context.cast::<libc::ucontext_t>();
            let mcontext = &mut (*context).uc_mcontext;
            let fault = (*info).si_addr() as u64;
            if fault == mcontext.pc {
                mcontext.pc = mcontext.regs[30];
            } else {
                mcontext.pc = mcontext.pc.wrapping_add(4);
            }
        }
    }

    fn emit(s: &str) {
        unsafe {
            libc::write(1, s.as_ptr().cast::<c_void>(), s.len());
        }
    }

    fn emit_num(mut value: i64) {
        let mut buf = [0u8; 24];
        let mut at = buf.len();
        let negative = value < 0;
        if value == 0 {
            at -= 1;
            buf[at] = b'0';
        }
        while value != 0 {
            at -= 1;
            buf[at] = b'0' + (value % 10).unsigned_abs() as u8;
            value /= 10;
        }
        if negative {
            at -= 1;
            buf[at] = b'-';
        }
        unsafe {
            libc::write(1, buf.as_ptr().add(at).cast::<c_void>(), buf.len() - at);
        }
    }

    fn take() -> (i32, i32) {
        (
            SIGNO.swap(0, Ordering::SeqCst),
            CODE.swap(0, Ordering::SeqCst),
        )
    }

    fn try_read(addr: u64) -> (i32, i32) {
        take();
        unsafe {
            let _value: u64;
            core::arch::asm!("ldr {v}, [{a}]", a = in(reg) addr, v = out(reg) _value,
                options(nostack, readonly));
        }
        take()
    }

    fn try_write(addr: u64) -> (i32, i32) {
        take();
        unsafe {
            // Store back what is there, so a store that wrongly succeeds does
            // not corrupt whoever owns the backing.
            core::arch::asm!(
                "ldr {v}, [{a}]",
                "str {v}, [{a}]",
                a = in(reg) addr, v = out(reg) _, options(nostack));
        }
        take()
    }

    fn try_exec(addr: u64) -> (i32, i32) {
        take();
        unsafe {
            core::arch::asm!("blr {a}", a = in(reg) addr, clobber_abi("C"), out("x30") _);
        }
        take()
    }

    /// One byte per access: 0 no signal, 1/2 SIGSEGV si_code, 3 another
    /// signal reached the handler (4: the process was killed instead).
    fn encode((signo, code): (i32, i32)) -> u8 {
        match (signo, code) {
            (0, _) => 0,
            (libc::SIGSEGV, 1 | 2) => code as u8,
            _ => 3,
        }
    }

    /// `[start, end)` of every line of `/proc/self/maps`, read without the
    /// heap into a fixed buffer.
    fn own_mappings(out: &mut [(u64, u64); 128]) -> usize {
        let mut buf = [0u8; 16384];
        let fd = unsafe { libc::open(b"/proc/self/maps\0".as_ptr().cast(), libc::O_RDONLY) };
        if fd < 0 {
            return 0;
        }
        let mut len = 0;
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().add(len).cast(), buf.len() - len) };
            if n <= 0 {
                break;
            }
            len += n as usize;
            if len == buf.len() {
                break;
            }
        }
        unsafe { libc::close(fd) };
        let parse = |s: &[u8]| {
            s.iter().try_fold(0u64, |acc, &b| {
                let digit = (b as char).to_digit(16)?;
                acc.checked_mul(16)?.checked_add(u64::from(digit))
            })
        };
        let mut count = 0;
        for line in buf[..len].split(|&b| b == b'\n') {
            let range = line.split(|&b| b == b' ').next().unwrap_or(&[]);
            let mut bounds = range.split(|&b| b == b'-');
            if let (Some(Some(start)), Some(Some(end))) =
                (bounds.next().map(parse), bounds.next().map(parse))
            {
                if count < out.len() {
                    out[count] = (start, end);
                    count += 1;
                }
            }
        }
        count
    }

    /// `addr` when no mapping of this process covers it; otherwise the first
    /// 2 MiB boundary past the covering mapping (repeated), so the probe never
    /// lands next to a mapping the process does own (a dynamic probe's own
    /// interpreter).
    fn unmapped_at_or_above(mut addr: u64, maps: &[(u64, u64)]) -> u64 {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        loop {
            match maps
                .iter()
                .find(|(start, end)| *start <= addr && addr < *end)
            {
                Some((_, end)) => addr = (*end + TWO_MIB) & !(TWO_MIB - 1),
                None => return addr,
            }
        }
    }

    /// Probe every window; 3 bytes per window (read, write, exec). Each
    /// access runs in its own forked child, so an access that kills the
    /// process instead of reaching the handler is reported (as 4) without
    /// losing the others.
    fn sample(results: &mut [u8; WINDOWS.len() * 3]) {
        let mut maps = [(0u64, 0u64); 128];
        let count = own_mappings(&mut maps);
        for (index, (_, base)) in WINDOWS.iter().enumerate() {
            let addr = unmapped_at_or_above(*base, &maps[..count]);
            let one = [
                in_child(|| [encode(try_read(addr))]).map_or(4, |[byte]| byte),
                in_child(|| [encode(try_write(addr))]).map_or(4, |[byte]| byte),
                in_child(|| [encode(try_exec(addr))]).map_or(4, |[byte]| byte),
            ];
            results[index * 3..index * 3 + 3].copy_from_slice(&one);
        }
    }

    fn print(prefix: &str, results: &[u8; WINDOWS.len() * 3]) {
        for (index, (name, _)) in WINDOWS.iter().enumerate() {
            for (offset, kind) in ["read", "write", "exec"].iter().enumerate() {
                emit(prefix);
                emit(name);
                emit("_");
                emit(kind);
                emit(" segv_code=");
                emit_num(i64::from(results[index * 3 + offset]));
                emit("\n");
            }
        }
    }

    fn install() -> bool {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
            libc::sigemptyset(&mut action.sa_mask);
            [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL]
                .iter()
                .all(|&signo| libc::sigaction(signo, &action, std::ptr::null_mut()) == 0)
        }
    }

    /// Wait for `pid` for at most 5 s; `None` on timeout.
    fn bounded_wait(pid: libc::pid_t) -> Option<i32> {
        let mut status = 0;
        for _ in 0..5000 {
            let reaped = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if reaped == pid {
                return Some(status);
            }
            if reaped < 0 {
                return None;
            }
            unsafe { libc::usleep(1000) };
        }
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        None
    }

    /// Run `f` in a forked child that reports its bytes through a pipe;
    /// `None` when the child died or never reported.
    fn in_child<const N: usize>(f: impl FnOnce() -> [u8; N]) -> Option<[u8; N]> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        match unsafe { libc::fork() } {
            0 => {
                let results = f();
                unsafe {
                    libc::write(fds[1], results.as_ptr().cast(), N);
                    libc::_exit(0);
                }
            }
            pid if pid > 0 => {
                unsafe { libc::close(fds[1]) };
                let status = bounded_wait(pid);
                let mut results = [0u8; N];
                let got = unsafe { libc::read(fds[0], results.as_mut_ptr().cast(), N) };
                unsafe { libc::close(fds[0]) };
                (status.is_some() && got == N as isize).then_some(results)
            }
            _ => {
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                None
            }
        }
    }

    /// A MAP_SHARED mapping is gone after munmap.
    fn shared_after_munmap() -> (u8, u8) {
        let len = 4 * PAGE as usize;
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return (9, 9);
        }
        unsafe { (addr as *mut u64).write_volatile(1) };
        unsafe { libc::munmap(addr, len) };
        let addr = addr as u64 + PAGE;
        (encode(try_read(addr)), encode(try_write(addr)))
    }

    fn first_image() {
        let mut results = [0u8; WINDOWS.len() * 3];
        sample(&mut results);
        print("", &results);
        match in_child(|| {
            let mut results = [0u8; WINDOWS.len() * 3];
            sample(&mut results);
            results
        }) {
            Some(results) => print("fork_child_", &results),
            None => emit("fork_child_lost=true\n"),
        }
        let (read, write) = shared_after_munmap();
        emit("shared_after_munmap_read segv_code=");
        emit_num(i64::from(read));
        emit("\nshared_after_munmap_write segv_code=");
        emit_num(i64::from(write));
        emit("\n");
        let path = b"/proc/self/exe\0";
        let arg0 = b"carrierwindowaccess\0";
        let arg1 = b"after-exec\0";
        let argv = [
            arg0.as_ptr().cast::<libc::c_char>(),
            arg1.as_ptr().cast(),
            std::ptr::null(),
        ];
        unsafe { libc::execv(path.as_ptr().cast(), argv.as_ptr()) };
        emit("execv_failed=true\n");
    }

    pub fn main() {
        if !install() {
            emit("sigaction_ok=false\n");
            return;
        }
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == "after-exec")
        {
            let mut results = [0u8; WINDOWS.len() * 3];
            sample(&mut results);
            print("after_exec_", &results);
        } else {
            first_image();
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn main() {
    probe::main();
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("carrierwindowaccess requires aarch64");
}
