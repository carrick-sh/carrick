//! Pages past the program break are not mapped, before or after an execve.
//!
//! Linux maps the heap a page at a time: `brk(b)` makes `[start_brk,
//! PAGE_ALIGN(b))` an anonymous read/write, non-executable mapping and leaves
//! everything above it unmapped. So an access in the break's own page past
//! `b` succeeds, an access in the next page faults with SIGSEGV (SEGV_MAPERR),
//! an instruction fetch from the heap faults with SIGSEGV (SEGV_ACCERR), a
//! shrunk range faults again, and a fresh image after execve sees nothing of
//! the previous image's heap.
//!
//! Carrick's HostSetup heap reuses one fixed heap window, and execve left the
//! previous image's heap leaves valid EL0 read/write/execute in the new
//! image's window: the old image's bytes stayed readable, writable and
//! executable past the new break until the new image's brk overwrote them.
//!
//! Each access is one instruction. The SIGSEGV/SIGBUS/SIGILL handler records
//! the signal number and `si_code`, then resumes after a data access or
//! returns to the caller of an instruction fetch. Raw `SYS_brk` is used
//! because musl's `sbrk()` fails every nonzero increment, and the break is
//! restored before any allocation so glibc's cached break stays true. Output
//! goes through heap-free `write(2)`. The fork wait is bounded at 5 s.

#[cfg(target_arch = "aarch64")]
mod probe {
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicI32, Ordering};

    const PAGE: u64 = 4096;
    /// How far the pre-exec image grows and fills its heap.
    const EXEC_FILL: u64 = 4 * 1024 * 1024;
    /// AArch64 `ret`.
    const RET: u32 = 0xd65f_03c0;
    /// Offsets past the post-exec page-aligned break that the previous image
    /// filled.
    const AFTER_EXEC_OFFSETS: [(&str, u64); 4] = [
        ("next_page", 0),
        ("plus_64k", 64 * 1024),
        ("plus_1m", 1024 * 1024),
        ("plus_3m", 3 * 1024 * 1024),
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
                // Instruction fetch: return to the `blr` site.
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

    /// `<prefix>_<kind> signal=<n> code=<n>` (code only when a signal arrived).
    fn report(prefix: &str, kind: &str, signo: i32, code: i32) {
        emit(prefix);
        emit("_");
        emit(kind);
        emit(" signal=");
        emit_num(i64::from(signo));
        if signo != 0 {
            emit(" code=");
            emit_num(i64::from(code));
        }
        emit("\n");
    }

    fn brk(addr: u64) -> u64 {
        unsafe { libc::syscall(libc::SYS_brk, addr) as u64 }
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
            core::arch::asm!("str {v:w}, [{a}]", a = in(reg) addr, v = in(reg) RET,
                options(nostack));
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

    fn check(addr: u64) -> [(i32, i32); 3] {
        [try_read(addr), try_write(addr), try_exec(addr)]
    }

    fn print_checks(prefix: &str, results: &[(i32, i32); 3]) {
        for (kind, (signo, code)) in ["read", "write", "exec"].iter().zip(results) {
            report(prefix, kind, *signo, *code);
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

    fn page_up(addr: u64) -> u64 {
        (addr + PAGE - 1) & !(PAGE - 1)
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

    fn before_exec() {
        let initial = brk(0);
        let aligned = page_up(initial);
        if brk(aligned) != aligned {
            emit("brk_align_ok=false\n");
            return;
        }

        // Same page past an unaligned break vs the next page.
        let unaligned = aligned + 100;
        let moved = brk(unaligned) == unaligned;
        let same = check(unaligned + 4);
        let next = check(aligned + PAGE);

        // Grow, fill, shrink: the released pages fault again.
        let grown_end = aligned + 16 * PAGE;
        let grew = brk(grown_end) == grown_end;
        for page in 0..16 {
            unsafe { ((aligned + page * PAGE) as *mut u32).write_volatile(RET) };
        }
        let shrunk = brk(aligned) == aligned;
        let after_shrink = check(aligned + 4 * PAGE);
        let regrow = brk(grown_end) == grown_end;
        let regrown_zero = unsafe { ((aligned + 4 * PAGE) as *const u32).read_volatile() } == 0;

        // A forked child that shrinks the break loses the range; the parent
        // keeps it.
        let fork_status = match unsafe { libc::fork() } {
            0 => {
                // 2 bits per read: 0 no signal, 1/2 SIGSEGV si_code, 3 other.
                let encode = |(signo, code): (i32, i32)| match (signo, code) {
                    (0, _) => 0,
                    (libc::SIGSEGV, 1 | 2) => code,
                    _ => 3,
                };
                let inside = encode(try_read(aligned + 4 * PAGE));
                let beyond = encode(try_read(grown_end + PAGE));
                brk(aligned);
                let shrunk = encode(try_read(aligned + 4 * PAGE));
                unsafe { libc::_exit(inside | (beyond << 2) | (shrunk << 4)) };
            }
            pid if pid > 0 => bounded_wait(pid),
            _ => None,
        };
        let parent_keeps = try_read(aligned + 4 * PAGE);
        let restored = brk(initial) == initial;

        emit("brk_moves_ok=");
        emit(if moved && grew && shrunk && regrow && restored {
            "true\n"
        } else {
            "false\n"
        });
        print_checks("same_page", &same);
        print_checks("next_page", &next);
        print_checks("after_shrink", &after_shrink);
        emit("regrown_zero=");
        emit(if regrown_zero { "true\n" } else { "false\n" });
        match fork_status {
            Some(status) if libc::WIFEXITED(status) => {
                let bits = libc::WEXITSTATUS(status);
                for (shift, name) in [(0, "inside"), (2, "beyond"), (4, "shrunk")] {
                    emit("fork_child_");
                    emit(name);
                    emit("_read segv_code=");
                    emit_num(i64::from((bits >> shift) & 3));
                    emit("\n");
                }
            }
            _ => emit("fork_child_lost=true\n"),
        }
        report("fork_parent", "read", parent_keeps.0, parent_keeps.1);

        // Grow and fill a large heap with `ret`, then replace the image.
        let start = brk(0);
        let fill_base = page_up(start);
        let fill_end = fill_base + EXEC_FILL;
        if brk(fill_end) != fill_end {
            emit("exec_fill_ok=false\n");
            return;
        }
        let mut page = fill_base;
        while page < fill_end {
            unsafe { (page as *mut u32).write_volatile(RET) };
            page += PAGE;
        }
        emit("exec_fill_ok=true\n");
        let path = b"/proc/self/exe\0";
        let arg0 = b"brkbeyondbreak\0";
        let arg1 = b"after-exec\0";
        let argv = [
            arg0.as_ptr().cast::<libc::c_char>(),
            arg1.as_ptr().cast(),
            std::ptr::null(),
        ];
        unsafe { libc::execv(path.as_ptr().cast(), argv.as_ptr()) };
        emit("execv_failed=true\n");
    }

    fn after_exec() {
        let aligned = page_up(brk(0));
        let mut results = [[(0, 0); 3]; AFTER_EXEC_OFFSETS.len()];
        for (slot, (_, offset)) in results.iter_mut().zip(AFTER_EXEC_OFFSETS) {
            *slot = check(aligned + offset);
        }
        for ((name, _), result) in AFTER_EXEC_OFFSETS.iter().zip(&results) {
            // No break manipulation follows, so this image may allocate.
            print_checks(&format!("after_exec_{name}"), result);
        }
    }

    pub fn main() {
        if !install() {
            emit("sigaction_ok=false\n");
            return;
        }
        let after = std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == "after-exec");
        if after {
            after_exec();
        } else {
            before_exec();
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn main() {
    probe::main();
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("brkbeyondbreak requires aarch64");
}
