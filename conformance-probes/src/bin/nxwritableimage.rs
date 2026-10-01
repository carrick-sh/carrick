//! Writable memory a process did not map PROT_EXEC does not execute.
//!
//! Linux (arm64): the ELF loader maps each PT_LOAD with that segment's
//! permissions, so `.data` and `.bss` are read/write and non-executable; the
//! main stack, the `brk` heap and an anonymous read/write mapping are
//! non-executable too. An instruction fetch from any of them is SIGSEGV with
//! SEGV_ACCERR.
//!
//! Carrick merged an image's segments into one region whose stage-1 leaves
//! cleared UXN, and its stack and grown heap leaves came from helpers that
//! defaulted to executable, so `.data`, `.bss`, the stack and the `brk` heap
//! ran code written into them, in the first image, in a forked child and
//! after an execve.
//!
//! Each region gets one `ret` written into it and is then called. The
//! SIGSEGV/SIGBUS/SIGILL handler records the signal and `si_code` and returns
//! to the call site. Raw `SYS_brk` is used because musl's `sbrk()` fails
//! every nonzero increment. Output uses heap-free `write(2)`; the fork wait is
//! bounded at 5 s.

#[cfg(target_arch = "aarch64")]
mod probe {
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicI32, Ordering};

    const PAGE: u64 = 4096;
    /// AArch64 `ret`.
    const RET: u32 = 0xd65f_03c0;
    const REGIONS: [&str; 6] = ["data", "bss", "stack", "brk_heap", "malloc_heap", "mmap_rw"];

    static mut DATA: [u32; 16] = [RET; 16];
    static mut BSS: [u32; 16] = [0; 16];

    static SIGNO: AtomicI32 = AtomicI32::new(0);
    static CODE: AtomicI32 = AtomicI32::new(0);

    extern "C" fn handler(signo: i32, info: *mut libc::siginfo_t, context: *mut c_void) {
        unsafe {
            SIGNO.store(signo, Ordering::SeqCst);
            CODE.store((*info).si_code, Ordering::SeqCst);
            let context = context.cast::<libc::ucontext_t>();
            let mcontext = &mut (*context).uc_mcontext;
            mcontext.pc = mcontext.regs[30];
        }
    }

    fn emit(s: &str) {
        unsafe {
            libc::write(1, s.as_ptr().cast::<c_void>(), s.len());
        }
    }

    fn emit_num(value: u8) {
        let digit = [b'0' + value];
        unsafe {
            libc::write(1, digit.as_ptr().cast::<c_void>(), 1);
        }
    }

    fn take() -> (i32, i32) {
        (
            SIGNO.swap(0, Ordering::SeqCst),
            CODE.swap(0, Ordering::SeqCst),
        )
    }

    /// Write `ret` at `code`, make it visible to instruction fetch, call it.
    /// 0: it ran; 1/2: SIGSEGV si_code; 3: another signal.
    fn exec_at(code: *mut u32) -> u8 {
        let addr = code as u64;
        unsafe {
            code.write_volatile(RET);
            core::arch::asm!(
                "dc cvau, {a}",
                "dsb ish",
                "ic ivau, {a}",
                "dsb ish",
                "isb",
                a = in(reg) addr,
                options(nostack)
            );
        }
        take();
        unsafe {
            core::arch::asm!("blr {a}", a = in(reg) addr, clobber_abi("C"), out("x30") _);
        }
        match take() {
            (0, _) => 0,
            (libc::SIGSEGV, code @ (1 | 2)) => code as u8,
            _ => 3,
        }
    }

    #[inline(never)]
    fn exec_on_stack() -> u8 {
        let mut stack = [0u32; 16];
        let result = exec_at(stack.as_mut_ptr());
        core::hint::black_box(&mut stack);
        result
    }

    fn sample(results: &mut [u8; REGIONS.len()]) {
        results[0] = exec_at(core::ptr::addr_of_mut!(DATA).cast());
        results[1] = exec_at(core::ptr::addr_of_mut!(BSS).cast());
        results[2] = exec_on_stack();
        let start = unsafe { libc::syscall(libc::SYS_brk, 0) } as u64;
        let aligned = (start + PAGE - 1) & !(PAGE - 1);
        let end = aligned + PAGE;
        results[3] = if unsafe { libc::syscall(libc::SYS_brk, end) } as u64 == end {
            let result = exec_at(aligned as *mut u32);
            unsafe { libc::syscall(libc::SYS_brk, start) };
            result
        } else {
            9
        };
        let heap = Box::into_raw(Box::new([0u32; 16]));
        results[4] = exec_at(heap.cast());
        drop(unsafe { Box::from_raw(heap) });
        let anon = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        results[5] = if anon == libc::MAP_FAILED {
            9
        } else {
            let result = exec_at(anon.cast());
            unsafe { libc::munmap(anon, PAGE as usize) };
            result
        };
    }

    fn print(prefix: &str, results: &[u8; REGIONS.len()]) {
        for (name, result) in REGIONS.iter().zip(results) {
            emit(prefix);
            emit(name);
            emit("_exec segv_code=");
            emit_num(*result);
            emit("\n");
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

    fn sample_in_child() -> Option<[u8; REGIONS.len()]> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        match unsafe { libc::fork() } {
            0 => {
                let mut results = [0u8; REGIONS.len()];
                sample(&mut results);
                unsafe {
                    libc::write(fds[1], results.as_ptr().cast(), results.len());
                    libc::_exit(0);
                }
            }
            pid if pid > 0 => {
                unsafe { libc::close(fds[1]) };
                let status = bounded_wait(pid);
                let mut results = [0u8; REGIONS.len()];
                let got = unsafe { libc::read(fds[0], results.as_mut_ptr().cast(), results.len()) };
                unsafe { libc::close(fds[0]) };
                (status.is_some() && got == results.len() as isize).then_some(results)
            }
            _ => None,
        }
    }

    pub fn main() {
        if !install() {
            emit("sigaction_ok=false\n");
            return;
        }
        let mut results = [0u8; REGIONS.len()];
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == "after-exec")
        {
            sample(&mut results);
            print("after_exec_", &results);
            return;
        }
        sample(&mut results);
        print("", &results);
        match sample_in_child() {
            Some(results) => print("fork_child_", &results),
            None => emit("fork_child_lost=true\n"),
        }
        let path = b"/proc/self/exe\0";
        let arg0 = b"nxwritableimage\0";
        let arg1 = b"after-exec\0";
        let argv = [
            arg0.as_ptr().cast::<libc::c_char>(),
            arg1.as_ptr().cast(),
            std::ptr::null(),
        ];
        unsafe { libc::execv(path.as_ptr().cast(), argv.as_ptr()) };
        emit("execv_failed=true\n");
    }
}

#[cfg(target_arch = "aarch64")]
fn main() {
    probe::main();
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("nxwritableimage requires aarch64");
}
