//! Differential coverage of wait-status core bits and sparse core publication.
//! Native Linux determines the signal-status observations. The sparse case
//! also checks that RLIMIT_CORE bounds the output file while PT_LOAD retains
//! the full logical mapping extent, with bounded child completion.

use conformance_probes::report;

unsafe fn enable_core_dumps() {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    libc::setrlimit(libc::RLIMIT_CORE, &lim);
    // PR_SET_DUMPABLE = 4. Some hardened environments demote the dumpable
    // flag after setuid/exec; we force it ON so the kernel will actually
    // attempt the dump (and set the bit).
    libc::prctl(4 /* PR_SET_DUMPABLE */, 1, 0, 0, 0);
}

/// Fork a child that immediately raises `sig` against itself, then reap.
/// Returns (signalled, coredumped).
unsafe fn fork_and_die_by(sig: i32) -> (bool, bool) {
    let pid = libc::fork();
    if pid == 0 {
        // Child: set default disposition for the signal so it actually kills
        // us (e.g. a parent's SIGQUIT handler must not leak into the child
        // for this test). Then raise.
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, core::ptr::null_mut());
        // Also unblock the signal in case the parent had it masked.
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut());
        libc::raise(sig);
        // raise() of a fatal default-disposition signal must not return.
        libc::_exit(99);
    }
    let mut status = 0i32;
    loop {
        let r = libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
        if r == -1 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
    }
    (libc::WIFSIGNALED(status), libc::WCOREDUMP(status))
}

/// Sparse mappings must not turn a small RLIMIT_CORE into reservation-sized
/// capture work. Preserve the logical PT_LOAD extent even when the file is
/// truncated. Linux charges emitted bytes, not seek-created holes, so the
/// logical file length may exceed the limit. Check allocated storage separately.
/// Every child wait and pipe read is bounded.
fn sparse_limited_core() {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};
    const LENGTH: usize = 64usize << 30;
    const LIMIT: u64 = 1 << 20;
    let dir = format!("/tmp/coredumpbit-sparse-{}", unsafe { libc::getpid() });
    let created = std::fs::create_dir(&dir).is_ok();
    let mut pipe = [-1; 2];
    let pipe_ok =
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } == 0;
    let mut child = -1;
    if created && pipe_ok {
        child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                libc::close(pipe[0]);
                if std::env::set_current_dir(&dir).is_err() {
                    libc::_exit(90);
                }
                let limit = libc::rlimit {
                    rlim_cur: LIMIT,
                    rlim_max: LIMIT,
                };
                let limit_errno = if libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 {
                    0
                } else {
                    *libc::__errno_location()
                };
                let base = libc::mmap(
                    core::ptr::null_mut(),
                    LENGTH,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                );
                let map_errno = if base == libc::MAP_FAILED {
                    *libc::__errno_location()
                } else {
                    0
                };
                let packet = [base as usize as u64, map_errno as u64, limit_errno as u64];
                if libc::write(
                    pipe[1],
                    packet.as_ptr().cast(),
                    core::mem::size_of_val(&packet),
                ) != 24
                {
                    libc::_exit(91);
                }
                libc::close(pipe[1]);
                if map_errno != 0 || limit_errno != 0 {
                    libc::_exit(92);
                }
                (base as *mut u8).write_volatile(17);
                (base as *mut u8).add(LENGTH - 4096).write_volatile(29);
                // Rust installs a SIGSEGV handler; restore the default and
                // unblock the signal just as the signal-bit cases above do.
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut action.sa_mask);
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGSEGV);
                if libc::sigaction(libc::SIGSEGV, &action, core::ptr::null_mut()) != 0
                    || libc::sigprocmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut()) != 0
                {
                    libc::_exit(94);
                }
                libc::raise(libc::SIGSEGV);
                libc::_exit(93);
            }
        }
    }
    if pipe_ok {
        unsafe {
            libc::close(pipe[1]);
        }
    }
    let mut status = 0;
    let mut reaped = false;
    if child > 0 {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
                reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !reaped {
            unsafe {
                libc::kill(child, libc::SIGKILL);
            }
            let end = Instant::now() + Duration::from_secs(1);
            while Instant::now() < end {
                if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
                    reaped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let mut packet = [u64::MAX; 3];
    let transport_ok =
        pipe_ok && unsafe { libc::read(pipe[0], packet.as_mut_ptr().cast(), 24) } == 24;
    if pipe_ok {
        unsafe {
            libc::close(pipe[0]);
        }
    }
    let mut core_size = 0;
    let mut allocated_bytes = 0;
    let mut elf = false;
    let mut extent = false;
    if created && reaped {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let Ok(file) = std::fs::File::open(entry.path()) else {
                    continue;
                };
                let Ok(meta) = file.metadata() else {
                    continue;
                };
                let mut bytes = Vec::new();
                if file.take(65536).read_to_end(&mut bytes).is_err() {
                    continue;
                }
                if bytes.get(..6) != Some(b"\x7fELF\x02\x01") {
                    continue;
                }
                elf = true;
                core_size = meta.len();
                allocated_bytes = meta.blocks() * 512;
                let u16_at = |i| {
                    bytes
                        .get(i..i + 2)
                        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                };
                let u64_at = |i| {
                    bytes
                        .get(i..i + 8)
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                };
                if let (Some(off), Some(size), Some(count)) = (u64_at(32), u16_at(54), u16_at(56)) {
                    for i in 0..usize::from(count) {
                        let Some(at) = (off as usize).checked_add(i * usize::from(size)) else {
                            break;
                        };
                        if bytes.get(at..at + 4) != Some(&1u32.to_le_bytes()) {
                            continue;
                        }
                        if let (Some(va), Some(filesz), Some(memsz)) =
                            (u64_at(at + 16), u64_at(at + 32), u64_at(at + 40))
                        {
                            extent |= transport_ok
                                && va <= packet[0]
                                && packet[0]
                                    .checked_add(LENGTH as u64)
                                    .zip(va.checked_add(memsz))
                                    .is_some_and(|(end, limit)| end <= limit)
                                && filesz >= LENGTH as u64;
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    report!(
        sparse_core_transport_ok = transport_ok,
        sparse_core_map_errno = packet[1],
        sparse_core_limit_errno = packet[2],
        sparse_core_reaped = reaped,
        sparse_core_wait_status = status,
        sparse_core_sigsegv =
            reaped && libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV,
        sparse_core_wcoredump = reaped && libc::WCOREDUMP(status),
        sparse_core_elf = elf,
        sparse_core_nonempty = core_size > 0,
        sparse_core_storage_within_limit = allocated_bytes > 0 && allocated_bytes <= LIMIT,
        sparse_core_full_load_extent = extent,
    );
}

fn main() {
    unsafe {
        enable_core_dumps();

        // Core-dumping signals: WCOREDUMP must be TRUE.
        let (sigabrt_term, sigabrt_core) = fork_and_die_by(libc::SIGABRT);
        let (sigsegv_term, sigsegv_core) = fork_and_die_by(libc::SIGSEGV);
        let (sigquit_term, sigquit_core) = fork_and_die_by(libc::SIGQUIT);

        // Non-core-dumping signals: WCOREDUMP must be FALSE. SIGTERM and
        // SIGKILL terminate the process but are NOT in the core-dumping set;
        // a synthesized 0x80 bit here would be a false positive.
        let (sigterm_term, sigterm_core) = fork_and_die_by(libc::SIGTERM);
        let (sigkill_term, sigkill_core) = fork_and_die_by(libc::SIGKILL);

        report!(
            sigabrt_wifsignaled = sigabrt_term,
            sigabrt_wcoredump_set = sigabrt_core,
            sigsegv_wifsignaled = sigsegv_term,
            sigsegv_wcoredump_set = sigsegv_core,
            sigquit_wifsignaled = sigquit_term,
            sigquit_wcoredump_set = sigquit_core,
            sigterm_wifsignaled = sigterm_term,
            sigterm_wcoredump_clear = !sigterm_core,
            sigkill_wifsignaled = sigkill_term,
            sigkill_wcoredump_clear = !sigkill_core,
        );
    }
    sparse_limited_core();
}
