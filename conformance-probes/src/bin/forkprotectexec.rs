//! Inherited COW execute-permission enforcement across fork.
//!
//! On Linux, anonymous private memory is inherited copy-on-write across fork.
//! Permission changes (mprotect) in a child process on inherited COW pages must
//! properly isolate child execution permissions from the parent:
//! - Dropping PROT_EXEC in the child on an inherited RWX page must cause
//!   subsequent instruction fetch in the child to fault with SIGSEGV (NX).
//! - Adding PROT_EXEC in the child on an inherited RW page must permit instruction
//!   fetch in the child to execute cleanly (exit 0).
//! - Neither operation disarms or modifies the parent's mapping permissions.
//! - Single-page mprotect on multi-page mappings must isolate the target page
//!   without corrupting neighbor pages.
//!
//! Parent sets up memory and fills the architecture's one-instruction `ret`
//! BEFORE fork. The child does no writes before mprotect, testing the active
//! COW state directly.
//!
//! Deterministic: reports boolean invariants only. Setup failures panic with
//! distinct diagnostics. Exact child PID reaped with EINTR retry and alarm
//! watchdogs in both child and parent.

use conformance_probes::report;

#[cfg(target_arch = "aarch64")]
unsafe fn fill_ret_and_sync(p: *mut u8, len: usize) {
    const RET: u32 = 0xd65f_03c0; // aarch64 `ret`
    let w = p as *mut u32;
    for i in 0..len / 4 {
        w.add(i).write(RET);
    }
    // Only EL0-legal barriers (dsb/isb) — NOT `dc cvau`/`ic ivau` or cacheflush,
    // which require SCTLR_EL1.UCI and would trap at EL0 on hosts without it,
    // confounding permission checks with trapped cache ops.
    core::arch::asm!("dsb ish");
    core::arch::asm!("isb");
}

#[cfg(target_arch = "x86_64")]
unsafe fn fill_ret_and_sync(p: *mut u8, len: usize) {
    // x86-64 `ret` = 0xC3: call to offset 0 returns immediately. Coherent
    // unified instruction cache for fresh page requires no explicit i-cache sync.
    for i in 0..len {
        p.add(i).write(0xC3);
    }
}

#[inline]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn sig_segv(status: libc::c_int) -> bool {
    libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV
}

fn fetch_allowed(status: libc::c_int) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

unsafe fn alloc_anon(len: usize, prot: libc::c_int) -> *mut u8 {
    let p = libc::mmap(
        core::ptr::null_mut(),
        len,
        prot,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        panic!("mmap({len}, {prot:#x}) failed: errno={}", errno());
    }
    p as *mut u8
}

unsafe fn reap_child(pid: libc::pid_t) -> libc::c_int {
    let mut status = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, 0);
        if rc == -1 {
            let err = errno();
            if err == libc::EINTR {
                continue;
            }
            panic!("waitpid({pid}) failed: errno={err}");
        }
        if rc != pid {
            panic!("waitpid({pid}) returned unexpected pid={rc}");
        }
        return status;
    }
}

/// Run an execution test in a child process.
///
/// If `mprotect_spec` is provided, the child calls `mprotect(addr, len, prot)`
/// before attempting execution. The child then casts `target_addr` to a function
/// pointer and calls it. If instruction fetch is permitted, `ret` executes and
/// the child exits 0. If prohibited, instruction fetch faults with SIGSEGV.
unsafe fn fork_and_test(
    target_addr: *mut u8,
    mprotect_spec: Option<(*mut u8, usize, libc::c_int)>,
) -> libc::c_int {
    // Bound each owned child independently, including when earlier cases timed out.
    libc::alarm(10);
    let pid = libc::fork();
    if pid < 0 {
        panic!("fork() failed: errno={}", errno());
    }
    if pid == 0 {
        // Child alarm watchdog: Linux alarms are not inherited across fork.
        // A shorter child alarm ensures a wedged execution terminates with
        // SIGALRM, completing the parent's exact reap and leaving no orphans.
        libc::alarm(3);
        if let Some((addr, len, prot)) = mprotect_spec {
            if libc::mprotect(addr as *mut libc::c_void, len, prot) != 0 {
                libc::_exit(10); // Distinct setup failure
            }
        }
        let f: extern "C" fn() = core::mem::transmute(target_addr);
        f();
        libc::_exit(0);
    }
    let status = reap_child(pid);
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 10 {
        panic!("child mprotect setup failed (exit 10)");
    }
    status
}

fn main() {
    unsafe {
        // Suppress core dumps from expected SIGSEGV child terminations.
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            panic!("setrlimit(RLIMIT_CORE) failed: errno={}", errno());
        }

        // Bounded alarm watchdog: prevent harness hangs if execution wedges.
        libc::alarm(10);

        let sc_page = libc::sysconf(libc::_SC_PAGESIZE);
        if sc_page <= 0 {
            panic!("sysconf(_SC_PAGESIZE) failed: errno={}", errno());
        }
        let page_size = sc_page as usize;

        // Setup mappings and deposit ret code in parent BEFORE fork.
        // No writes will be performed in child before mprotect/jump so COW remains armed.
        let rwx_page = alloc_anon(
            page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );
        fill_ret_and_sync(rwx_page, page_size);

        let rw_page = alloc_anon(page_size, libc::PROT_READ | libc::PROT_WRITE);
        fill_ret_and_sync(rw_page, page_size);

        let neighbor_pages = alloc_anon(
            2 * page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );
        fill_ret_and_sync(neighbor_pages, 2 * page_size);

        // Control 1: Parent initial RWX mapping allows execution.
        let rwx_ctrl = fork_and_test(rwx_page, None);

        // Control 2: Parent initial RW mapping faults on execution.
        let rw_ctrl = fork_and_test(rw_page, None);

        // Case 1: Child inherits RWX page, mprotects RWX -> RW (drop EXEC), jump must fault SIGSEGV.
        let drop_exec = fork_and_test(
            rwx_page,
            Some((rwx_page, page_size, libc::PROT_READ | libc::PROT_WRITE)),
        );

        // Case 2: Child inherits RW page, mprotects RW -> RWX (add EXEC), jump must exit 0.
        let add_exec = fork_and_test(
            rw_page,
            Some((
                rw_page,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            )),
        );

        // Case 3 (Neighbor): Child inherits 2-page RWX mapping, mprotects page 0 to RW.
        // Execution on page 0 must fault SIGSEGV.
        let neighbor_drop = fork_and_test(
            neighbor_pages,
            Some((
                neighbor_pages,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )),
        );

        // Case 4 (Neighbor): Execution on retained page 1 must succeed (exit 0).
        let page1 = neighbor_pages.add(page_size);
        let neighbor_retain = fork_and_test(
            page1,
            Some((
                neighbor_pages,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )),
        );

        // Control 3: Parent's RWX mapping remains executable after child mutations.
        let rwx_post = fork_and_test(rwx_page, None);

        // Control 4: Parent's RW mapping remains non-executable after child mutations.
        let rw_post = fork_and_test(rw_page, None);

        report!(
            parent_rwx_control_exec = fetch_allowed(rwx_ctrl),
            parent_rw_control_faults = sig_segv(rw_ctrl),
            child_cow_drop_exec_faults = sig_segv(drop_exec),
            child_cow_add_exec_allowed = fetch_allowed(add_exec),
            neighbor_dropped_page_faults = sig_segv(neighbor_drop),
            neighbor_retained_page_allowed = fetch_allowed(neighbor_retain),
            parent_rwx_post_child_exec = fetch_allowed(rwx_post),
            parent_rw_post_child_faults = sig_segv(rw_post),
        );

        libc::munmap(rwx_page as *mut libc::c_void, page_size);
        libc::munmap(rw_page as *mut libc::c_void, page_size);
        libc::munmap(neighbor_pages as *mut libc::c_void, 2 * page_size);
        libc::alarm(0);
    }
}
