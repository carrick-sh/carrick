//! `vfork-exec-siblings [workers] [rounds]` (#2890, #2924): the shape of the
//! Go runtime's `fork/exec` once it runs more than one P, on ARM. Worker
//! threads map, touch and unmap anonymous memory and yield in a loop, while
//! a spawner thread `vfork`s and execs this image (`vfork-exec-child`, which
//! exits 0) `rounds` times. While the vfork child runs on the shared address
//! space the spawner is suspended and the workers keep editing it.
//!
//! Prints `vfork-exec-siblings ok rounds=N` and exits 0. Otherwise it prints
//! what failed and exits: 94 a failed `vfork` (its errno printed), 95 a child
//! that did not exit 0 (its wait status printed; an exec failure exits with
//! the errno), 98 threads that did not finish within 30 seconds, 99 a memory
//! edit that did not answer as Linux does (a negative mmap or a nonzero
//! munmap).
use std::ffi::CString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SPAN: usize = 16 * 4096;

fn edit_memory(stop: &AtomicBool, bad: &AtomicUsize) {
    while !stop.load(Ordering::Acquire) {
        // SAFETY: a fresh private anonymous mapping this thread owns alone.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SPAN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            bad.fetch_add(1, Ordering::AcqRel);
            break;
        }
        for offset in (0..SPAN).step_by(4096) {
            // SAFETY: inside the mapping above.
            unsafe { std::ptr::write_volatile(map.cast::<u8>().add(offset), 1) };
        }
        // SAFETY: unmaps exactly the mapping above.
        if unsafe { libc::munmap(map, SPAN) } != 0 {
            bad.fetch_add(1, Ordering::AcqRel);
        }
        // SAFETY: no arguments.
        unsafe { libc::sched_yield() };
    }
}

/// One `vfork` and exec of `path`. The child touches only what was built
/// before the `vfork` and makes system calls, as Go's child does.
fn vfork_exec(path: &CString, argv: &[*const libc::c_char; 3]) -> Result<i32, i32> {
    let envp = [std::ptr::null::<libc::c_char>()];
    #[allow(deprecated)]
    // SAFETY: the child calls only execve and _exit on prepared pointers.
    let pid = unsafe { libc::vfork() };
    if pid == 0 {
        // SAFETY: prepared, NUL-terminated argument vectors.
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(*libc::__errno_location());
        }
    }
    if pid < 0 {
        // SAFETY: reads this thread's errno.
        return Err(unsafe { *libc::__errno_location() });
    }
    let mut status = -1;
    // SAFETY: waits for the child this thread just created.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited != pid {
        return Ok(-1);
    }
    Ok(status)
}

pub fn vfork_exec_siblings(argv0: &str, workers: usize, rounds: usize) -> i32 {
    let stop = Arc::new(AtomicBool::new(false));
    let bad = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..workers {
        let stop = stop.clone();
        let bad = bad.clone();
        threads.push(std::thread::spawn(move || edit_memory(&stop, &bad)));
    }
    let done = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicI32::new(0));
    let failed_round = Arc::new(AtomicI32::new(-1));
    let failed_clone = Arc::new(AtomicBool::new(false));
    let spawner = {
        let path = CString::new(argv0).expect("argv0");
        let done = done.clone();
        let failed = failed.clone();
        let failed_round = failed_round.clone();
        let failed_clone = failed_clone.clone();
        std::thread::spawn(move || {
            let arg0 = CString::new("el1-sched").expect("arg0");
            let arg1 = CString::new("vfork-exec-child").expect("arg1");
            let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
            for round in 0..rounds {
                match vfork_exec(&path, &argv) {
                    Ok(0) => done.store(round + 1, Ordering::Release),
                    Ok(status) => {
                        failed.store(status, Ordering::Release);
                        failed_round.store(round as i32, Ordering::Release);
                        break;
                    }
                    Err(errno) => {
                        failed.store(errno, Ordering::Release);
                        failed_round.store(round as i32, Ordering::Release);
                        failed_clone.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        })
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !spawner.is_finished() {
        if Instant::now() > deadline {
            println!(
                "vfork-exec-siblings timeout rounds={}",
                done.load(Ordering::Acquire)
            );
            return 98;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = spawner.join();
    stop.store(true, Ordering::Release);
    for thread in threads {
        let _ = thread.join();
    }
    let round = failed_round.load(Ordering::Acquire);
    if round >= 0 {
        let failed = failed.load(Ordering::Acquire);
        if failed_clone.load(Ordering::Acquire) {
            println!("vfork-exec-siblings round={round} vfork errno={failed}");
            return 94;
        }
        println!("vfork-exec-siblings round={round} status={failed:#06x}");
        return 95;
    }
    let bad = bad.load(Ordering::Acquire);
    if bad != 0 {
        println!("vfork-exec-siblings bad-edits={bad}");
        return 99;
    }
    println!("vfork-exec-siblings ok rounds={rounds}");
    0
}
