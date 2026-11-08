//! Real executable populations: no dispatcher injection or custody construction.
//! Every identity observation is the running caller's readlinkat syscall.
// This standalone guest deliberately exercises the Linux syscall ABI; it is
// not a carrier host-service implementation. Native runs only qualify it.
#![allow(clippy::disallowed_methods)]

use std::ffi::{CStr, CString};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

// Also used between vfork and _exit: no allocation, locks or libc stdio.
fn link_matches(expected: &[u8]) -> Result<(), i32> {
    let mut bytes = [0u8; 4096];
    let n = unsafe {
        libc::syscall(
            libc::SYS_readlinkat,
            libc::AT_FDCWD,
            c"/proc/self/exe".as_ptr(),
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    };
    if n < 0 {
        Err(errno())
    } else if bytes[..n as usize] == *expected {
        Ok(())
    } else {
        Err(-1)
    }
}

fn check_link(expected: &str) {
    assert_eq!(
        link_matches(expected.as_bytes()),
        Ok(()),
        "running caller readlinkat(/proc/self/exe), expected {expected}; positive error is Linux errno"
    );
}

fn pipe() -> [i32; 2] {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    fds
}

fn send(fd: i32, byte: u8) {
    assert_eq!(
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) },
        1
    );
}

fn receive(fd: i32) -> u8 {
    let mut ready = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut ready, 1, 5000) },
        1,
        "bounded handshake fd={fd}"
    );
    let mut byte = 0;
    assert_eq!(
        unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) },
        1,
        "participant exited before its observation"
    );
    byte
}

fn kill_and_reap(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let n = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        if n == pid || (n < 0 && errno() == libc::ECHILD) {
            return;
        }
        if Instant::now() >= deadline {
            eprintln!("cleanup could not reap participant {pid}");
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn reap(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut status = 0;
    loop {
        let n = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if n == pid {
            assert_eq!(status, 0, "participant {pid} failed");
            return;
        }
        assert_eq!(n, 0);
        if Instant::now() >= deadline {
            kill_and_reap(pid);
            panic!("bounded reap of {pid}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn fork_read(expected: &str) {
    let result = pipe();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        check_link(expected);
        send(result[1], b'F');
        unsafe { libc::_exit(0) }
    }
    assert_eq!(receive(result[0]), b'F');
    check_link(expected);
    reap(pid);
    for fd in result {
        unsafe {
            libc::close(fd);
        }
    }
}

// CLONE_VM|CLONE_VFORK is Linux vfork with a private child stack. Returning
// twice through a Rust frame with libc::vfork would corrupt the shared stack.
extern "C" fn vfork_child(argument: *mut libc::c_void) -> i32 {
    // SAFETY: the suspended parent retains this immutable argument until exit.
    let (expected, output) = unsafe { &*argument.cast::<(&str, i32)>() };
    let code = match link_matches(expected.as_bytes()) {
        Ok(()) => 0,
        Err(e) if e > 0 => e,
        Err(_) => 127,
    };
    let byte = code as u8;
    unsafe {
        libc::write(*output, (&byte as *const u8).cast(), 1);
        libc::_exit(code);
    }
}

fn vfork_read(expected: &str) {
    let result = pipe();
    let mut argument = (expected, result[1]);
    let mut stack = vec![0u128; 4096];
    let top = unsafe { stack.as_mut_ptr().add(stack.len()).cast() };
    let pid = unsafe {
        libc::clone(
            vfork_child,
            top,
            libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD,
            (&mut argument as *mut (&str, i32)).cast(),
        )
    };
    assert!(pid >= 0);
    assert_eq!(receive(result[0]), 0, "vfork caller readlink errno");
    check_link(expected);
    reap(pid);
    for fd in result {
        unsafe {
            libc::close(fd);
        }
    }
}

fn thread_read(expected: &str) {
    let expected = expected.to_owned();
    let ready = pipe();
    let release = pipe();
    let worker_expected = expected.clone();
    let worker = std::thread::spawn(move || {
        check_link(&worker_expected);
        send(ready[1], b'T');
        assert_eq!(receive(release[0]), b'Q');
        check_link(&worker_expected);
    });
    assert_eq!(receive(ready[0]), b'T');
    check_link(&expected); // Worker is live, waiting for this leader.
    send(release[1], b'Q');
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "bounded thread completion");
        std::thread::sleep(Duration::from_millis(1));
    }
    worker.join().unwrap();
    for fd in [ready[0], ready[1], release[0], release[1]] {
        unsafe {
            libc::close(fd);
        }
    }
}

fn failed_exec(expected: &str) {
    let argv = [c"missing".as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    assert_eq!(
        unsafe {
            libc::execve(
                c"/definitely-missing-native-exe".as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        },
        -1
    );
    assert_eq!(errno(), 2);
    check_link(expected); // Running caller's MM, not a saved local executable.
}

fn holder(args: &[String]) {
    let mut expected = args[2].clone();
    let input: i32 = args[3].parse().unwrap();
    let output: i32 = args[4].parse().unwrap();
    check_link(&expected); // First syscall observation after real exec/adoption.
    send(output, b'I');
    loop {
        let command = receive(input);
        match command {
            b'F' => fork_read(&expected),
            b'V' => vfork_read(&expected),
            b'T' => thread_read(&expected),
            b'E' => failed_exec(&expected),
            b'R' => {
                expected.push_str(".renamed");
                check_link(&expected);
            }
            b'U' => {
                expected.push_str(" (deleted)");
                check_link(&expected);
            }
            b'Q' => return,
            _ => panic!("invalid command"),
        }
        send(output, command);
    }
}

fn start(path: &CStr, expected: &str) -> (i32, i32, i32) {
    let input = pipe();
    let output = pipe();
    let expected = CString::new(expected).unwrap();
    let input_arg = CString::new(input[0].to_string()).unwrap();
    let output_arg = CString::new(output[1].to_string()).unwrap();
    let argv = [
        path.as_ptr(),
        c"--holder".as_ptr(),
        expected.as_ptr(),
        input_arg.as_ptr(),
        output_arg.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::close(input[1]);
            libc::close(output[0]);
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(120);
        }
    }
    unsafe {
        libc::close(input[0]);
        libc::close(output[1]);
    }
    (pid, input[1], output[0])
}

// Failure cleanup is scoped to the actual children, never a process-name kill.
struct Population(Vec<(i32, i32, i32)>);
impl Drop for Population {
    fn drop(&mut self) {
        for child in &self.0 {
            kill_and_reap(child.0);
            unsafe {
                libc::close(child.1);
                libc::close(child.2);
            }
        }
    }
}

struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--holder") {
        holder(&args);
        return;
    }
    let mode = args.get(1).expect("scenario");
    println!(
        "fixture_source_sha256={}",
        env!("CARRICK_NATIVE_EXE_SOURCE_SHA256")
    );
    assert!(matches!(
        mode.as_str(),
        "populations" | "fork" | "vfork" | "thread" | "failed" | "mutations"
    ));
    // argv[0] is an absolute fixture path. No /proc lookup can fail in driver
    // setup before the native child reaches the syscall under test.
    let source = std::path::Path::new(&args[0]).canonicalize().unwrap();
    let directory =
        std::env::temp_dir().join(format!("native-exe-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(directory.join("bin")).unwrap();
    let _cleanup = Directory(directory.clone());
    let a = directory.join("bin/a");
    let b = directory.join("bin/b");
    for path in [&a, &b] {
        std::fs::copy(&source, path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let link = directory.join("launch-b");
    std::os::unix::fs::symlink("bin/b", &link).unwrap();
    // A executes a relative pathname; B executes a final symlink. Both are
    // native fork children and MUST prepare/adopt before their first read.
    std::env::set_current_dir(&directory).unwrap();
    let mut population = Population(Vec::new());
    let first = start(c"bin/a", a.to_str().unwrap());
    population.0.push(first);
    let second = start(
        &CString::new(link.to_str().unwrap()).unwrap(),
        b.to_str().unwrap(),
    );
    population.0.push(second);
    for child in [first, second] {
        assert_eq!(receive(child.2), b'I');
    }
    println!("two_live_distinct_relative_symlink=ok");
    let commands: &[u8] = match mode.as_str() {
        "populations" => b"",
        "fork" => b"F",
        "vfork" => b"V",
        "thread" => b"T",
        "failed" => b"E",
        "mutations" => b"RU",
        _ => unreachable!(),
    };
    for command in commands {
        // Root dispatch publishes changes while BOTH native holders are live.
        if *command == b'R' {
            for path in [&a, &b] {
                std::fs::rename(path, path.with_extension("renamed")).unwrap();
            }
        } else if *command == b'U' {
            for path in [&a, &b] {
                std::fs::remove_file(path.with_extension("renamed")).unwrap();
            }
        }
        for child in [first, second] {
            send(child.1, *command);
        }
        for child in [first, second] {
            assert_eq!(receive(child.2), *command);
        }
        println!("{}_both_live=ok", char::from(*command));
    }
    for child in [first, second] {
        send(child.1, b'Q');
    }
    while let Some(child) = population.0.pop() {
        // reap owns timeout cleanup; a failed exit must not leave a reaped
        // PID in the population's Drop path.
        reap(child.0);
        unsafe {
            libc::close(child.1);
            libc::close(child.2);
        }
    }
    std::env::set_current_dir("/").unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    println!("cleanup=ok");
}
