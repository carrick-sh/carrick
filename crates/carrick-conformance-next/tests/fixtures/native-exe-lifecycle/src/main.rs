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

// Failure record after an `X` byte on a report pipe: holder pid (i32 LE),
// kind (`e` readlink errno, `x` execve errno, both i32 LE; `l` link bytes),
// payload length (u16 LE),
// payload. The observer prints it; the participant's stderr is not captured.
const FAILURE_HEADER: usize = 7;
const FAILURE_PAYLOAD_MAX: usize = 4096;

// Allocation-free; also used between vfork and _exit.
fn send_failure(fd: i32, kind: u8, payload: &[u8]) {
    let mut record = [0u8; FAILURE_HEADER + FAILURE_PAYLOAD_MAX];
    let len = payload.len().min(FAILURE_PAYLOAD_MAX);
    record[..4].copy_from_slice(&unsafe { libc::getpid() }.to_le_bytes());
    record[4] = kind;
    record[5..7].copy_from_slice(&(len as u16).to_le_bytes());
    record[FAILURE_HEADER..FAILURE_HEADER + len].copy_from_slice(&payload[..len]);
    unsafe {
        libc::write(fd, (&b'X' as *const u8).cast(), 1);
        libc::write(fd, record.as_ptr().cast(), FAILURE_HEADER + len);
    }
}

// Re-reads the link and sends what was actually observed.
fn send_link_failure(fd: i32) {
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
        send_failure(fd, b'e', &errno().to_le_bytes());
    } else {
        send_failure(fd, b'l', &bytes[..n as usize]);
    }
}

// Allocation-free stderr writer, safe between vfork and _exit.
fn err_bytes(bytes: &[u8]) {
    unsafe {
        libc::write(2, bytes.as_ptr().cast(), bytes.len());
    }
}

fn err_number(value: i64) {
    let mut digits = [0u8; 21];
    let mut at = digits.len();
    let mut rest = value.unsigned_abs();
    loop {
        at -= 1;
        digits[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if value < 0 {
        at -= 1;
        digits[at] = b'-';
    }
    err_bytes(&digits[at..]);
}

/// One-line diagnostic: the expected link, the bytes (or errno) actually read.
fn report_link(role: &[u8], expected: &[u8]) {
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
    err_bytes(role);
    err_bytes(b": readlinkat(/proc/self/exe) pid=");
    err_number(unsafe { libc::getpid() } as i64);
    err_bytes(b" expected=[");
    err_bytes(expected);
    if n < 0 {
        err_bytes(b"] errno=");
        err_number(errno() as i64);
    } else {
        err_bytes(b"] actual=[");
        err_bytes(&bytes[..n as usize]);
        err_bytes(b"]");
    }
    err_bytes(b"\n");
}

fn check_link(expected: &str) {
    if link_matches(expected.as_bytes()).is_err() {
        report_link(b"check_link", expected.as_bytes());
        panic!("running caller readlinkat(/proc/self/exe) did not name {expected}");
    }
}

/// Holder's first observation: on failure tell the observer (`X`) before the
/// pipe closes, so EOF is never the only symptom.
fn holder_check(expected: &str, output: i32) {
    if link_matches(expected.as_bytes()).is_err() {
        report_link(b"holder", expected.as_bytes());
        send_link_failure(output);
        unsafe {
            libc::_exit(121);
        }
    }
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

fn receive(fd: i32, role: &str) -> u8 {
    let mut ready = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut ready, 1, 5000) },
        1,
        "bounded handshake {role} fd={fd}"
    );
    let mut byte = 0;
    let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
    assert_eq!(
        n,
        1,
        "{role} (fd={fd}): participant exited before its observation (read={n} errno={})",
        errno()
    );
    if byte == b'X' {
        panic!(
            "{role} (fd={fd}): participant reported failure: {}",
            read_failure(fd)
        );
    }
    byte
}

fn read_exact_bounded(fd: i32, out: &mut [u8]) -> bool {
    let mut got = 0;
    while got < out.len() {
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut ready, 1, 5000) } != 1 {
            return false;
        }
        let n = unsafe { libc::read(fd, out[got..].as_mut_ptr().cast(), out.len() - got) };
        if n <= 0 {
            return false;
        }
        got += n as usize;
    }
    true
}

// Describes the record `send_failure` wrote after an `X` byte.
fn read_failure(fd: i32) -> String {
    let mut header = [0u8; FAILURE_HEADER];
    if !read_exact_bounded(fd, &mut header) {
        return "no failure detail followed the report".to_owned();
    }
    let pid = i32::from_le_bytes(header[..4].try_into().unwrap());
    let len = u16::from_le_bytes(header[5..7].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len.min(FAILURE_PAYLOAD_MAX)];
    if !read_exact_bounded(fd, &mut payload) {
        return format!("holder pid={pid}: truncated failure detail");
    }
    match header[4] {
        b'e' | b'x' if payload.len() == 4 => format!(
            "participant pid={pid} {} errno={}",
            if header[4] == b'x' {
                "execve failed"
            } else {
                "readlinkat(/proc/self/exe) failed"
            },
            i32::from_le_bytes(payload[..4].try_into().unwrap())
        ),
        b'l' => format!(
            "holder pid={pid} actual link=[{}] (len {})",
            String::from_utf8_lossy(&payload),
            payload.len()
        ),
        kind => format!("holder pid={pid}: unknown detail kind {kind}"),
    }
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
    assert_eq!(receive(result[0], "fork child result"), b'F');
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
    assert_eq!(
        receive(result[0], "vfork child result"),
        0,
        "vfork caller readlink errno"
    );
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
        assert_eq!(receive(release[0], "thread release"), b'Q');
        check_link(&worker_expected);
    });
    assert_eq!(receive(ready[0], "thread ready"), b'T');
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
    holder_check(&expected, output); // First syscall observation after real exec/adoption.
    send(output, b'I');
    loop {
        let command = receive(input, "holder command");
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
            err_bytes(b"holder execve failed errno=");
            err_number(errno() as i64);
            err_bytes(b"\n");
            send_failure(output[1], b'x', &errno().to_le_bytes());
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
    for (child, expected) in [(first, &a), (second, &b)] {
        let role = format!("holder report expected link=[{}]", expected.display());
        assert_eq!(receive(child.2, &role), b'I');
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
            assert_eq!(receive(child.2, "holder report"), *command);
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
