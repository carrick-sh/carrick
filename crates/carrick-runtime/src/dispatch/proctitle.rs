//! Host process-title management for carrick.
//!
//! macOS shows the contents of `argv[0]` (and the rest of the argv array) in
//! `ps`, Activity Monitor and friends. Overwriting `argv[0]` in place is the
//! libuv/Node trick for setting `process.title` — but it caps the writable
//! window at `strlen(argv[0])`, which can be as short as `7` (just `carrick`)
//! when the binary is on $PATH. That's not enough room for the full
//! `carrick: <guest-name>` label we want.
//!
//! `libuv` and PostgreSQL widen that window by **relocating the environment**:
//! `argv[0]` … `argv[argc-1]` and `environ[0]` … `environ[n-1]` are laid out
//! by the kernel in one contiguous run of bytes at the top of the user stack.
//! If we `strdup` every `environ[i]` onto the heap and repoint `*_NSGetEnviron`
//! at the heap copy, the original env strings on the stack become free real
//! estate we can write the process title into — extending the writable
//! window from `strlen(argv[0])` to (end of last env string) − (start of argv[0]).
//!
//! We deliberately do **not** touch CoreFoundation / LaunchServices: Carrick
//! runs guests by forking *without* exec, and CF/LS are not fork-safe — a
//! forked child taking a CF lock that the parent held at fork time deadlocks
//! talking to `launchservicesd` over Mach, wedging the guest's vCPU. The
//! argv/environ stack overwrite is fork-safe (the heap copy survives fork;
//! the stack bytes are private per process after fork).

use std::sync::OnceLock;

#[cfg(target_os = "macos")]
struct Buffer {
    start: *mut u8,
    len: usize,
}

#[cfg(target_os = "macos")]
unsafe impl Send for Buffer {}
#[cfg(target_os = "macos")]
unsafe impl Sync for Buffer {}

/// Discovered writable `argv`/`environ` byte range. `None` if discovery
/// declined to relocate (non-contiguous layout, NULL pointers, etc).
#[cfg(target_os = "macos")]
static BUFFER: OnceLock<Option<Buffer>> = OnceLock::new();

/// Initialize process-title relocation. Idempotent — subsequent calls are
/// no-ops. Best-effort: on any unexpected layout the function declines to
/// relocate and `set_host_process_name` falls back to the legacy
/// `argv[0]`-only window.
///
/// MUST be called on the main thread, before any other thread is created
/// and before `fork(2)`. Calling later races with libc's environ accessors
/// and may leave forked children seeing the old `environ` pointer.
#[cfg(target_os = "macos")]
pub fn init() {
    BUFFER.get_or_init(|| unsafe { discover_and_relocate() });
}

#[cfg(not(target_os = "macos"))]
pub fn init() {}

/// Set the host thread/process name to `carrick: <comm>` so external
/// tools (Activity Monitor, `ps -M`, `sample`, lldb) can tell which
/// guest a carrick host process is running — invaluable when a forked
/// child hangs. `comm` is the guest's NUL-padded task name.
#[cfg(target_os = "macos")]
pub fn set_host_process_name(comm: &[u8]) {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]);
    let label = format!("carrick: {}", name.trim());

    // (1) Thread name — shows in lldb / Instruments / sample / crash
    // reports. Capped at MAXTHREADNAMESIZE (64).
    let thread_label: String = label.chars().take(63).collect();
    if let Ok(cstr) = std::ffi::CString::new(thread_label) {
        unsafe {
            libc::pthread_setname_np(cstr.as_ptr());
        }
    }

    // (2) argv buffer in-place overwrite — what `ps` reads. macOS's `ps`
    // shows the argument vector. If `init()` widened the writable range
    // by relocating environ, we get the full argv+envp byte span; otherwise
    // we fall back to overwriting just `argv[0]` (legacy behaviour). NUL-pad
    // the remainder so a shortened name doesn't leave stale trailing text.
    unsafe {
        if let Some((buf, len)) = wide_buffer() {
            write_label_into(buf, len, label.as_bytes());
        } else {
            write_label_argv0_only(label.as_bytes());
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn set_host_process_name(_comm: &[u8]) {}

#[cfg(target_os = "macos")]
fn wide_buffer() -> Option<(*mut u8, usize)> {
    BUFFER
        .get()
        .and_then(|opt| opt.as_ref())
        .map(|b| (b.start, b.len))
}

#[cfg(target_os = "macos")]
unsafe fn write_label_into(buf: *mut u8, len: usize, bytes: &[u8]) {
    unsafe {
        let n = bytes.len().min(len);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
        for i in n..len {
            *buf.add(i) = 0;
        }
    }
}

#[cfg(target_os = "macos")]
unsafe fn write_label_argv0_only(bytes: &[u8]) {
    unsafe {
        let argv = libc::_NSGetArgv();
        if argv.is_null() || (*argv).is_null() {
            return;
        }
        let arg0 = *(*argv);
        if arg0.is_null() {
            return;
        }
        let orig_len = libc::strlen(arg0);
        let n = bytes.len().min(orig_len);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), arg0 as *mut u8, n);
        for i in n..orig_len {
            *arg0.add(i) = 0;
        }
    }
}

/// Walk `argv` and `environ`, confirm they form one contiguous byte run on
/// the stack, then duplicate `environ` onto the heap and repoint
/// `*_NSGetEnviron` at the duplicate. On success returns the reclaimed
/// `[start, start + len)` byte range that subsequent `set_host_process_name`
/// calls may overwrite freely.
///
/// Safety invariants on success:
/// - `start` points to `argv[0]`'s first byte.
/// - `len` is the byte count from `argv[0]` through the last byte (including
///   trailing NUL) of the last environment string.
/// - All bytes in `[start, start + len)` are private process memory we now
///   own — argv[1..] / argv[argc] / environ[*] strings live there and will
///   be clobbered by the first title write; nothing in carrick reads them
///   after init.
#[cfg(target_os = "macos")]
unsafe fn discover_and_relocate() -> Option<Buffer> {
    unsafe {
        let argc_p = libc::_NSGetArgc();
        let argv_pp = libc::_NSGetArgv();
        let environ_pp = libc::_NSGetEnviron();
        if argc_p.is_null() || argv_pp.is_null() || environ_pp.is_null() {
            return None;
        }
        let argc = *argc_p;
        let argv = *argv_pp;
        let environ = *environ_pp;
        if argv.is_null() || argc <= 0 {
            return None;
        }
        let arg0 = *argv;
        if arg0.is_null() {
            return None;
        }

        // Walk argv strings, requiring each to abut the previous
        // (prev_end + 1 == next_start). The kernel guarantees this layout on
        // macOS.
        let mut cursor = arg0 as *const libc::c_char;
        let mut end: *const libc::c_char = arg0 as *const libc::c_char;
        for i in 0..argc {
            let p = *argv.offset(i as isize);
            if p.is_null() {
                return None;
            }
            if (p as *const libc::c_char) != cursor {
                return None;
            }
            let l = libc::strlen(p);
            end = (p as *const u8).add(l) as *const libc::c_char;
            cursor = end.add(1);
        }

        // Then the environment strings — same contiguity rule. We also count
        // them so we know how big a heap-side environ pointer array to allocate.
        let mut env_count: usize = 0;
        if !environ.is_null() {
            let mut i: usize = 0;
            loop {
                let p = *environ.add(i);
                if p.is_null() {
                    break;
                }
                if (p as *const libc::c_char) != cursor {
                    return None;
                }
                let l = libc::strlen(p);
                end = (p as *const u8).add(l) as *const libc::c_char;
                cursor = end.add(1);
                i += 1;
            }
            env_count = i;
        }

        let start = arg0 as *mut u8;
        let len = (end as usize) - (arg0 as usize) + 1; // include trailing NUL

        // Strdup the env strings onto the heap and point a new environ array
        // at them. We Box::leak the array because libc's getenv/setenv/unsetenv
        // expect the array's storage to live for the rest of the process.
        let mut new_env: Vec<*mut libc::c_char> = Vec::with_capacity(env_count + 1);
        if !environ.is_null() {
            for i in 0..env_count {
                let src = *environ.add(i);
                let dup = libc::strdup(src);
                if dup.is_null() {
                    // strdup failure mid-relocation: roll back partial dups so we
                    // don't leak, then decline. The original stack environ stays
                    // authoritative.
                    for &p in &new_env {
                        libc::free(p as *mut libc::c_void);
                    }
                    return None;
                }
                new_env.push(dup);
            }
        }
        new_env.push(std::ptr::null_mut());

        // Hand the Vec's storage to libc forever — leak into a Box<[T]> first
        // so its layout matches the `**char` libc wants.
        let leaked: &'static mut [*mut libc::c_char] = Box::leak(new_env.into_boxed_slice());
        *environ_pp = leaked.as_mut_ptr();

        Some(Buffer { start, len })
    }
}
