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
//! window from `strlen(argv[0])` to (end of last env string) − (start of `argv[0]`).
//!
//! We deliberately do **not** touch CoreFoundation / LaunchServices: Carrick
//! runs guests by forking *without* exec, and CF/LS are not fork-safe — a
//! forked child taking a CF lock that the parent held at fork time deadlocks
//! talking to `launchservicesd` over Mach, wedging the guest's vCPU. The
//! argv/environ stack overwrite is fork-safe (the heap copy survives fork;
//! the stack bytes are private per process after fork).
//!
//! ## Non-macOS hosts
//!
//! carrick also targets Linux/KVM, FreeBSD/bhyve and NetBSD/NVMM, where the
//! same `carrick:<id>: <name>` title underpins the scoped-kill / run-id
//! isolation (`pkill -f "carrick:<id>:"`, `scripts/sudo/kill.sh`) that lets
//! concurrent runs / lanes / the conformance gate coexist:
//!
//!   * **BSD (FreeBSD/NetBSD/OpenBSD/DragonFly):** the kernel reserves a
//!     dedicated `ps_strings` title slot, and libc exposes `setproctitle(3)` to
//!     write it — no environ relocation needed. We call `setproctitle("-%s",
//!     label)`; the leading `-` suppresses libc's default `progname: ` prefix so
//!     the visible title is *exactly* the label.
//!   * **Linux:** glibc/musl have no `setproctitle`, so we use the libuv trick —
//!     overwrite the contiguous `argv`/`environ` byte run in place (that's what
//!     `/proc/PID/cmdline` and `ps` read), widening the writable window by
//!     relocating `environ` onto the heap exactly as the macOS path does (using
//!     the `environ` global instead of `_NSGetEnviron`). We also set
//!     `/proc/PID/comm` via `prctl(PR_SET_NAME)` for the 15-char short name. An
//!     `.init_array` constructor captures `(argc, argv, envp)` before `main`,
//!     since Linux has no `_NSGetArgv`/`_NSGetEnviron` accessors.
//!
//! All non-macOS paths preserve the macOS fork-safety constraints: `init()`
//! runs before any fork/thread, and the widened buffer is private per process
//! after fork.
//
// The label machinery (`RUN_ID`, `run_id`, `proc_label`) and a few helpers are
// only reachable on some platforms; they are exercised on every platform by the
// unit tests, so allow dead_code module-wide rather than cfg-gating the still-
// tested helpers.
#![allow(dead_code)]

use std::sync::OnceLock;

/// Per-run id (from `CARRICK_RUN_ID`, inherited across guest forks via the
/// environment), cached once. Lets cleanup scope to a single run instead of
/// reaping every `carrick:` host process — the hazard that forces the
/// conformance gate and the LTP sweeps to run serially. The CLI gives EVERY
/// `carrick run` a sensible default for this (precedence: explicit
/// `CARRICK_RUN_ID` → the container `--name` → an auto 12-hex short id from the
/// `carrick ps` id space), so a run is scoped + reapable by default with no env
/// var to set — see `crate::commands` (carrick-cli).
static RUN_ID: OnceLock<Option<String>> = OnceLock::new();

fn run_id() -> Option<&'static str> {
    RUN_ID
        .get_or_init(|| {
            std::env::var("CARRICK_RUN_ID")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .as_deref()
}

/// Build the host process title. With a run id this is `carrick:<id>: <name>`,
/// which is greppable per-run — but the id MUST be matched with its trailing
/// delimiter: `pkill -f "carrick:<id>:"` (note the final `:`), NOT a bare
/// `carrick:<id>`. The `:` separates the id from the name, so a run id that is a
/// PREFIX of another (e.g. `…-c1` vs `…-c10`) would over-match without it — the
/// scoped reaper (`scripts/sudo/kill.sh`) anchors on `carrick:<id>:` as a literal
/// for exactly this reason. The match survives `setpgid`/`setsid` escapes.
/// Without a run id the title is the legacy `carrick: <name>`. Both keep the
/// literal `carrick:` so the global recovery reaper still matches for manual
/// cleanup.
pub(crate) fn proc_label(name: &str, run_id: Option<&str>) -> String {
    match run_id {
        Some(id) if !id.is_empty() => format!("carrick:{id}: {}", name.trim()),
        _ => format!("carrick: {}", name.trim()),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct Buffer {
    start: *mut u8,
    len: usize,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe impl Send for Buffer {}
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe impl Sync for Buffer {}

/// Discovered writable `argv`/`environ` byte range. `None` if discovery
/// declined to relocate (non-contiguous layout, NULL pointers, etc).
#[cfg(any(target_os = "macos", target_os = "linux"))]
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

/// BSD `init()`: `setproctitle(3)` writes a kernel-reserved title slot, so
/// there is nothing to relocate. No-op.
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub fn init() {}

/// Linux `init()`: relocate `environ` onto the heap (libuv trick) to widen the
/// in-place writable argv/env window. See the macOS `init()` and
/// `discover_and_relocate` for the contiguity/fork-safety contract; the only
/// difference is the argv/environ source — captured by the `.init_array`
/// constructor below instead of `_NSGetArgv`/`_NSGetEnviron`.
#[cfg(target_os = "linux")]
pub fn init() {
    BUFFER.get_or_init(|| unsafe { discover_and_relocate() });
}

/// Fallback `init()` for any other non-macOS host (no title mechanism known).
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
pub fn init() {}

/// Set the host thread/process name to `carrick: <comm>` so external
/// tools (Activity Monitor, `ps -M`, `sample`, lldb) can tell which
/// guest a carrick host process is running — invaluable when a forked
/// child hangs. `comm` is the guest's NUL-padded task name.
#[cfg(target_os = "macos")]
pub fn set_host_process_name(comm: &[u8]) {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]);
    let label = proc_label(&name, run_id());

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

/// BSD `set_host_process_name`: build the same `proc_label` and hand it to
/// `setproctitle(3)`. The `-` format prefix suppresses libc's default
/// `progname: ` so `ps -o command` shows EXACTLY the label, e.g.
/// `carrick:cr-test123: ls` — greppable per-run for the scoped reaper.
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub fn set_host_process_name(comm: &[u8]) {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]);
    let label = proc_label(&name, run_id());

    // A NUL in the label would truncate the C string; `proc_label` only ever
    // contains the run-id + the guest task name, but guard anyway.
    let Ok(clabel) = std::ffi::CString::new(label) else {
        return;
    };
    // Leading "-" in the format suppresses setproctitle's default
    // "progname: " prefix, so the title is the label verbatim.
    const FMT: &[u8] = b"-%s\0";
    unsafe {
        libc::setproctitle(
            FMT.as_ptr() as *const libc::c_char,
            clabel.as_ptr() as *const libc::c_char,
        );
    }
}

/// Linux `set_host_process_name`: (a) overwrite the in-place argv/env byte
/// window — what `/proc/PID/cmdline` and `ps` read — NUL-padding the remainder,
/// and (b) `prctl(PR_SET_NAME)` to set `/proc/PID/comm` (15-char cap) for the
/// short name. Mirrors the macOS argv-overwrite path; if `init()` declined to
/// relocate we fall back to the `argv[0]`-only window.
#[cfg(target_os = "linux")]
pub fn set_host_process_name(comm: &[u8]) {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]);
    let label = proc_label(&name, run_id());

    // (1) /proc/PID/comm via prctl(PR_SET_NAME) — the kernel caps this at 16
    // bytes including the NUL (15 visible chars). Shows in `ps -o comm`, top,
    // /proc/PID/comm, and as the thread name in gdb/perf. Use the run-id +
    // name label truncated to fit; the full label lives in cmdline below.
    if let Ok(cstr) = std::ffi::CString::new(label.chars().take(15).collect::<String>()) {
        unsafe {
            libc::prctl(libc::PR_SET_NAME, cstr.as_ptr() as libc::c_ulong, 0, 0, 0);
        }
    }

    // (2) argv/env byte window in-place overwrite — what `/proc/PID/cmdline`
    // and `ps -o command` read. If `init()` widened the window by relocating
    // environ we get the full argv+envp byte span; otherwise fall back to
    // `argv[0]`-only. NUL-pad the remainder so a shortened name doesn't leave
    // stale trailing text (and so `/proc/PID/cmdline`'s NUL-separated parsing
    // collapses to the single title arg).
    unsafe {
        if let Some((buf, len)) = wide_buffer() {
            write_label_into(buf, len, label.as_bytes());
        } else {
            write_label_argv0_only(label.as_bytes());
        }
    }
}

/// Fallback for any other non-macOS host: no title mechanism. No-op.
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
pub fn set_host_process_name(_comm: &[u8]) {}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn wide_buffer() -> Option<(*mut u8, usize)> {
    BUFFER
        .get()
        .and_then(|opt| opt.as_ref())
        .map(|b| (b.start, b.len))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
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
///   own — `argv[1..]` / `argv[argc]` / `environ[*]` strings live there and will
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
            if !std::ptr::eq(p, cursor) {
                return None;
            }
            let l = libc::strlen(p);
            end = (p as *const u8).add(l) as *const libc::c_char;
            cursor = end.add(1);
        }

        // Then the environment strings — same contiguity rule. We also count
        // them so we know how big a heap-side environ pointer array to allocate.
        // STOP-AT-FIRST-BREAK semantics: if any setenv has run before init()
        // (eg the host added OS_ACTIVITY_MODE on a realloc'd environ array),
        // the freshly-malloc'd heap string won't abut the stack run. Stop
        // claiming bytes for the writable buffer at that point, but keep
        // walking the array so we still strdup every env entry onto the heap.
        let mut env_count: usize = 0;
        let mut still_contiguous = true;
        if !environ.is_null() {
            let mut i: usize = 0;
            loop {
                let p = *environ.add(i);
                if p.is_null() {
                    break;
                }
                if still_contiguous {
                    if std::ptr::eq(p, cursor) {
                        let l = libc::strlen(p);
                        end = (p as *const u8).add(l) as *const libc::c_char;
                        cursor = end.add(1);
                    } else {
                        still_contiguous = false;
                    }
                }
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

// ---- Linux argv/environ capture + relocation ----
//
// Linux has no `_NSGetArgv`/`_NSGetEnviron`. The glibc/musl runtime instead
// invokes every `.init_array` constructor with `(int argc, char **argv, char
// **envp)` before `main`, so we register one to stash those pointers. `environ`
// is a libc global; we relocate it (and read it back) the same way the macOS
// path uses `*_NSGetEnviron`.
#[cfg(target_os = "linux")]
mod linux_capture {
    use std::sync::atomic::{AtomicPtr, Ordering};

    pub(super) static ARGC: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    pub(super) static ARGV: AtomicPtr<*mut libc::c_char> = AtomicPtr::new(std::ptr::null_mut());

    /// `.init_array` entry: glibc/musl call this with `(argc, argv, envp)`
    /// before `main`. We only stash argc/argv here — `environ` is read from the
    /// libc global at relocation time so we observe any pre-`init` setenv.
    ///
    /// # Safety
    /// Invoked by the C runtime with the process's real argv. We only copy the
    /// two scalar pointer/count values into atomics.
    pub(super) extern "C" fn capture(argc: libc::c_int, argv: *mut *mut libc::c_char) {
        ARGC.store(argc, Ordering::Relaxed);
        ARGV.store(argv, Ordering::Relaxed);
    }

    // Register `capture` in `.init_array`. `#[used]` keeps the linker from
    // dropping the otherwise-unreferenced pointer; the section name is the
    // glibc/musl constructor table the dynamic loader walks with (argc,argv,
    // envp). The signature `(c_int, **c_char)` matches what the loader passes
    // (the third `envp` arg is ignored — extra args are harmless on the SysV
    // ABI).
    #[used]
    #[unsafe(link_section = ".init_array")]
    static CAPTURE_CTOR: extern "C" fn(libc::c_int, *mut *mut libc::c_char) = capture;
}

// libc's `environ` global. glibc and musl both export it; the `libc` crate does
// not bind it, so declare it here (matches PostgreSQL/libuv usage on Linux).
#[cfg(target_os = "linux")]
unsafe extern "C" {
    static mut environ: *mut *mut libc::c_char;
}

#[cfg(target_os = "linux")]
unsafe fn write_label_argv0_only(bytes: &[u8]) {
    use std::sync::atomic::Ordering;
    unsafe {
        let argv = linux_capture::ARGV.load(Ordering::Relaxed);
        if argv.is_null() {
            return;
        }
        let arg0 = *argv;
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

/// Linux twin of the macOS `discover_and_relocate`: same contiguity walk and
/// heap-relocation of `environ`, but argv/argc come from the `.init_array`
/// capture and environ is the libc global rather than `_NSGetEnviron`. The
/// kernel lays argv+envp out as one contiguous run at the top of the stack on
/// Linux too, so the macOS contiguity invariants hold. See the macOS function
/// for the full safety contract.
#[cfg(target_os = "linux")]
unsafe fn discover_and_relocate() -> Option<Buffer> {
    use std::sync::atomic::Ordering;
    unsafe {
        let argc = linux_capture::ARGC.load(Ordering::Relaxed);
        let argv = linux_capture::ARGV.load(Ordering::Relaxed);
        // The `.init_array` constructor must have run before `init()` (it runs
        // before `main`). If argv is null we never captured it — decline.
        if argv.is_null() || argc <= 0 {
            return None;
        }
        let arg0 = *argv;
        if arg0.is_null() {
            return None;
        }
        let environ_ptr = std::ptr::addr_of_mut!(environ);
        // Local snapshot of the environ array head. Named distinctly from the
        // `environ` static (a `let environ` would shadow-error: E0530).
        let env_arr = *environ_ptr;

        // Walk argv strings, requiring each to abut the previous
        // (prev_end + 1 == next_start) — the kernel's stack layout.
        let mut cursor = arg0 as *const libc::c_char;
        let mut end: *const libc::c_char = arg0 as *const libc::c_char;
        for i in 0..argc {
            let p = *argv.offset(i as isize);
            if p.is_null() {
                return None;
            }
            if !std::ptr::eq(p, cursor) {
                return None;
            }
            let l = libc::strlen(p);
            end = (p as *const u8).add(l) as *const libc::c_char;
            cursor = end.add(1);
        }

        // Then environ — same contiguity rule, STOP-AT-FIRST-BREAK so a pre-init
        // setenv (heap-allocated, won't abut the stack run) bounds the writable
        // window but we still strdup every entry onto the heap.
        let mut env_count: usize = 0;
        let mut still_contiguous = true;
        if !env_arr.is_null() {
            let mut i: usize = 0;
            loop {
                let p = *env_arr.add(i);
                if p.is_null() {
                    break;
                }
                if still_contiguous {
                    if std::ptr::eq(p, cursor) {
                        let l = libc::strlen(p);
                        end = (p as *const u8).add(l) as *const libc::c_char;
                        cursor = end.add(1);
                    } else {
                        still_contiguous = false;
                    }
                }
                i += 1;
            }
            env_count = i;
        }

        let start = arg0 as *mut u8;
        let len = (end as usize) - (arg0 as usize) + 1; // include trailing NUL

        // Strdup the env strings onto the heap and repoint `environ` at the
        // duplicate. Box::leak so libc's getenv/setenv keep a live array.
        let mut new_env: Vec<*mut libc::c_char> = Vec::with_capacity(env_count + 1);
        if !env_arr.is_null() {
            for i in 0..env_count {
                let src = *env_arr.add(i);
                let dup = libc::strdup(src);
                if dup.is_null() {
                    for &p in &new_env {
                        libc::free(p as *mut libc::c_void);
                    }
                    return None;
                }
                new_env.push(dup);
            }
        }
        new_env.push(std::ptr::null_mut());

        let leaked: &'static mut [*mut libc::c_char] = Box::leak(new_env.into_boxed_slice());
        *environ_ptr = leaked.as_mut_ptr();

        Some(Buffer { start, len })
    }
}

#[cfg(test)]
mod tests {
    use super::proc_label;

    #[test]
    fn label_with_run_id_is_scoped_per_run() {
        // A scoped reaper greps "carrick:<id>" — this must contain exactly that
        // token (colon then id, no space) so it can't match another run's title.
        assert_eq!(proc_label("ls", Some("cr-42")), "carrick:cr-42: ls");
    }

    #[test]
    fn label_without_run_id_is_legacy() {
        assert_eq!(proc_label("ls", None), "carrick: ls");
        assert_eq!(proc_label("ls", Some("")), "carrick: ls");
    }

    #[test]
    fn scoped_label_is_not_matched_by_another_runs_grep() {
        // The whole point: run A's reaper (grep "carrick:cr-A") must NOT match
        // run B's title, nor the legacy title.
        assert!(!proc_label("ls", Some("cr-B")).contains("carrick:cr-A"));
        assert!(!proc_label("ls", None).contains("carrick:cr-A"));
        // ...but the global recovery reaper (grep "carrick:") still matches both.
        assert!(proc_label("ls", Some("cr-B")).contains("carrick:"));
        assert!(proc_label("ls", None).contains("carrick:"));
    }
}
