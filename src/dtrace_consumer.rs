//! In-process libdtrace consumer.
//!
//! Spawns a child carrick process under DTrace control, compiles the
//! bundled D program, and lets dtrace_consume / dtrace_aggregate_print
//! emit per-event lines and frequency-sorted aggregations directly to
//! the caller's stdout.
//!
//! The carrick parent must run as root (libdtrace opens /dev/dtrace).

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::Path;

/// Bundled D program. Mirrors `scripts/syscalls.d` so the build artifact
/// is self-contained.
pub const BUNDLED_D_SCRIPT: &str = include_str!("../scripts/syscalls.d");

const DTRACE_VERSION: c_int = 3;
const DTRACE_PROBESPEC_NAME: c_int = 3;
const DTRACE_C_ZDEFS: c_uint = 0x0004;
const DTRACE_C_PSPEC: c_uint = 0x0080;
const DTRACE_WORKSTATUS_OKAY: c_int = 0;
const DTRACE_WORKSTATUS_DONE: c_int = 1;
const PS_DEAD: c_int = 5;
const PS_UNDEAD: c_int = 4;

#[repr(C)]
struct DtraceHdl(c_void);
#[repr(C)]
struct DtraceProg(c_void);
#[repr(C)]
struct PsProchandle(c_void);

#[link(name = "dtrace")]
unsafe extern "C" {
    fn dtrace_open(version: c_int, flags: c_int, err: *mut c_int) -> *mut DtraceHdl;
    fn dtrace_close(hdl: *mut DtraceHdl);
    fn dtrace_errno(hdl: *mut DtraceHdl) -> c_int;
    fn dtrace_errmsg(hdl: *mut DtraceHdl, err: c_int) -> *const c_char;
    fn dtrace_setopt(hdl: *mut DtraceHdl, key: *const c_char, val: *const c_char) -> c_int;
    fn dtrace_program_strcompile(
        hdl: *mut DtraceHdl,
        program: *const c_char,
        spec: c_int,
        flags: c_uint,
        argc: c_int,
        argv: *const *const c_char,
    ) -> *mut DtraceProg;
    fn dtrace_program_exec(
        hdl: *mut DtraceHdl,
        prog: *mut DtraceProg,
        info: *mut c_void,
    ) -> c_int;
    fn dtrace_proc_create(
        hdl: *mut DtraceHdl,
        file: *const c_char,
        argv: *const *const c_char,
    ) -> *mut PsProchandle;
    fn dtrace_proc_release(hdl: *mut DtraceHdl, proc: *mut PsProchandle);
    fn dtrace_proc_continue(hdl: *mut DtraceHdl, proc: *mut PsProchandle);
    fn dtrace_proc_state(hdl: *mut DtraceHdl, proc: *mut PsProchandle) -> c_int;
    fn dtrace_go(hdl: *mut DtraceHdl) -> c_int;
    fn dtrace_stop(hdl: *mut DtraceHdl) -> c_int;
    fn dtrace_sleep(hdl: *mut DtraceHdl);
    fn dtrace_work(
        hdl: *mut DtraceHdl,
        fp: *mut libc_file,
        probe: *mut c_void,
        rec: *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn dtrace_aggregate_snap(hdl: *mut DtraceHdl) -> c_int;
    fn dtrace_aggregate_print(
        hdl: *mut DtraceHdl,
        fp: *mut libc_file,
        walk: *mut c_void,
    ) -> c_int;
}

// FILE* opaque type. We pass libc stdout straight through.
#[repr(C)]
struct libc_file(c_void);

// macOS exposes `stdout` as a macro that resolves to `__stdoutp`.
unsafe extern "C" {
    #[link_name = "__stdoutp"]
    static STDOUT_FP: *mut libc_file;
}

#[derive(Debug, thiserror::Error)]
pub enum DTraceError {
    #[error("dtrace_open failed: errno={0}")]
    Open(c_int),
    #[error("dtrace_setopt('{key}'='{val}') failed: {msg}")]
    SetOpt { key: String, val: String, msg: String },
    #[error("dtrace_program_strcompile failed: {0}")]
    Compile(String),
    #[error("dtrace_program_exec failed: {0}")]
    Exec(String),
    #[error("dtrace_proc_create failed: {0}")]
    ProcCreate(String),
    #[error("dtrace_go failed: {0}")]
    Go(String),
    #[error("dtrace_work failed: {0}")]
    Work(String),
    #[error("argv contains nul byte: {0:?}")]
    BadArg(String),
}

unsafe fn errmsg(hdl: *mut DtraceHdl) -> String {
    let e = unsafe { dtrace_errno(hdl) };
    let p = unsafe { dtrace_errmsg(hdl, e) };
    if p.is_null() {
        format!("dtrace errno={}", e)
    } else {
        unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
    }
}

/// Toggles applied to the libdtrace consumer before `dtrace_go`.
#[derive(Debug, Clone, Default)]
pub struct TraceOptions {
    /// When true, sets the libdtrace `flowindent` option — same as
    /// running `dtrace -F`. Indents each entry/return event by call
    /// depth.
    pub flowindent: bool,
}

/// Spawn `child_path` with `child_argv` under DTrace, with our bundled
/// D program enabled. Streams live events and aggregations to the
/// parent's stdout. Returns when the child exits.
pub fn run_child_under_dtrace(
    child_path: &Path,
    child_argv: &[String],
    opts: &TraceOptions,
) -> Result<(), DTraceError> {
    // argv[0] convention: pass the child path as argv[0]. dtrace_proc_create
    // takes file + argv, and the argv array must be NULL-terminated.
    let path_c =
        CString::new(child_path.as_os_str().to_string_lossy().as_bytes())
            .map_err(|_| DTraceError::BadArg(child_path.display().to_string()))?;
    let mut argv_c: Vec<CString> = Vec::with_capacity(child_argv.len() + 1);
    argv_c.push(path_c.clone());
    for a in child_argv {
        argv_c.push(
            CString::new(a.as_bytes()).map_err(|_| DTraceError::BadArg(a.clone()))?,
        );
    }
    let mut argv_ptrs: Vec<*const c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let mut err: c_int = 0;
    let hdl = unsafe { dtrace_open(DTRACE_VERSION, 0, &mut err) };
    if hdl.is_null() {
        return Err(DTraceError::Open(err));
    }

    // Sensible runtime defaults are appended to in `all_opts` below.
    let mut all_opts: Vec<(&str, &str)> =
        vec![
            ("bufsize", "4m"),
            ("aggsize", "4m"),
            ("aggrate", "1ms"),
            ("statusrate", "10ms"),
            ("strsize", "512"),
        ];
    if opts.flowindent {
        all_opts.push(("flowindent", ""));
    }
    for (k, v) in &all_opts {
        let kc = CString::new(*k).unwrap();
        let vc = CString::new(*v).unwrap();
        if unsafe { dtrace_setopt(hdl, kc.as_ptr(), vc.as_ptr()) } != 0 {
            let msg = unsafe { errmsg(hdl) };
            unsafe { dtrace_close(hdl) };
            return Err(DTraceError::SetOpt {
                key: (*k).into(),
                val: (*v).into(),
                msg,
            });
        }
    }

    let program_c = CString::new(BUNDLED_D_SCRIPT).expect("D script has nul bytes?");
    let prog = unsafe {
        dtrace_program_strcompile(
            hdl,
            program_c.as_ptr(),
            DTRACE_PROBESPEC_NAME,
            DTRACE_C_ZDEFS | DTRACE_C_PSPEC,
            0,
            std::ptr::null(),
        )
    };
    if prog.is_null() {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::Compile(msg));
    }

    if unsafe { dtrace_program_exec(hdl, prog, std::ptr::null_mut()) } != 0 {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::Exec(msg));
    }

    let proc_h = unsafe { dtrace_proc_create(hdl, path_c.as_ptr(), argv_ptrs.as_ptr()) };
    if proc_h.is_null() {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::ProcCreate(msg));
    }

    if unsafe { dtrace_go(hdl) } != 0 {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_proc_release(hdl, proc_h) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::Go(msg));
    }

    unsafe { dtrace_proc_continue(hdl, proc_h) };

    // Consume loop: sleep + work until both work reports DONE and the
    // child process is dead. dtrace_work prints to stdout for us.
    loop {
        unsafe { dtrace_sleep(hdl) };
        let status = unsafe {
            dtrace_work(
                hdl,
                STDOUT_FP,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let proc_state = unsafe { dtrace_proc_state(hdl, proc_h) };
        let child_terminal = proc_state == PS_DEAD || proc_state == PS_UNDEAD;
        match status {
            DTRACE_WORKSTATUS_DONE => break,
            DTRACE_WORKSTATUS_OKAY => {
                if child_terminal {
                    break;
                }
            }
            _ => {
                let msg = unsafe { errmsg(hdl) };
                unsafe { dtrace_proc_release(hdl, proc_h) };
                unsafe { dtrace_close(hdl) };
                return Err(DTraceError::Work(msg));
            }
        }
    }

    unsafe { dtrace_stop(hdl) };
    unsafe { dtrace_aggregate_snap(hdl) };
    unsafe { dtrace_aggregate_print(hdl, STDOUT_FP, std::ptr::null_mut()) };
    unsafe { dtrace_proc_release(hdl, proc_h) };
    unsafe { dtrace_close(hdl) };
    Ok(())
}
