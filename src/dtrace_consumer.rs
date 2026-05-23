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

/// Bundled guest stack-walker D program (`scripts/guest_stack.d`).
/// copyin-walks the guest aarch64 frame-pointer chain from the
/// `vcpu-trap` probe's GuestRegs struct. Selected by `carrick trace
/// --stack`. NOTE: uses `#define` macros, so it must be compiled with
/// the C preprocessor enabled (DTRACE_C_CPP).
pub const BUNDLED_GUEST_STACK_D: &str = include_str!("../scripts/guest_stack.d");

const DTRACE_VERSION: c_int = 3;
const DTRACE_PROBESPEC_NAME: c_int = 3;
const DTRACE_C_ZDEFS: c_uint = 0x0004;
const DTRACE_C_PSPEC: c_uint = 0x0080;
const DTRACE_WORKSTATUS_OKAY: c_int = 0;
const DTRACE_WORKSTATUS_DONE: c_int = 1;
const PS_DEAD: c_int = 5;
const PS_UNDEAD: c_int = 4;

// libdtrace consume callbacks. dtrace_work hands each fired probe to `probe`
// and each data record to `rec`. Returning DTRACE_CONSUME_THIS (0) tells
// libdtrace to format the record (printf/printa) to `fp` itself; passing NULL
// callbacks instead makes it skip all formatting, which is why our live
// stream was silent. Mirrors dtrace(1)'s chew/chewrec.
const DTRACE_CONSUME_THIS: c_int = 0;
const DTRACE_CONSUME_NEXT: c_int = 1;

type ConsumeProbeFn = extern "C" fn(data: *const c_void, arg: *mut c_void) -> c_int;
type ConsumeRecFn =
    extern "C" fn(data: *const c_void, rec: *const c_void, arg: *mut c_void) -> c_int;

extern "C" fn chew(_data: *const c_void, _arg: *mut c_void) -> c_int {
    DTRACE_CONSUME_THIS
}

extern "C" fn chewrec(_data: *const c_void, rec: *const c_void, _arg: *mut c_void) -> c_int {
    // NULL rec marks the end of this probe's records — advance to the next.
    if rec.is_null() {
        DTRACE_CONSUME_NEXT
    } else {
        DTRACE_CONSUME_THIS
    }
}

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
    fn dtrace_program_exec(hdl: *mut DtraceHdl, prog: *mut DtraceProg, info: *mut c_void) -> c_int;
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
        probe: ConsumeProbeFn,
        rec: ConsumeRecFn,
        arg: *mut c_void,
    ) -> c_int;
    fn dtrace_aggregate_snap(hdl: *mut DtraceHdl) -> c_int;
    fn dtrace_aggregate_print(hdl: *mut DtraceHdl, fp: *mut libc_file, walk: *mut c_void) -> c_int;
}

// FILE* opaque type. We pass libc stdout straight through.
#[repr(C)]
struct libc_file(c_void);

// macOS exposes `stdout` as a macro that resolves to `__stdoutp`.
unsafe extern "C" {
    #[link_name = "__stdoutp"]
    static STDOUT_FP: *mut libc_file;
    fn fflush(stream: *mut libc_file) -> c_int;
    fn fopen(path: *const c_char, mode: *const c_char) -> *mut libc_file;
    fn fclose(stream: *mut libc_file) -> c_int;
}

#[derive(Debug, thiserror::Error)]
pub enum DTraceError {
    #[error("dtrace_open failed: errno={0}")]
    Open(c_int),
    #[error("dtrace_setopt('{key}'='{val}') failed: {msg}")]
    SetOpt {
        key: String,
        val: String,
        msg: String,
    },
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
    #[error("failed to open trace output file: {0}")]
    OutOpen(String),
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
    /// Custom D program to compile instead of the bundled syscall tracer.
    /// `None` uses `BUNDLED_D_SCRIPT`.
    pub script: Option<String>,
    /// When set, write DTrace events + aggregations to this file instead of
    /// stdout. Keeps trace output from intermixing with an interactive (`-t`)
    /// guest's own stdout — the traced command's stdio is untouched.
    pub out_path: Option<String>,
    /// Credentials the traced carrick child should drop to before it dispatches
    /// the requested command. The libdtrace parent still runs as root.
    pub drop_credentials: Option<TraceDropCredentials>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceDropCredentials {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

pub const TRACE_CHILD_COMMAND: &str = "__trace-child";

struct TraceExecArgv {
    exec_path: CString,
    argv: Vec<CString>,
}

/// Spawn `child_path` with `child_argv` under DTrace, with our bundled
/// D program enabled. Streams live events and aggregations to the
/// parent's stdout. Returns when the child exits.
pub fn run_child_under_dtrace(
    child_path: &Path,
    child_argv: &[String],
    opts: &TraceOptions,
) -> Result<(), DTraceError> {
    let trace_argv = trace_exec_argv(child_path, child_argv, opts.drop_credentials.as_ref())?;
    let mut argv_ptrs: Vec<*const c_char> = trace_argv.argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // Where the consumer writes events + aggregations. Defaults to stdout;
    // `out_path` redirects to a file so trace output doesn't intermix with an
    // interactive guest's own stdout. The returned fp must outlive the consume
    // loop; closed at the end if we opened it.
    let (out_fp, owns_fp) = match &opts.out_path {
        Some(path) => {
            let pc =
                CString::new(path.as_bytes()).map_err(|_| DTraceError::BadArg(path.clone()))?;
            let mode = c"w";
            // SAFETY: pc/mode are valid NUL-terminated C strings.
            let fp = unsafe { fopen(pc.as_ptr(), mode.as_ptr()) };
            if fp.is_null() {
                return Err(DTraceError::OutOpen(path.clone()));
            }
            (fp, true)
        }
        // SAFETY: STDOUT_FP is the process's libc stdout.
        None => (unsafe { STDOUT_FP }, false),
    };

    let mut err: c_int = 0;
    let hdl = unsafe { dtrace_open(DTRACE_VERSION, 0, &mut err) };
    if hdl.is_null() {
        if owns_fp {
            unsafe { fclose(out_fp) };
        }
        return Err(DTraceError::Open(err));
    }

    // Sensible runtime defaults are appended to in `all_opts` below.
    let mut all_opts: Vec<(&str, &str)> = vec![
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
        // INVARIANT: every (k, v) in all_opts is a static string literal with no
        // interior NUL byte, so CString::new cannot fail.
        #[allow(clippy::unwrap_used)]
        let kc = CString::new(*k).unwrap();
        #[allow(clippy::unwrap_used)]
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

    let proc_h =
        unsafe { dtrace_proc_create(hdl, trace_argv.exec_path.as_ptr(), argv_ptrs.as_ptr()) };
    if proc_h.is_null() {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::ProcCreate(msg));
    }

    let program_src: &str = opts.script.as_deref().unwrap_or(BUNDLED_D_SCRIPT);
    let program_c = match CString::new(program_src) {
        Ok(program_c) => program_c,
        Err(_) => {
            unsafe { dtrace_proc_release(hdl, proc_h) };
            unsafe { dtrace_close(hdl) };
            return Err(DTraceError::Compile(
                "D script contains a nul byte".to_owned(),
            ));
        }
    };
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
        unsafe { dtrace_proc_release(hdl, proc_h) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::Compile(msg));
    }

    if unsafe { dtrace_program_exec(hdl, prog, std::ptr::null_mut()) } != 0 {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_proc_release(hdl, proc_h) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::Exec(msg));
    }

    if unsafe { dtrace_go(hdl) } != 0 {
        let msg = unsafe { errmsg(hdl) };
        unsafe { dtrace_proc_release(hdl, proc_h) };
        unsafe { dtrace_close(hdl) };
        return Err(DTraceError::Go(msg));
    }

    unsafe { dtrace_proc_continue(hdl, proc_h) };

    // Consume loop: sleep + work until tracing reports DONE or the child
    // process is dead. dtrace_work prints to stdout for us.
    loop {
        unsafe { dtrace_sleep(hdl) };
        let status = unsafe { dtrace_work(hdl, out_fp, chew, chewrec, std::ptr::null_mut()) };
        // dtrace_work writes events into the C stdio buffer, which is
        // block-buffered when the sink is a pipe/file. Flush every cycle so the
        // live stream stays live even when the traced child never exits (e.g.
        // a deadlock we're trying to diagnose).
        unsafe { fflush(out_fp) };
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
    unsafe { dtrace_aggregate_print(hdl, out_fp, std::ptr::null_mut()) };
    unsafe { dtrace_proc_release(hdl, proc_h) };
    unsafe { dtrace_close(hdl) };
    if owns_fp {
        // SAFETY: out_fp was opened by us via fopen and is no longer used.
        unsafe {
            fflush(out_fp);
            fclose(out_fp);
        }
    }
    Ok(())
}

fn trace_exec_argv(
    child_path: &Path,
    child_argv: &[String],
    drop_credentials: Option<&TraceDropCredentials>,
) -> Result<TraceExecArgv, DTraceError> {
    let child_path_string = child_path.as_os_str().to_string_lossy().into_owned();
    let exec_path = cstring_arg(&child_path_string)?;
    let mut argv = Vec::with_capacity(child_argv.len() + 8);
    argv.push(exec_path.clone());

    if let Some(creds) = drop_credentials {
        argv.push(cstring_arg(TRACE_CHILD_COMMAND)?);
        argv.push(cstring_arg("--trace-uid")?);
        argv.push(cstring_arg(&creds.uid.to_string())?);
        argv.push(cstring_arg("--trace-gid")?);
        argv.push(cstring_arg(&creds.gid.to_string())?);
        if !creds.groups.is_empty() {
            argv.push(cstring_arg("--trace-groups")?);
            argv.push(cstring_arg(&join_ids(&creds.groups))?);
        }
        argv.push(cstring_arg("--")?);
    }

    for a in child_argv {
        argv.push(cstring_arg(a)?);
    }

    Ok(TraceExecArgv { exec_path, argv })
}

fn cstring_arg(arg: &str) -> Result<CString, DTraceError> {
    CString::new(arg.as_bytes()).map_err(|_| DTraceError::BadArg(arg.to_owned()))
}

fn join_ids(ids: &[u32]) -> String {
    ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::{TRACE_CHILD_COMMAND, TraceDropCredentials, trace_exec_argv};
    use std::ffi::CString;
    use std::path::Path;

    fn argv_strings(argv: &[CString]) -> Vec<String> {
        argv.iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn trace_exec_argv_without_credentials_runs_child_directly() {
        let argv = trace_exec_argv(
            Path::new("/tmp/carrick"),
            &["run".to_owned(), "alpine".to_owned()],
            None,
        )
        .unwrap();

        assert_eq!(argv.exec_path.to_string_lossy(), "/tmp/carrick");
        assert_eq!(
            argv_strings(&argv.argv),
            vec!["/tmp/carrick", "run", "alpine"]
        );
    }

    #[test]
    fn trace_exec_argv_with_credentials_uses_self_demoting_child() {
        let argv = trace_exec_argv(
            Path::new("/tmp/carrick"),
            &["run".to_owned(), "alpine".to_owned()],
            Some(&TraceDropCredentials {
                uid: 501,
                gid: 20,
                groups: vec![20, 12],
            }),
        )
        .unwrap();

        assert_eq!(argv.exec_path.to_string_lossy(), "/tmp/carrick");
        assert_eq!(
            argv_strings(&argv.argv),
            vec![
                "/tmp/carrick",
                TRACE_CHILD_COMMAND,
                "--trace-uid",
                "501",
                "--trace-gid",
                "20",
                "--trace-groups",
                "20,12",
                "--",
                "run",
                "alpine",
            ]
        );
    }
}
