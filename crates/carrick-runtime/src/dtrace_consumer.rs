//! In-process libdtrace consumer — the engine behind `carrick trace`.
//!
//! # Theory of operation
//!
//! `dtrace(1)` the command-line tool is itself just a thin client of
//! `libdtrace`: it opens a handle, compiles a D program, spawns/grabs a victim
//! process, and pumps a consume loop. carrick links `libdtrace` directly and
//! *is* that client, in-process. The motivation is fidelity over a subprocess:
//! carrick needs to follow a guest across `fork`/`clone` into real macOS child
//! processes (and sibling vCPU threads) that re-register their USDT probes, drop
//! to the invoking user's credentials, and outlive their parent — control that
//! is awkward-to-impossible to drive through a separate `dtrace(1)` you only talk
//! to over a pipe. Owning the handle means carrick controls the exact spawn
//! (`dtrace_proc_create` + `dtrace_proc_continue`), the buffer/aggregation
//! options, the output sink, and the stop condition.
//!
//! ## The flow
//!
//! 1. `dtrace_open` a handle (requires root: libdtrace opens `/dev/dtrace`; a
//!    non-root carrick parent cannot trace at all).
//! 2. `dtrace_proc_create` spawns the victim — another `carrick` invocation (the
//!    `child_path`/`child_argv`) — *suspended*, so its probes can be armed before
//!    it runs a single instruction.
//! 3. Compile the D program (the bundled syscall tracer, the guest stack-walker,
//!    or a caller-supplied `-s` script), `dtrace_program_exec` to install it,
//!    `dtrace_go` to enable the probes, then `dtrace_proc_continue` to release
//!    the suspended child.
//! 4. Pump: `dtrace_sleep` (wait for the aggregation/status rate), `dtrace_work`
//!    (drain fired probes), `fflush`, repeat — until the stop condition.
//!
//! ## The chew/chewrec callback contract (a real bug, encoded here)
//!
//! `dtrace_work` takes a *probe* callback and a *record* callback. The crucial,
//! non-obvious part: a callback returning `DTRACE_CONSUME_THIS` tells libdtrace
//! to do the `printf`/`printa` formatting of that record to the `FILE*` itself —
//! exactly as `dtrace(1)`'s `chew`/`chewrec` do. Passing NULL callbacks instead
//! makes libdtrace skip *all* formatting, which is why an earlier version's live
//! stream was silent. So `chew`/`chewrec` are deliberately near-trivial:
//! they exist to return `CONSUME_THIS` (and, in `chewrec`, `CONSUME_NEXT` on the
//! NULL record that marks a probe's end) so libdtrace prints. The D program's own
//! `printf`/`printa`/`@agg` statements are what actually produce the output.
//!
//! ## Output sink + the sudo ownership trap
//!
//! Output defaults to the parent's `stdout` (`STDOUT_FP`, macOS's
//! `__stdoutp`). `--trace-out` redirects it to a file so trace lines never
//! intermix with an interactive (`-t`) guest's own stdio. Because the libdtrace
//! parent runs as root but the human invoked `carrick trace` under `sudo`, a
//! freshly-`fopen`'d trace file lands `root:wheel`; `TraceOutput::open`
//! `fchown`s it back to the invoking `(uid, gid)` so the user can read/`rm` it
//! without sudo (the file is 0644 regardless, so reads never needed sudo — the
//! historical "`--trace-out` writes nothing" was a `sudo cat` perm artifact, not
//! a write bug). Every pump cycle `fflush`es: `dtrace_work` writes into a
//! block-buffered C stdio buffer when the sink is a pipe/file, so an unflushed
//! stream looks dead precisely when you are watching a *hang* — the case the
//! tracer exists to diagnose.
//!
//! ## Stop condition: linger-past-child
//!
//! With the bundled default tracer (no `-s`) we stop the instant the directly
//! spawned child is gone, so a plain `carrick trace -- run …` returns promptly.
//! With a caller-supplied script (`opts.script.is_some()`) we *linger*: the user
//! is responsible for bounding their own program (the carrick-trace skill
//! mandates a `tick-Ns { exit(0) }`), and we keep draining so that (a) a guest
//! that forked real macOS children/sibling-vCPU threads is still traced after the
//! first process exits, and (b) a fast-crashing guest still flushes its buffered
//! events and the final `END` aggregation. The outer `timeout` the CLI wraps
//! every run in is the backstop.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Bundled D program. Mirrors `scripts/dtrace/syscalls.d` so the build artifact
/// is self-contained.
pub const BUNDLED_D_SCRIPT: &str = include_str!("../../../scripts/dtrace/syscalls.d");

/// Bundled guest stack-walker D program (`scripts/dtrace/guest_stack.d`).
/// copyin-walks the guest aarch64 frame-pointer chain from the
/// `vcpu-trap` probe's GuestRegs struct. Selected by `carrick trace
/// --stack`. NOTE: uses `#define` macros, so it must be compiled with
/// the C preprocessor enabled (DTRACE_C_CPP).
pub const BUNDLED_GUEST_STACK_D: &str = include_str!("../../../scripts/dtrace/guest_stack.d");

pub const BUNDLED_DSR_PROFILE_D: &str = include_str!("../../../scripts/dtrace/dsr-profile.d");
pub const BUNDLED_DSR_INDIRECT_D: &str = include_str!("../../../scripts/dtrace/dsr-indirect.d");
pub const BUNDLED_DSR_FORK_D: &str = include_str!("../../../scripts/dtrace/dsr-fork.d");

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
const DTRACEACT_EXIT: u16 = 2;

const DTRACEDROP_PRINCIPAL: c_int = 0;
const DTRACEDROP_AGGREGATION: c_int = 1;
const DTRACEDROP_DYNAMIC: c_int = 2;
const DTRACEDROP_DYNRINSE: c_int = 3;
const DTRACEDROP_DYNDIRTY: c_int = 4;

type ConsumeProbeFn = extern "C" fn(data: *const c_void, arg: *mut c_void) -> c_int;
type ConsumeRecFn =
    extern "C" fn(data: *const c_void, rec: *const c_void, arg: *mut c_void) -> c_int;
type HandleDropFn = extern "C" fn(data: *const DtraceDropData, arg: *mut c_void) -> c_int;

#[repr(C)]
#[derive(Clone, Copy)]
struct DtraceRecDesc {
    action: u16,
    size: u32,
    offset: u32,
    alignment: u16,
    format: u16,
    argument: u64,
    user_argument: u64,
}

#[repr(C)]
struct DtraceDropData {
    handle: *mut DtraceHdl,
    cpu: c_int,
    kind: c_int,
    drops: u64,
    total: u64,
    message: *const c_char,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DTraceRunReport {
    pub principal_drops: u64,
    pub aggregation_drops: u64,
    pub dynamic_drops: u64,
    pub other_drops: u64,
    pub interrupted: bool,
}

struct InterruptRegistrations(Vec<signal_hook::SigId>);

impl InterruptRegistrations {
    fn install(interrupted: &Arc<AtomicBool>) -> Result<Self, DTraceError> {
        let mut registrations = Vec::with_capacity(2);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            registrations.push(
                signal_hook::flag::register(signal, Arc::clone(interrupted))
                    .map_err(DTraceError::SignalHandler)?,
            );
        }
        Ok(Self(registrations))
    }
}

impl Drop for InterruptRegistrations {
    fn drop(&mut self) {
        for registration in self.0.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn record_drop(report: &mut DTraceRunReport, kind: c_int, drops: u64) {
    let counter = match kind {
        DTRACEDROP_PRINCIPAL => &mut report.principal_drops,
        DTRACEDROP_AGGREGATION => &mut report.aggregation_drops,
        DTRACEDROP_DYNAMIC | DTRACEDROP_DYNRINSE | DTRACEDROP_DYNDIRTY => &mut report.dynamic_drops,
        _ => &mut report.other_drops,
    };
    *counter = counter.saturating_add(drops);
}

extern "C" fn handle_drop(data: *const DtraceDropData, arg: *mut c_void) -> c_int {
    if data.is_null() || arg.is_null() {
        return 0;
    }
    let report = unsafe { &mut *arg.cast::<DTraceRunReport>() };
    let data = unsafe { &*data };
    record_drop(report, data.kind, data.drops);
    0
}

extern "C" fn chew(_data: *const c_void, _arg: *mut c_void) -> c_int {
    DTRACE_CONSUME_THIS
}

extern "C" fn chewrec(_data: *const c_void, rec: *const c_void, _arg: *mut c_void) -> c_int {
    // NULL rec marks the end of this probe's records — advance to the next.
    if rec.is_null() {
        DTRACE_CONSUME_NEXT
    } else if unsafe { &*rec.cast::<DtraceRecDesc>() }.action == DTRACEACT_EXIT {
        // `exit(status)` is a libdtrace control action, not trace output. Asking
        // libdtrace to format it prints the bare status (for example `0`) and
        // corrupts a machine protocol emitted by the following END clause.
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
    fn dtrace_handle_drop(hdl: *mut DtraceHdl, callback: HandleDropFn, arg: *mut c_void) -> c_int;
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
    fn fileno(stream: *mut libc_file) -> c_int;
}

#[derive(Debug, thiserror::Error)]
pub enum DTraceError {
    #[error("dtrace_open failed: errno={0}")]
    Open(c_int),
    #[error("install DTrace interrupt handler: {0}")]
    SignalHandler(std::io::Error),
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
    #[error("dtrace_handle_drop failed: {0}")]
    HandleDrop(String),
    #[error("dtrace_work failed: {0}")]
    Work(String),
    #[error("argv contains nul byte: {0:?}")]
    BadArg(String),
    #[error("failed to open trace output file: {0}")]
    OutOpen(String),
}

struct TraceOutput {
    fp: *mut libc_file,
    owned: bool,
}

impl TraceOutput {
    /// Open the event sink. `owner` is the invoking user's (uid, gid) when the
    /// tracer is running under sudo (the libdtrace parent must be root, but the
    /// user invoked `carrick trace`): the freshly-created file is `fchown`'d to
    /// them so they fully own their trace output — otherwise it lands root:wheel
    /// and `rm`/editing it needs sudo (which made `--trace-out` LOOK broken: a
    /// naive `sudo cat` without NOPASSWD silently fails to read it). The file is
    /// world-readable either way (fopen "w" → 0644), so reads never need sudo.
    fn open(path: Option<&str>, owner: Option<(u32, u32)>) -> Result<Self, DTraceError> {
        match path {
            Some(path) => {
                let pc =
                    CString::new(path.as_bytes()).map_err(|_| DTraceError::BadArg(path.into()))?;
                let mode = c"w";
                let fp = unsafe { fopen(pc.as_ptr(), mode.as_ptr()) };
                if fp.is_null() {
                    return Err(DTraceError::OutOpen(path.into()));
                }
                if let Some((uid, gid)) = owner {
                    // Best-effort: hand the file to the invoking user. A failure
                    // (e.g. not actually privileged) is non-fatal — the trace
                    // still writes; it's just root-owned.
                    unsafe {
                        libc::fchown(fileno(fp), uid, gid);
                    }
                }
                Ok(Self { fp, owned: true })
            }
            None => Ok(Self {
                fp: unsafe { STDOUT_FP },
                owned: false,
            }),
        }
    }

    fn fp(&self) -> *mut libc_file {
        self.fp
    }
}

impl Drop for TraceOutput {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                fflush(self.fp);
                fclose(self.fp);
            }
        }
    }
}

struct DtraceHandle {
    hdl: *mut DtraceHdl,
}

impl DtraceHandle {
    fn open() -> Result<Self, DTraceError> {
        let mut err: c_int = 0;
        let hdl = unsafe { dtrace_open(DTRACE_VERSION, 0, &mut err) };
        if hdl.is_null() {
            Err(DTraceError::Open(err))
        } else {
            Ok(Self { hdl })
        }
    }

    fn as_ptr(&self) -> *mut DtraceHdl {
        self.hdl
    }

    fn errmsg(&self) -> String {
        unsafe { errmsg(self.hdl) }
    }
}

impl Drop for DtraceHandle {
    fn drop(&mut self) {
        unsafe { dtrace_close(self.hdl) };
    }
}

struct DtraceProcess {
    hdl: *mut DtraceHdl,
    proc_h: *mut PsProchandle,
}

impl DtraceProcess {
    fn create(
        hdl: &DtraceHandle,
        file: *const c_char,
        argv: *const *const c_char,
    ) -> Result<Self, DTraceError> {
        let proc_h = unsafe { dtrace_proc_create(hdl.as_ptr(), file, argv) };
        if proc_h.is_null() {
            Err(DTraceError::ProcCreate(hdl.errmsg()))
        } else {
            Ok(Self {
                hdl: hdl.as_ptr(),
                proc_h,
            })
        }
    }

    fn as_ptr(&self) -> *mut PsProchandle {
        self.proc_h
    }
}

impl Drop for DtraceProcess {
    fn drop(&mut self) {
        unsafe { dtrace_proc_release(self.hdl, self.proc_h) };
    }
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
#[derive(Debug, Clone)]
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
    /// Print any aggregations that remain after the D program's `END` clause.
    /// Built-in profiles emit their complete protocol from `END` and disable
    /// this to prevent an unversioned duplicate dump.
    pub print_remaining_aggregates: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            flowindent: false,
            script: None,
            out_path: None,
            drop_credentials: None,
            print_remaining_aggregates: true,
        }
    }
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
) -> Result<DTraceRunReport, DTraceError> {
    let trace_argv = trace_exec_argv(child_path, child_argv, opts.drop_credentials.as_ref())?;
    let mut argv_ptrs: Vec<*const c_char> = trace_argv.argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // Where the consumer writes events + aggregations. Defaults to stdout;
    // `out_path` redirects to a file so trace output doesn't intermix with an
    // interactive guest's own stdout. The returned fp must outlive the consume
    // loop; closed at the end if we opened it.
    let out = TraceOutput::open(
        opts.out_path.as_deref(),
        opts.drop_credentials.as_ref().map(|c| (c.uid, c.gid)),
    )?;
    let hdl = DtraceHandle::open()?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let mut report = DTraceRunReport::default();
    if unsafe {
        dtrace_handle_drop(
            hdl.as_ptr(),
            handle_drop,
            (&mut report as *mut DTraceRunReport).cast(),
        )
    } != 0
    {
        return Err(DTraceError::HandleDrop(hdl.errmsg()));
    }

    // Sensible runtime defaults are appended to in `all_opts` below.
    let mut all_opts: Vec<(&str, &str)> = vec![
        ("bufsize", "4m"),
        ("aggsize", "4m"),
        ("dynvarsize", "64m"),
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
        if unsafe { dtrace_setopt(hdl.as_ptr(), kc.as_ptr(), vc.as_ptr()) } != 0 {
            let msg = hdl.errmsg();
            return Err(DTraceError::SetOpt {
                key: (*k).into(),
                val: (*v).into(),
                msg,
            });
        }
    }

    let proc_h = DtraceProcess::create(&hdl, trace_argv.exec_path.as_ptr(), argv_ptrs.as_ptr())?;

    let program_src: &str = opts.script.as_deref().unwrap_or(BUNDLED_D_SCRIPT);
    let program_c = match CString::new(program_src) {
        Ok(program_c) => program_c,
        Err(_) => {
            return Err(DTraceError::Compile(
                "D script contains a nul byte".to_owned(),
            ));
        }
    };
    let prog = unsafe {
        dtrace_program_strcompile(
            hdl.as_ptr(),
            program_c.as_ptr(),
            DTRACE_PROBESPEC_NAME,
            DTRACE_C_ZDEFS | DTRACE_C_PSPEC,
            0,
            std::ptr::null(),
        )
    };
    if prog.is_null() {
        let msg = hdl.errmsg();
        return Err(DTraceError::Compile(msg));
    }

    if unsafe { dtrace_program_exec(hdl.as_ptr(), prog, std::ptr::null_mut()) } != 0 {
        let msg = hdl.errmsg();
        return Err(DTraceError::Exec(msg));
    }

    if unsafe { dtrace_go(hdl.as_ptr()) } != 0 {
        let msg = hdl.errmsg();
        return Err(DTraceError::Go(msg));
    }

    // libdtrace installs its own process-signal handlers during activation.
    // Register after `dtrace_go` so signal-hook chains that final handler
    // instead of having our flag handler replaced before the consume loop.
    let _interrupt_registrations = InterruptRegistrations::install(&interrupted)?;

    unsafe { dtrace_proc_continue(hdl.as_ptr(), proc_h.as_ptr()) };

    // When a custom D script is supplied, the user is responsible for bounding
    // it (the skill mandates a `tick-Ns { exit(0) }`), so we let it OUTLIVE the
    // directly-spawned child: a guest `fork`/`clone` becomes a real macOS child
    // (or sibling vCPU thread) that re-registers its probes and can outlive its
    // parent, and a fast-crashing guest still has buffered events plus a
    // `tick`/`END` aggregation to drain. We stop only when the script itself
    // exits (`DONE`) — or the outer `timeout` the CLI wraps every run in fires.
    // With the bundled default tracer (no `-s`, no self-exit) we keep the old
    // behaviour: stop as soon as the spawned child is gone, so a plain
    // `carrick trace -- run …` returns promptly.
    let linger_past_child = opts.script.is_some();
    loop {
        unsafe { dtrace_sleep(hdl.as_ptr()) };
        let status =
            unsafe { dtrace_work(hdl.as_ptr(), out.fp(), chew, chewrec, std::ptr::null_mut()) };
        // dtrace_work writes events into the C stdio buffer, which is
        // block-buffered when the sink is a pipe/file. Flush every cycle so the
        // live stream stays live even when the traced child never exits (e.g.
        // a deadlock we're trying to diagnose).
        unsafe { fflush(out.fp()) };
        let proc_state = unsafe { dtrace_proc_state(hdl.as_ptr(), proc_h.as_ptr()) };
        let child_terminal = proc_state == PS_DEAD || proc_state == PS_UNDEAD;
        if interrupted.load(Ordering::Acquire) {
            report.interrupted = true;
            break;
        }
        match status {
            DTRACE_WORKSTATUS_DONE => break,
            DTRACE_WORKSTATUS_OKAY => {
                if child_terminal && !linger_past_child {
                    break;
                }
            }
            _ => {
                let msg = hdl.errmsg();
                return Err(DTraceError::Work(msg));
            }
        }
    }

    unsafe { dtrace_stop(hdl.as_ptr()) };
    report.interrupted |= interrupted.load(Ordering::Acquire);
    if opts.print_remaining_aggregates {
        unsafe { dtrace_aggregate_snap(hdl.as_ptr()) };
        unsafe { dtrace_aggregate_print(hdl.as_ptr(), out.fp(), std::ptr::null_mut()) };
    }
    unsafe { fflush(out.fp()) };
    Ok(report)
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

pub fn join_ids(ids: &[u32]) -> String {
    ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::{
        DTRACE_CONSUME_NEXT, DTRACE_CONSUME_THIS, DTRACEACT_EXIT, DTRACEDROP_AGGREGATION,
        DTRACEDROP_DYNAMIC, DTRACEDROP_DYNDIRTY, DTRACEDROP_DYNRINSE, DTRACEDROP_PRINCIPAL,
        DTraceRunReport, DtraceRecDesc, TRACE_CHILD_COMMAND, TraceDropCredentials, TraceOptions,
        chewrec, join_ids, record_drop, trace_exec_argv,
    };
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

    #[test]
    fn join_ids_formats_comma_separated_decimal_ids() {
        assert_eq!(join_ids(&[]), "");
        assert_eq!(join_ids(&[20]), "20");
        assert_eq!(join_ids(&[20, 12, 501]), "20,12,501");
    }

    #[test]
    fn macos_drop_ordinals_and_categories_are_pinned() {
        assert_eq!(DTRACEDROP_PRINCIPAL, 0);
        assert_eq!(DTRACEDROP_AGGREGATION, 1);
        assert_eq!(DTRACEDROP_DYNAMIC, 2);
        assert_eq!(DTRACEDROP_DYNRINSE, 3);
        assert_eq!(DTRACEDROP_DYNDIRTY, 4);

        let mut report = DTraceRunReport::default();
        record_drop(&mut report, DTRACEDROP_PRINCIPAL, 1);
        record_drop(&mut report, DTRACEDROP_AGGREGATION, 2);
        record_drop(&mut report, DTRACEDROP_DYNAMIC, 3);
        record_drop(&mut report, DTRACEDROP_DYNRINSE, 4);
        record_drop(&mut report, DTRACEDROP_DYNDIRTY, 5);
        record_drop(&mut report, 9, 6);
        assert_eq!(
            report,
            DTraceRunReport {
                principal_drops: 1,
                aggregation_drops: 2,
                dynamic_drops: 12,
                other_drops: 6,
                interrupted: false,
            }
        );
    }

    #[test]
    fn default_trace_options_print_remaining_aggregates() {
        assert!(TraceOptions::default().print_remaining_aggregates);
    }

    #[test]
    fn record_consumer_suppresses_exit_status_but_formats_protocol_records() {
        let exit = DtraceRecDesc {
            action: DTRACEACT_EXIT,
            size: 0,
            offset: 0,
            alignment: 0,
            format: 0,
            argument: 0,
            user_argument: 0,
        };
        let printf = DtraceRecDesc { action: 3, ..exit };
        assert_eq!(
            chewrec(
                std::ptr::null(),
                (&exit as *const DtraceRecDesc).cast(),
                std::ptr::null_mut(),
            ),
            DTRACE_CONSUME_NEXT
        );
        assert_eq!(
            chewrec(
                std::ptr::null(),
                (&printf as *const DtraceRecDesc).cast(),
                std::ptr::null_mut(),
            ),
            DTRACE_CONSUME_THIS
        );
    }
}
