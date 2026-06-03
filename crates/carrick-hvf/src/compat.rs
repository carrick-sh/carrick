//! Compatibility reporting primitives for syscall coverage, unknown flags,
//! partial implementations, and runtime diagnostics.
//!
//! THEORY OF OPERATION
//!
//! Every syscall the dispatcher handles flows a [`CompatEvent`] through
//! [`CompatReporter::record`]. That single funnel does three things, in order of
//! cost: it fires the matching USDT probe (gated on a DTrace consumer, so
//! near-free when none is attached), optionally emits a verbose stderr line
//! (opt-in via `CARRICK_TRACE_SYSCALLS`, the env check cached once at
//! construction so it is not re-read per syscall), and then AGGREGATES the event
//! inline.
//!
//! The aggregation design is the load-bearing decision. An earlier version
//! stored one `CompatEvent` per syscall in a `Vec` and allocated a `String` name
//! on the hot path even when nobody consumed the report — an unbounded heap
//! growth that taxed every syscall-heavy run. Now `record` keeps only what a
//! report needs: lock-free `AtomicU64` counters for the common entry/return
//! events, and small dedup `HashMap`s (behind a `parking_lot::Mutex`) for the
//! RARE events — unhandled syscalls, partial implementations, unknown flag bits,
//! unhandled ioctls, unimplemented `/proc` and `/sys` reads, unsupported
//! signals. A syscall-heavy run thus costs a few integer increments rather than
//! a heap push. The detailed aggregate report stays always-on because the maps
//! are cheap and only grow with the number of DISTINCT rare events.
//!
//! [`CompatReport`] is the rendered snapshot (text or JSON), cross-referenced
//! against the static [`crate::syscall`] metadata table to compute coverage. The
//! `unknown_syscall_flags` channel in particular exists to catch Linux ABI drift
//! LOUDLY — a guest passing a flag bit carrick doesn't recognise surfaces here
//! instead of being silently dropped.
//!
//! This module also owns the two `#[repr(C)]` register-snapshot structs
//! ([`SyscallArgs`], [`GuestRegs`]) that the hot-path USDT probes pass to DTrace
//! by raw pointer; their field layout is mirrored by the `.d` scripts and is
//! therefore an ABI — see the per-struct docs and [`crate::probes`].

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallArgs(pub [u64; 6]);

impl From<[u64; 6]> for SyscallArgs {
    fn from(args: [u64; 6]) -> Self {
        Self(args)
    }
}

/// Snapshot of the guest's key aarch64 registers at a trap. Passed to
/// the `vcpu__trap` USDT probe AS A RAW POINTER (the probe arg is the
/// struct's address as a u64); DTrace does `copyin(arg0,
/// sizeof(gregs_t))` and reads fields by offset as native u64s. We do
/// NOT use usdt's `Serialize`→JSON path here: this probe fires on
/// every syscall, so JSON-encoding to a string on each fire would be
/// far too expensive, and `json()`+`strtoll` in D can't even round-
/// trip a full u64 (it parses signed, overflowing past i63). A
/// `#[repr(C)]` struct read directly is both faster and exact.
///
/// `fp` (x29) is the head of the AAPCS64 frame-pointer chain;
/// `stack_guest_base`/`stack_host_base` let a consumer translate stack
/// VAs to host addresses and `copyin` frames. Field ORDER and `repr(C)`
/// are load-bearing — the matching `gregs_t` in `guest_stack.d` mirrors
/// this layout. Keep all fields u64 so offsets are a clean 8*index.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestRegs {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub x8: u64,
    pub x0: u64,
    /// Base of the guest stack's mapped region (guest VA) and the host
    /// VA carrick mapped it at. A DTrace consumer translates any stack
    /// guest VA to its host address with
    ///   `host = stack_host_base + (guest_va - stack_guest_base)`
    /// then `copyin`s it. We expose the two bases SEPARATELY rather
    /// than a single offset because the offset (`host_base -
    /// guest_base`) wraps past i64::MAX when the stack sits high and
    /// the host mapping sits low — and DTrace's `json()`+`strtoll`
    /// parse signed, so a wrapping offset decodes to garbage. Both
    /// bases individually fit in i64, so the subtraction-then-add in D
    /// stays in range. Both 0 if `sp` isn't in any known region.
    pub stack_guest_base: u64,
    pub stack_host_base: u64,
    /// Exclusive guest-VA end of the stack region, so a consumer can
    /// bound-check a frame address before `copyin` (a frame-pointer
    /// chain that walks off the end / into garbage otherwise produces
    /// spurious copyin errors). 0 if no region.
    pub stack_guest_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompatEvent {
    SyscallEntry {
        number: u64,
        name: Cow<'static, str>,
        args: SyscallArgs,
    },
    SyscallReturn {
        number: u64,
        name: Cow<'static, str>,
        retval: i64,
        errno: Option<i32>,
    },
    UnhandledSyscall {
        number: u64,
        name: String,
        args: SyscallArgs,
    },
    PartialSyscall {
        number: u64,
        name: String,
        args: SyscallArgs,
        reason: String,
    },
    UnhandledIoctl {
        fd: i32,
        request: u64,
        arg: u64,
    },
    ProcReadUnimplemented {
        path: String,
    },
    SysReadUnimplemented {
        path: String,
    },
    SignalUnsupported {
        signum: i32,
        reason: String,
    },
    /// The guest passed flag bits we don't recognise to a syscall.
    /// Surfaced systematically by the `check_syscall_flags` helper so
    /// that every syscall-flag drift from the Linux ABI shows up as a
    /// loud, aggregated entry in the compat report instead of being
    /// silently ignored (or, worse, silently dropping behaviour the
    /// guest expected). The `unknown_bits` field is the raw set bits
    /// not covered by `supported_mask`.
    UnknownSyscallFlags {
        number: u64,
        name: String,
        argument: u32,
        unknown_bits: u64,
    },
}

impl CompatEvent {
    pub fn unhandled_syscall(number: u64, name: impl Into<String>, args: SyscallArgs) -> Self {
        Self::UnhandledSyscall {
            number,
            name: name.into(),
            args,
        }
    }

    pub fn partial_syscall(
        number: u64,
        name: impl Into<String>,
        args: SyscallArgs,
        reason: impl Into<String>,
    ) -> Self {
        Self::PartialSyscall {
            number,
            name: name.into(),
            args,
            reason: reason.into(),
        }
    }

    pub fn unhandled_ioctl(fd: i32, request: u64, arg: u64) -> Self {
        Self::UnhandledIoctl { fd, request, arg }
    }

    pub fn proc_read_unimplemented(path: impl Into<String>) -> Self {
        Self::ProcReadUnimplemented { path: path.into() }
    }

    pub fn sys_read_unimplemented(path: impl Into<String>) -> Self {
        Self::SysReadUnimplemented { path: path.into() }
    }

    pub fn unknown_syscall_flags(
        number: u64,
        name: impl Into<String>,
        argument: u32,
        unknown_bits: u64,
    ) -> Self {
        Self::UnknownSyscallFlags {
            number,
            name: name.into(),
            argument,
            unknown_bits,
        }
    }
}

/// Aggregates compatibility events as they happen rather than buffering
/// every syscall. Storing one `CompatEvent` per syscall (the old
/// design) grew an unbounded `Vec` and allocated a `String` name on the
/// hot path even when nobody consumed it. Now `record` bumps counters /
/// rare-event maps directly, so a syscall-heavy run costs a few integer
/// increments instead of a heap push. The detailed report stays
/// always-on (the aggregate maps are cheap); only the verbose
/// per-event stderr trace is opt-in via `CARRICK_TRACE_SYSCALLS`.
#[derive(Debug)]
pub struct CompatReporter {
    syscall_entries: AtomicU64,
    syscall_returns_ok: AtomicU64,
    syscall_returns_errno: AtomicU64,
    unhandled_syscalls: Mutex<HashMap<(u64, String), u64>>,
    partial_syscalls: Mutex<HashMap<(u64, String, String), u64>>,
    unhandled_ioctls: Mutex<HashMap<u64, u64>>,
    proc_read_unimplemented: Mutex<HashMap<String, u64>>,
    sys_read_unimplemented: Mutex<HashMap<String, u64>>,
    unsupported_signals: Mutex<HashMap<(i32, String), u64>>,
    unknown_syscall_flags: Mutex<HashMap<(u64, String, u32, u64), u64>>,
    /// Cached once at construction so we don't `getenv` per syscall.
    trace_syscalls: bool,
}

impl Default for CompatReporter {
    fn default() -> Self {
        Self {
            syscall_entries: AtomicU64::new(0),
            syscall_returns_ok: AtomicU64::new(0),
            syscall_returns_errno: AtomicU64::new(0),
            unhandled_syscalls: Mutex::new(HashMap::new()),
            partial_syscalls: Mutex::new(HashMap::new()),
            unhandled_ioctls: Mutex::new(HashMap::new()),
            proc_read_unimplemented: Mutex::new(HashMap::new()),
            sys_read_unimplemented: Mutex::new(HashMap::new()),
            unsupported_signals: Mutex::new(HashMap::new()),
            unknown_syscall_flags: Mutex::new(HashMap::new()),
            trace_syscalls: std::env::var_os("CARRICK_TRACE_SYSCALLS").is_some(),
        }
    }
}

impl CompatReporter {
    pub fn record(&self, event: CompatEvent) {
        // USDT probe first — usdt gates the closure on is_enabled, so
        // this is near-free when no DTrace consumer is attached.
        crate::probes::fire(&event);
        // Opt-in verbose stderr trace (cached env check, not per-call).
        if self.trace_syscalls
            && let Ok(line) = serde_json::to_string(&event)
        {
            eprintln!("[carrick-syscall] {line}");
        }
        // Aggregate inline. Common events (entry/return) are pure
        // counter bumps; rare events land in their dedup maps.
        match event {
            CompatEvent::SyscallEntry { .. } => {
                self.syscall_entries.fetch_add(1, Ordering::Relaxed);
            }
            CompatEvent::SyscallReturn { errno, .. } => {
                if errno.is_some() {
                    self.syscall_returns_errno.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.syscall_returns_ok.fetch_add(1, Ordering::Relaxed);
                }
            }
            CompatEvent::UnhandledSyscall { number, name, .. } => {
                *self
                    .unhandled_syscalls
                    .lock()
                    .entry((number, name))
                    .or_default() += 1;
            }
            CompatEvent::PartialSyscall {
                number,
                name,
                reason,
                ..
            } => {
                *self
                    .partial_syscalls
                    .lock()
                    .entry((number, name, reason))
                    .or_default() += 1;
            }
            CompatEvent::UnhandledIoctl { request, .. } => {
                *self.unhandled_ioctls.lock().entry(request).or_default() += 1;
            }
            CompatEvent::ProcReadUnimplemented { path } => {
                *self.proc_read_unimplemented.lock().entry(path).or_default() += 1;
            }
            CompatEvent::SysReadUnimplemented { path } => {
                *self.sys_read_unimplemented.lock().entry(path).or_default() += 1;
            }
            CompatEvent::SignalUnsupported { signum, reason } => {
                *self
                    .unsupported_signals
                    .lock()
                    .entry((signum, reason))
                    .or_default() += 1;
            }
            CompatEvent::UnknownSyscallFlags {
                number,
                name,
                argument,
                unknown_bits,
            } => {
                *self
                    .unknown_syscall_flags
                    .lock()
                    .entry((number, name, argument, unknown_bits))
                    .or_default() += 1;
            }
        }
    }

    pub fn snapshot(&self) -> CompatReport {
        let syscall_entries = self.syscall_entries.load(Ordering::Relaxed);
        let syscall_returns_ok = self.syscall_returns_ok.load(Ordering::Relaxed);
        let syscall_returns_errno = self.syscall_returns_errno.load(Ordering::Relaxed);
        let unhandled_raw = self.unhandled_syscalls.lock().clone();
        let partial_syscalls = self.partial_syscalls.lock().clone();
        let unhandled_ioctls = self.unhandled_ioctls.lock().clone();
        let proc_read_unimplemented = self.proc_read_unimplemented.lock().clone();
        let sys_read_unimplemented = self.sys_read_unimplemented.lock().clone();
        let unsupported_signals = self.unsupported_signals.lock().clone();
        let unknown_syscall_flags = self.unknown_syscall_flags.lock().clone();

        // Split hit-but-unimplemented syscalls into those the aarch64 table
        // recognises (Deferred/Planned roadmap entries — e.g. io_uring_setup)
        // versus genuinely unknown numbers. This lets the report tell "we know
        // this syscall and haven't emulated it yet" apart from "we have no idea
        // what this number is", so a real workload's deferred-syscall hit-counts
        // can drive what to implement next.
        let mut deferred_map: HashMap<(u64, String), u64> = HashMap::new();
        let mut unknown_map: HashMap<(u64, String), u64> = HashMap::new();
        for (key, count) in unhandled_raw {
            if crate::syscall::lookup_aarch64(key.0).is_some() {
                deferred_map.insert(key, count);
            } else {
                unknown_map.insert(key, count);
            }
        }
        let unhandled_syscall_invocations = unknown_map.values().sum::<u64>();
        let deferred_syscall_invocations = deferred_map.values().sum::<u64>();
        let unhandled_syscalls = sorted_syscalls(unknown_map);
        let deferred_syscalls = sorted_syscalls(deferred_map);
        let partial_syscall_invocations = partial_syscalls.values().sum::<u64>();
        let partial_syscalls = sorted_partials(partial_syscalls);
        let unhandled_ioctl_invocations = unhandled_ioctls.values().sum::<u64>();
        let unhandled_ioctls = sorted_ioctls(unhandled_ioctls);
        let proc_read_unimplemented = sorted_paths(proc_read_unimplemented);
        let sys_read_unimplemented = sorted_paths(sys_read_unimplemented);
        let unsupported_signals = sorted_signals(unsupported_signals);
        let unknown_flag_invocations = unknown_syscall_flags.values().sum::<u64>();
        let unknown_syscall_flags = sorted_unknown_flags(unknown_syscall_flags);

        let summary = CompatSummary {
            syscall_invocations: syscall_entries,
            syscall_returns_ok,
            syscall_returns_errno,
            distinct_unhandled_syscalls: unhandled_syscalls.len() as u64,
            unhandled_syscall_invocations,
            distinct_deferred_syscalls: deferred_syscalls.len() as u64,
            deferred_syscall_invocations,
            distinct_partial_syscalls: partial_syscalls.len() as u64,
            partial_syscall_invocations,
            distinct_unhandled_ioctls: unhandled_ioctls.len() as u64,
            unhandled_ioctl_invocations,
            distinct_proc_read_unimplemented: proc_read_unimplemented.len() as u64,
            distinct_sys_read_unimplemented: sys_read_unimplemented.len() as u64,
            distinct_unsupported_signals: unsupported_signals.len() as u64,
            distinct_unknown_syscall_flags: unknown_syscall_flags.len() as u64,
            unknown_syscall_flag_invocations: unknown_flag_invocations,
        };

        CompatReport {
            summary,
            unhandled_syscalls,
            deferred_syscalls,
            partial_syscalls,
            unhandled_ioctls,
            proc_read_unimplemented,
            sys_read_unimplemented,
            unsupported_signals,
            unknown_syscall_flags,
        }
    }

    pub fn finish(self) -> CompatReport {
        self.snapshot()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatReport {
    pub summary: CompatSummary,
    /// Hit-but-unimplemented syscalls whose numbers are NOT in the aarch64
    /// table — genuinely unknown to Carrick.
    pub unhandled_syscalls: Vec<SyscallCount>,
    /// Hit-but-unimplemented syscalls the aarch64 table DOES recognise
    /// (Deferred/Planned). Sorted by call count so the top entries are the
    /// highest-value emulation targets for the workload that produced them.
    pub deferred_syscalls: Vec<SyscallCount>,
    pub partial_syscalls: Vec<PartialSyscallCount>,
    pub unhandled_ioctls: Vec<IoctlCount>,
    pub proc_read_unimplemented: Vec<PathCount>,
    pub sys_read_unimplemented: Vec<PathCount>,
    pub unsupported_signals: Vec<SignalCount>,
    pub unknown_syscall_flags: Vec<UnknownFlagsCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownFlagsCount {
    pub number: u64,
    pub name: String,
    /// Which argument index carried the unknown bits (0-based; the
    /// kernel mostly uses arg 3 for openat's `flags`, arg 1 for pipe2,
    /// etc., so the index makes the report self-documenting).
    pub argument: u32,
    /// Hex string for human readability — these are commonly things
    /// like `0x40000` (O_NOATIME) or `0x4000` (O_DIRECTORY) and you
    /// want them in the same shape as the Linux header.
    pub unknown_bits: String,
    pub count: u64,
}

fn sorted_unknown_flags(src: HashMap<(u64, String, u32, u64), u64>) -> Vec<UnknownFlagsCount> {
    let mut entries: Vec<UnknownFlagsCount> = src
        .into_iter()
        .map(
            |((number, name, argument, unknown_bits), count)| UnknownFlagsCount {
                number,
                name,
                argument,
                unknown_bits: format!("{:#x}", unknown_bits),
                count,
            },
        )
        .collect();
    entries.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.number.cmp(&b.number))
            .then_with(|| a.argument.cmp(&b.argument))
    });
    entries
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatSummary {
    pub syscall_invocations: u64,
    pub syscall_returns_ok: u64,
    pub syscall_returns_errno: u64,
    pub distinct_unhandled_syscalls: u64,
    pub unhandled_syscall_invocations: u64,
    pub distinct_deferred_syscalls: u64,
    pub deferred_syscall_invocations: u64,
    pub distinct_partial_syscalls: u64,
    pub partial_syscall_invocations: u64,
    pub distinct_unhandled_ioctls: u64,
    pub unhandled_ioctl_invocations: u64,
    pub distinct_proc_read_unimplemented: u64,
    pub distinct_sys_read_unimplemented: u64,
    pub distinct_unsupported_signals: u64,
    pub distinct_unknown_syscall_flags: u64,
    pub unknown_syscall_flag_invocations: u64,
}

impl CompatReport {
    pub fn render(&self, format: CompatReportFormat) -> Result<String, CompatReportRenderError> {
        match format {
            CompatReportFormat::Json => Ok(serde_json::to_string_pretty(self)?),
            CompatReportFormat::Text => Ok(self.render_text()),
        }
    }

    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Carrick compatibility report\n\n");
        out.push_str("Summary:\n");
        let s = &self.summary;
        out.push_str(&format!(
            "  syscalls observed: {} (returned ok: {}, errno: {})\n",
            s.syscall_invocations, s.syscall_returns_ok, s.syscall_returns_errno,
        ));
        out.push_str(&format!(
            "  unhandled syscalls: {} distinct, {} invocations\n",
            s.distinct_unhandled_syscalls, s.unhandled_syscall_invocations,
        ));
        out.push_str(&format!(
            "  deferred syscalls (recognised, not yet emulated): {} distinct, {} invocations\n",
            s.distinct_deferred_syscalls, s.deferred_syscall_invocations,
        ));
        out.push_str(&format!(
            "  partial syscalls: {} distinct, {} invocations\n",
            s.distinct_partial_syscalls, s.partial_syscall_invocations,
        ));
        out.push_str(&format!(
            "  unhandled ioctls: {} distinct, {} invocations\n",
            s.distinct_unhandled_ioctls, s.unhandled_ioctl_invocations,
        ));
        out.push_str(&format!(
            "  unimplemented /proc reads: {} distinct paths\n",
            s.distinct_proc_read_unimplemented,
        ));
        out.push_str(&format!(
            "  unimplemented /sys reads: {} distinct paths\n",
            s.distinct_sys_read_unimplemented,
        ));
        out.push_str(&format!(
            "  unsupported signals: {} distinct\n",
            s.distinct_unsupported_signals,
        ));
        render_section(&mut out, "Unhandled syscalls", &self.unhandled_syscalls);
        render_section(
            &mut out,
            "Deferred syscalls (recognised, not yet emulated, top by call count)",
            &self.deferred_syscalls,
        );
        render_section(&mut out, "Partial syscalls", &self.partial_syscalls);
        render_section(&mut out, "Unhandled ioctls", &self.unhandled_ioctls);
        render_section(
            &mut out,
            "Unimplemented /proc reads",
            &self.proc_read_unimplemented,
        );
        render_section(
            &mut out,
            "Unimplemented /sys reads",
            &self.sys_read_unimplemented,
        );
        render_section(&mut out, "Unsupported signals", &self.unsupported_signals);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CompatReportFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallCount {
    pub number: u64,
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSyscallCount {
    pub number: u64,
    pub name: String,
    pub reason: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoctlCount {
    pub request: u64,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathCount {
    pub path: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalCount {
    pub signum: i32,
    pub reason: String,
    pub count: u64,
}

#[derive(Debug, Error)]
pub enum CompatReportRenderError {
    #[error("failed to serialize compatibility report: {0}")]
    Json(#[from] serde_json::Error),
}

impl std::fmt::Display for SyscallCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}) x{}", self.name, self.number, self.count)
    }
}

impl std::fmt::Display for PartialSyscallCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) x{}: {}",
            self.name, self.number, self.count, self.reason
        )
    }
}

impl std::fmt::Display for IoctlCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x} x{}", self.request, self.count)
    }
}

impl std::fmt::Display for PathCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} x{}", self.path, self.count)
    }
}

impl std::fmt::Display for SignalCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} x{}: {}", self.signum, self.count, self.reason)
    }
}

fn sorted_syscalls(counts: HashMap<(u64, String), u64>) -> Vec<SyscallCount> {
    let mut rows = counts
        .into_iter()
        .map(|((number, name), count)| SyscallCount {
            number,
            name,
            count,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.number.cmp(&b.number)));
    rows
}

fn sorted_partials(counts: HashMap<(u64, String, String), u64>) -> Vec<PartialSyscallCount> {
    let mut rows = counts
        .into_iter()
        .map(|((number, name, reason), count)| PartialSyscallCount {
            number,
            name,
            reason,
            count,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.number.cmp(&b.number)));
    rows
}

fn sorted_ioctls(counts: HashMap<u64, u64>) -> Vec<IoctlCount> {
    let mut rows = counts
        .into_iter()
        .map(|(request, count)| IoctlCount { request, count })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.request.cmp(&b.request)));
    rows
}

fn sorted_paths(counts: HashMap<String, u64>) -> Vec<PathCount> {
    let mut rows = counts
        .into_iter()
        .map(|(path, count)| PathCount { path, count })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.path.cmp(&b.path)));
    rows
}

fn sorted_signals(counts: HashMap<(i32, String), u64>) -> Vec<SignalCount> {
    let mut rows = counts
        .into_iter()
        .map(|((signum, reason), count)| SignalCount {
            signum,
            reason,
            count,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.signum.cmp(&b.signum)));
    rows
}

fn render_section<T: std::fmt::Display>(out: &mut String, name: &str, rows: &[T]) {
    out.push('\n');
    out.push_str(name);
    out.push_str(":\n");
    if rows.is_empty() {
        out.push_str("  none\n");
        return;
    }
    for row in rows {
        out.push_str("  ");
        out.push_str(&row.to_string());
        out.push('\n');
    }
}
