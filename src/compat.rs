use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallArgs(pub [u64; 6]);

impl From<[u64; 6]> for SyscallArgs {
    fn from(args: [u64; 6]) -> Self {
        Self(args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompatEvent {
    SyscallEntry {
        number: u64,
        name: String,
        args: SyscallArgs,
    },
    SyscallReturn {
        number: u64,
        name: String,
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
}

#[derive(Debug, Default)]
pub struct CompatReporter {
    events: Vec<CompatEvent>,
}

impl CompatReporter {
    pub fn record(&mut self, event: CompatEvent) {
        crate::probes::fire(&event);
        // Opt-in syscall trace. Off by default; set
        // `CARRICK_TRACE_SYSCALLS=1` to get one-line-per-event output on
        // stderr. Useful when chasing "where does this EINVAL come
        // from?" without standing up the full libdtrace consumer.
        if std::env::var_os("CARRICK_TRACE_SYSCALLS").is_some() {
            if let Ok(line) = serde_json::to_string(&event) {
                eprintln!("[carrick-syscall] {line}");
            }
        }
        self.events.push(event);
    }

    pub fn finish(self) -> CompatReport {
        let mut unhandled_syscalls = HashMap::<(u64, String), u64>::new();
        let mut partial_syscalls = HashMap::<(u64, String, String), u64>::new();
        let mut unhandled_ioctls = HashMap::<u64, u64>::new();
        let mut proc_read_unimplemented = HashMap::<String, u64>::new();
        let mut sys_read_unimplemented = HashMap::<String, u64>::new();
        let mut unsupported_signals = HashMap::<(i32, String), u64>::new();

        let mut syscall_entries = 0_u64;
        let mut syscall_returns_ok = 0_u64;
        let mut syscall_returns_errno = 0_u64;

        for event in self.events {
            match event {
                CompatEvent::SyscallEntry { .. } => {
                    syscall_entries += 1;
                }
                CompatEvent::SyscallReturn { errno, .. } => {
                    if errno.is_some() {
                        syscall_returns_errno += 1;
                    } else {
                        syscall_returns_ok += 1;
                    }
                }
                CompatEvent::UnhandledSyscall { number, name, .. } => {
                    *unhandled_syscalls.entry((number, name)).or_default() += 1;
                }
                CompatEvent::PartialSyscall {
                    number,
                    name,
                    reason,
                    ..
                } => {
                    *partial_syscalls.entry((number, name, reason)).or_default() += 1;
                }
                CompatEvent::UnhandledIoctl { request, .. } => {
                    *unhandled_ioctls.entry(request).or_default() += 1;
                }
                CompatEvent::ProcReadUnimplemented { path } => {
                    *proc_read_unimplemented.entry(path).or_default() += 1;
                }
                CompatEvent::SysReadUnimplemented { path } => {
                    *sys_read_unimplemented.entry(path).or_default() += 1;
                }
                CompatEvent::SignalUnsupported { signum, reason } => {
                    *unsupported_signals.entry((signum, reason)).or_default() += 1;
                }
            }
        }

        let unhandled_syscall_invocations = unhandled_syscalls.values().sum::<u64>();
        let unhandled_syscalls = sorted_syscalls(unhandled_syscalls);
        let partial_syscall_invocations = partial_syscalls.values().sum::<u64>();
        let partial_syscalls = sorted_partials(partial_syscalls);
        let unhandled_ioctl_invocations = unhandled_ioctls.values().sum::<u64>();
        let unhandled_ioctls = sorted_ioctls(unhandled_ioctls);
        let proc_read_unimplemented = sorted_paths(proc_read_unimplemented);
        let sys_read_unimplemented = sorted_paths(sys_read_unimplemented);
        let unsupported_signals = sorted_signals(unsupported_signals);

        let summary = CompatSummary {
            syscall_invocations: syscall_entries,
            syscall_returns_ok,
            syscall_returns_errno,
            distinct_unhandled_syscalls: unhandled_syscalls.len() as u64,
            unhandled_syscall_invocations,
            distinct_partial_syscalls: partial_syscalls.len() as u64,
            partial_syscall_invocations,
            distinct_unhandled_ioctls: unhandled_ioctls.len() as u64,
            unhandled_ioctl_invocations,
            distinct_proc_read_unimplemented: proc_read_unimplemented.len() as u64,
            distinct_sys_read_unimplemented: sys_read_unimplemented.len() as u64,
            distinct_unsupported_signals: unsupported_signals.len() as u64,
        };

        CompatReport {
            summary,
            unhandled_syscalls,
            partial_syscalls,
            unhandled_ioctls,
            proc_read_unimplemented,
            sys_read_unimplemented,
            unsupported_signals,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatReport {
    pub summary: CompatSummary,
    pub unhandled_syscalls: Vec<SyscallCount>,
    pub partial_syscalls: Vec<PartialSyscallCount>,
    pub unhandled_ioctls: Vec<IoctlCount>,
    pub proc_read_unimplemented: Vec<PathCount>,
    pub sys_read_unimplemented: Vec<PathCount>,
    pub unsupported_signals: Vec<SignalCount>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatSummary {
    pub syscall_invocations: u64,
    pub syscall_returns_ok: u64,
    pub syscall_returns_errno: u64,
    pub distinct_unhandled_syscalls: u64,
    pub unhandled_syscall_invocations: u64,
    pub distinct_partial_syscalls: u64,
    pub partial_syscall_invocations: u64,
    pub distinct_unhandled_ioctls: u64,
    pub unhandled_ioctl_invocations: u64,
    pub distinct_proc_read_unimplemented: u64,
    pub distinct_sys_read_unimplemented: u64,
    pub distinct_unsupported_signals: u64,
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
