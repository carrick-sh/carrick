//! `/proc` mount.
//!
//! This module owns Carrick's synthetic procfs registry and renderers. The
//! dispatcher supplies live process/memory context, but adding a new synthetic
//! `/proc` file should require touching this module and its tests.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};
use crate::memory::{
    LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_HEAP_BASE, LINUX_HEAP_SIZE,
    LINUX_MMAP_BASE, LINUX_MMAP_SIZE, LINUX_PAGE_TABLES_BASE, LINUX_STACK_SIZE, LINUX_STACK_TOP,
};

use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcMapsEntry {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub path: String,
}

/// Minimal live state needed by synthetic `/proc` renderers.
#[derive(Debug, Clone, Default)]
pub struct SyntheticProcContext {
    pub executable_path: String,
    pub argv: Vec<String>,
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
    pub brk_current: u64,
    pub mmap_next: u64,
}

pub(crate) fn synthetic_file(path: &str, ctx: &SyntheticProcContext) -> Option<Vec<u8>> {
    match path {
        "/proc/cmdline" => Some(synthetic_proc_cmdline().to_vec()),
        "/proc/config.gz" => Some(synthetic_proc_config_gz()),
        "/proc/cpuinfo" => Some(synthetic_proc_cpuinfo()),
        "/proc/diskstats" => Some(synthetic_proc_diskstats().to_vec()),
        "/proc/filesystems" => Some(synthetic_proc_filesystems().to_vec()),
        "/proc/loadavg" => Some(synthetic_proc_loadavg().to_vec()),
        "/proc/meminfo" => Some(synthetic_proc_meminfo().to_vec()),
        "/proc/mounts" => Some(synthetic_proc_mounts().to_vec()),
        "/proc/partitions" => Some(synthetic_proc_partitions().to_vec()),
        "/proc/stat" => Some(synthetic_proc_stat()),
        "/proc/uptime" => Some(synthetic_proc_uptime().into_bytes()),
        "/proc/version" => Some(synthetic_proc_version().to_vec()),
        "/proc/self/auxv" => Some(synthetic_proc_self_auxv().to_vec()),
        "/proc/self/cmdline" => Some(synthetic_proc_self_cmdline(&ctx.argv, &ctx.executable_path)),
        "/proc/self/comm" => Some(synthetic_proc_self_comm(&ctx.executable_path).into_bytes()),
        "/proc/self/limits" => Some(synthetic_proc_self_limits().to_vec()),
        "/proc/self/maps" => Some(synthetic_proc_maps(ctx).into_bytes()),
        "/proc/self/stat" => Some(synthetic_proc_self_stat(&ctx.executable_path).into_bytes()),
        "/proc/self/statm" => Some(synthetic_proc_self_statm()),
        "/proc/self/status" => Some(synthetic_proc_self_status(&ctx.executable_path).into_bytes()),
        "/proc/sys/kernel/osrelease" => Some(synthetic_proc_osrelease().to_vec()),
        "/proc/sys/kernel/hostname" => Some(synthetic_proc_hostname().to_vec()),
        // The default 64-bit Linux pid ceiling. LTP (e.g. setpgid02) reads
        // this to bound pid scans; without it tst_test aborts with ENOENT.
        "/proc/sys/kernel/pid_max" => Some(b"4194304\n".to_vec()),
        "/proc/sys/kernel/random/boot_id" => Some(synthetic_proc_boot_id().to_vec()),
        // glibc's `__check_pf` fallback for AF_NETLINK-less hosts.
        "/proc/net/if_inet6" => {
            Some(b"00000000000000000000000000000001 01 80 10 80       lo\n".to_vec())
        }
        _ => {
            let self_comm = process_short_name(&ctx.executable_path);
            parse_proc_pid_path(path)
                .and_then(|(pid, rest)| synthetic_proc_pid_file(pid, rest, &self_comm))
        }
    }
}

/// Directory entries (tid names) for `/proc/<pid>/task/`, or `None` if `pid`
/// isn't a guest we expose.
pub(crate) fn synthetic_task_dir(pid: u32) -> Option<Vec<String>> {
    let own = crate::thread::current_thread_states();
    if own.iter().any(|(t, _)| *t as u32 == pid) {
        return Some(own.iter().map(|(t, _)| t.to_string()).collect());
    }
    if crate::host_proc::is_guest_process(pid) {
        return Some(vec![pid.to_string()]);
    }
    None
}

/// `(., .., <tid>...)` entries for a `/proc/<pid>/task/` path.
fn proc_task_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    let p = path.strip_suffix('/').unwrap_or(path);
    let pid: u32 = p
        .strip_prefix("/proc/")?
        .strip_suffix("/task")?
        .parse()
        .ok()?;
    let tids = synthetic_task_dir(pid)?;
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(tids.into_iter().map(|t| DirEnt {
        name: t,
        kind: EntryKind::Directory,
    }));
    Some(entries)
}

pub struct ProcVfs;

impl ProcVfs {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProcVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for ProcVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/proc" || proc_task_dir_entries(path).is_some() {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o555,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if synthetic_file(path, &SyntheticProcContext::default()).is_some() {
            return Ok(Metadata {
                kind: EntryKind::File,
                mode: 0o444,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        Err(LINUX_ENOENT)
    }

    fn readdir(&self, path: &str) -> Result<Vec<super::DirEnt>, VfsError> {
        if path != "/proc" {
            return Err(LINUX_ENOTDIR);
        }
        Err(LINUX_ENOTDIR)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        if let Some(entries) = proc_task_dir_entries(path) {
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags: 0,
            });
        }
        let synth_ctx = SyntheticProcContext {
            executable_path: ctx.executable_path.unwrap_or("").to_owned(),
            argv: ctx.argv.unwrap_or(&[]).to_vec(),
            address_space_regions: ctx.address_space_regions.map(|regions| regions.to_vec()),
            brk_current: ctx.brk_current,
            mmap_next: ctx.mmap_next,
        };
        let Some(contents) = synthetic_file(path, &synth_ctx) else {
            return Err(crate::linux_abi::LINUX_ENOSYS);
        };
        if flags.write {
            return Err(LINUX_EACCES);
        }
        Ok(VfsHandle::Bytes {
            path: path.to_string(),
            contents,
            status_flags: 0,
        })
    }

    fn name(&self) -> &'static str {
        "proc"
    }
}

fn synthetic_proc_maps(ctx: &SyntheticProcContext) -> String {
    if let Some(regions) = ctx.address_space_regions.as_deref() {
        return render_proc_maps_from_regions(
            regions,
            &ctx.executable_path,
            ctx.brk_current,
            ctx.mmap_next,
        );
    }
    format!(
        "0000000000400000-0000000000410000 r-xp 00000000 00:00 0 {executable_path}\n\
         {heap_base:016x}-{heap_end:016x} rw-p 00000000 00:00 0 [heap]\n\
         {mmap_base:016x}-{mmap_end:016x} rwxp 00000000 00:00 0 [carrick-mmap]\n\
         0000007fffe00000-0000008000000000 rw-p 00000000 00:00 0 [stack]\n",
        executable_path = ctx.executable_path,
        heap_base = LINUX_HEAP_BASE,
        heap_end = LINUX_HEAP_BASE + LINUX_HEAP_SIZE,
        mmap_base = LINUX_MMAP_BASE,
        mmap_end = LINUX_MMAP_BASE + LINUX_MMAP_SIZE,
    )
}

fn render_proc_maps_from_regions(
    regions: &[ProcMapsEntry],
    executable_path: &str,
    brk_current: u64,
    mmap_next: u64,
) -> String {
    let mut sorted: Vec<&ProcMapsEntry> = regions.iter().collect();
    sorted.sort_by_key(|r| r.start);
    let mut out = String::new();
    for region in sorted {
        let (start, mut end, label) = label_for_region(region, executable_path);
        match label.as_str() {
            "[heap]" if brk_current > start && brk_current <= region.end => {
                end = brk_current;
            }
            "[carrick-mmap]" if mmap_next > start && mmap_next <= region.end => {
                end = mmap_next;
            }
            _ => {}
        }
        let r = if region.read { 'r' } else { '-' };
        let w = if region.write { 'w' } else { '-' };
        let x = if region.execute { 'x' } else { '-' };
        out.push_str(&format!(
            "{start:016x}-{end:016x} {r}{w}{x}p 00000000 00:00 0                          {label}\n",
        ));
    }
    out
}

fn label_for_region(region: &ProcMapsEntry, executable_path: &str) -> (u64, u64, String) {
    let start = region.start;
    let end = region.end;
    let label = if start == LINUX_HEAP_BASE {
        "[heap]".to_owned()
    } else if start == LINUX_MMAP_BASE {
        "[carrick-mmap]".to_owned()
    } else if start == LINUX_STACK_TOP.saturating_sub(LINUX_STACK_SIZE) {
        "[stack]".to_owned()
    } else if start == LINUX_EL0_TRAMPOLINE_BASE {
        "[carrick-trampoline]".to_owned()
    } else if start == LINUX_EL1_VECTORS_BASE {
        "[carrick-vectors]".to_owned()
    } else if start == LINUX_PAGE_TABLES_BASE {
        "[carrick-pagetables]".to_owned()
    } else if !region.path.is_empty() {
        region.path.clone()
    } else if region.execute {
        executable_path.to_owned()
    } else {
        String::new()
    };
    (start, end, label)
}

fn synthetic_proc_cpuinfo() -> Vec<u8> {
    // One "processor" block per logical CPU so the count agrees with
    // sched_getaffinity, /proc/stat and /sys/.../cpu/online. Go/nproc count
    // CPUs via sched_getaffinity, but lscpu and some runtimes parse this.
    let ncpu = crate::host_facts::logical_cpu_count();
    let mut out = String::new();
    for cpu in 0..ncpu {
        out.push_str(&format!(
            "processor\t: {cpu}\n\
BogoMIPS\t: 48.00\n\
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n\
CPU implementer\t: 0x61\n\
CPU architecture\t: 8\n\
CPU variant\t: 0x0\n\
CPU part\t: 0x000\n\
CPU revision\t: 0\n\
\n"
        ));
    }
    out.push_str("Hardware\t: Carrick\n");
    out.into_bytes()
}

fn synthetic_proc_version() -> &'static [u8] {
    b"Linux version 6.6.0-carrick (carrick@bootstrap) (rustc) #1 SMP PREEMPT_DYNAMIC\n"
}

fn synthetic_proc_osrelease() -> &'static [u8] {
    b"6.6.0-carrick\n"
}

fn synthetic_proc_hostname() -> &'static [u8] {
    b"carrick\n"
}

fn synthetic_proc_loadavg() -> &'static [u8] {
    b"0.00 0.00 0.00 1/1 1\n"
}

fn synthetic_proc_uptime() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as f64;
    format!("{seconds:.2} {seconds:.2}\n")
}

fn synthetic_proc_meminfo() -> &'static [u8] {
    b"MemTotal:       16777216 kB\n\
MemFree:        16000000 kB\n\
MemAvailable:   16000000 kB\n\
Buffers:               0 kB\n\
Cached:                0 kB\n\
SwapCached:            0 kB\n\
Active:                0 kB\n\
Inactive:              0 kB\n\
SwapTotal:             0 kB\n\
SwapFree:              0 kB\n\
Dirty:                 0 kB\n\
Writeback:             0 kB\n\
AnonPages:             0 kB\n\
Mapped:                0 kB\n\
Shmem:                 0 kB\n\
Slab:                  0 kB\n\
KernelStack:           0 kB\n\
PageTables:            0 kB\n\
NFS_Unstable:          0 kB\n\
Bounce:                0 kB\n\
WritebackTmp:          0 kB\n\
CommitLimit:    16777216 kB\n\
Committed_AS:          0 kB\n\
VmallocTotal:   17179869184 kB\n\
VmallocUsed:           0 kB\n\
VmallocChunk:          0 kB\n"
}

fn synthetic_proc_stat() -> Vec<u8> {
    // Aggregate "cpu" line followed by one "cpuN" line per logical CPU, so the
    // per-CPU count agrees with sched_getaffinity and /proc/cpuinfo. The jiffy
    // columns are zero (carrick has no global CPU-time accounting yet).
    let ncpu = crate::host_facts::logical_cpu_count();
    let mut out = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
    for cpu in 0..ncpu {
        out.push_str(&format!("cpu{cpu} 0 0 0 0 0 0 0 0 0 0\n"));
    }
    out.push_str(
        "intr 0\n\
ctxt 0\n\
btime 0\n\
processes 1\n\
procs_running 1\n\
procs_blocked 0\n\
softirq 0\n",
    );
    out.into_bytes()
}

/// Kernel `Cpus_allowed` bitmask format: comma-separated 32-bit groups, most
/// significant first, the high group unpadded and lower groups zero-padded to
/// 8 hex digits (e.g. 10 CPUs → "000003ff" is shown as "3ff"; 33 CPUs →
/// "1,ffffffff"). Built from the online set.
fn cpus_allowed_hex(ncpu: usize) -> String {
    let groups = ncpu.div_ceil(32).max(1);
    let mut parts = Vec::with_capacity(groups);
    for g in (0..groups).rev() {
        let lo = g * 32;
        let mut word: u32 = 0;
        for bit in 0..32 {
            if lo + bit < ncpu {
                word |= 1u32 << bit;
            }
        }
        if g == groups - 1 {
            parts.push(format!("{word:x}"));
        } else {
            parts.push(format!("{word:08x}"));
        }
    }
    parts.join(",")
}

/// Kernel `Cpus_allowed_list` range list: "0" for a uniprocessor, "0-9" for 10.
fn cpus_allowed_list(ncpu: usize) -> String {
    if ncpu <= 1 {
        "0".to_owned()
    } else {
        format!("0-{}", ncpu - 1)
    }
}

fn synthetic_proc_self_status(executable_path: &str) -> String {
    let comm = process_short_name(executable_path);
    let ncpu = crate::host_facts::logical_cpu_count();
    let cpus_hex = cpus_allowed_hex(ncpu);
    let cpus_list = cpus_allowed_list(ncpu);
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    let vsize_kb = host.virtual_bytes / 1024;
    let rss_kb = host.resident_bytes / 1024;
    let peak_kb = (host.virtual_bytes.max(host.maxrss_bytes)) / 1024;
    let hwm_kb = host.maxrss_bytes / 1024;
    format!(
        "Name:\t{comm}\n\
Umask:\t0022\n\
State:\tR (running)\n\
Tgid:\t1\n\
Ngid:\t0\n\
Pid:\t1\n\
PPid:\t0\n\
TracerPid:\t0\n\
Uid:\t0\t0\t0\t0\n\
Gid:\t0\t0\t0\t0\n\
FDSize:\t256\n\
Groups:\t\n\
VmPeak:\t{peak_kb:>8} kB\n\
VmSize:\t{vsize_kb:>8} kB\n\
VmLck:\t       0 kB\n\
VmPin:\t       0 kB\n\
VmHWM:\t{hwm_kb:>8} kB\n\
VmRSS:\t{rss_kb:>8} kB\n\
VmData:\t       0 kB\n\
VmStk:\t       0 kB\n\
VmExe:\t       0 kB\n\
VmLib:\t       0 kB\n\
VmPTE:\t       0 kB\n\
VmSwap:\t       0 kB\n\
Threads:\t1\n\
SigQ:\t0/0\n\
SigPnd:\t0000000000000000\n\
ShdPnd:\t0000000000000000\n\
SigBlk:\t0000000000000000\n\
SigIgn:\t0000000000000000\n\
SigCgt:\t0000000000000000\n\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\n\
Cpus_allowed:\t{cpus_hex}\n\
Cpus_allowed_list:\t{cpus_list}\n\
Mems_allowed:\t1\n\
Mems_allowed_list:\t0\n\
voluntary_ctxt_switches:\t0\n\
nonvoluntary_ctxt_switches:\t0\n"
    )
}

fn synthetic_proc_self_cmdline(argv: &[String], executable_path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let args: Vec<&str> = if argv.is_empty() {
        vec![executable_path]
    } else {
        argv.iter().map(String::as_str).collect()
    };
    for arg in args {
        bytes.extend_from_slice(arg.as_bytes());
        bytes.push(0);
    }
    bytes
}

fn synthetic_proc_self_comm(executable_path: &str) -> String {
    let mut comm = process_short_name(executable_path);
    comm.push('\n');
    comm
}

fn synthetic_proc_self_stat(executable_path: &str) -> String {
    let comm = process_short_name(executable_path);
    let pid = std::process::id();
    let ppid = unsafe { libc::getppid() } as u32;
    proc_stat_line(pid, &comm, 'R', ppid, pid, pid)
}

fn proc_stat_line(pid: u32, comm: &str, state: char, ppid: u32, pgrp: u32, session: u32) -> String {
    format!(
        "{pid} ({comm}) {state} {ppid} {pgrp} {session} 0 -1 4194560 0 0 0 0 0 0 0 0 \
20 0 1 0 1 10485760 256 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 \
17 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}

fn synthetic_proc_pid_file(pid: u32, rest: &str, self_comm: &str) -> Option<Vec<u8>> {
    if let Some(task_rest) = rest.strip_prefix("task/") {
        if let Some((tid_str, file)) = task_rest.split_once('/')
            && let Ok(tid) = tid_str.parse::<u32>()
        {
            return synthetic_proc_pid_file(tid, file, self_comm);
        }
        return None;
    }

    let own_threads = crate::thread::current_thread_states();
    if let Some(&(tid, state)) = own_threads.iter().find(|(t, _)| *t as u32 == pid) {
        let ppid = unsafe { libc::getppid() } as u32;
        let me = std::process::id();
        let _ = tid;
        match rest {
            "stat" => {
                return Some(proc_stat_line(pid, self_comm, state, ppid, me, me).into_bytes());
            }
            "comm" => return Some(format!("{self_comm}\n").into_bytes()),
            "cmdline" => {
                let mut b = self_comm.as_bytes().to_vec();
                b.push(0);
                return Some(b);
            }
            "status" => {
                return Some(
                    format!(
                        "Name:\t{self_comm}\nState:\t{state} ({long})\nTgid:\t{me}\n\
Pid:\t{pid}\nPPid:\t{ppid}\nThreads:\t{n}\n",
                        long = proc_state_long(state),
                        n = own_threads.len(),
                    )
                    .into_bytes(),
                );
            }
            _ => return None,
        }
    }

    if !crate::host_proc::is_guest_process(pid) {
        return None;
    }
    let info = crate::host_proc::pid_info(pid)?;
    let comm = if info.comm.is_empty() {
        "carrick".to_owned()
    } else {
        info.comm.clone()
    };
    match rest {
        "stat" => Some(
            proc_stat_line(pid, &comm, info.state, info.ppid, info.pgid, info.pgid).into_bytes(),
        ),
        "comm" => Some(format!("{comm}\n").into_bytes()),
        "cmdline" => {
            let mut b = comm.clone().into_bytes();
            b.push(0);
            Some(b)
        }
        "status" => Some(
            format!(
                "Name:\t{comm}\n\
State:\t{state} ({state_long})\n\
Tgid:\t{pid}\n\
Pid:\t{pid}\n\
PPid:\t{ppid}\n\
TracerPid:\t0\n\
Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
Threads:\t1\n",
                state = info.state,
                state_long = proc_state_long(info.state),
                ppid = info.ppid,
                uid = info.uid,
                gid = info.gid,
            )
            .into_bytes(),
        ),
        _ => None,
    }
}

fn proc_state_long(state: char) -> &'static str {
    match state {
        'S' => "sleeping",
        'T' => "stopped",
        'Z' => "zombie",
        _ => "running",
    }
}

fn parse_proc_pid_path(path: &str) -> Option<(u32, &str)> {
    let tail = path.strip_prefix("/proc/")?;
    let (pid_str, rest) = tail.split_once('/')?;
    let pid: u32 = pid_str.parse().ok()?;
    Some((pid, rest))
}

fn synthetic_proc_self_statm() -> Vec<u8> {
    // "size resident shared text lib data dt" in pages. size = virtual size,
    // resident = RSS, both from the host kernel; the rest are zero (we don't
    // separately account shared/text/data). Page unit is the guest's page size.
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    let pg = crate::linux_abi::LINUX_PAGE_SIZE;
    let size = host.virtual_bytes / pg;
    let resident = host.resident_bytes / pg;
    format!("{size} {resident} 0 0 0 0 0\n").into_bytes()
}

fn synthetic_proc_boot_id() -> &'static [u8] {
    b"00000000-0000-4000-8000-000000000000\n"
}

fn synthetic_proc_cmdline() -> &'static [u8] {
    b"BOOT_IMAGE=/boot/Image root=/dev/vda1 ro\n"
}

fn synthetic_proc_mounts() -> &'static [u8] {
    b"overlay / overlay ro,relatime 0 0\n"
}

fn synthetic_proc_filesystems() -> &'static [u8] {
    b"nodev\ttmpfs\n\
nodev\tproc\n\
nodev\tsysfs\n\
nodev\toverlay\n"
}

fn synthetic_proc_config_gz() -> Vec<u8> {
    use std::io::Write;
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let body = "\
# Synthesised by carrick for /proc/config.gz\n\
CONFIG_64BIT=y\n\
CONFIG_ARM64=y\n\
CONFIG_MMU=y\n\
CONFIG_EVENTFD=y\n\
CONFIG_SIGNALFD=y\n\
CONFIG_TIMERFD=y\n\
CONFIG_EPOLL=y\n\
CONFIG_FUTEX=y\n\
CONFIG_FUTEX_PI=y\n\
CONFIG_POSIX_TIMERS=y\n\
CONFIG_POSIX_MQUEUE=y\n\
CONFIG_AIO=y\n\
CONFIG_FHANDLE=y\n\
CONFIG_INOTIFY_USER=y\n\
CONFIG_SYSVIPC=y\n\
CONFIG_SECCOMP=y\n\
CONFIG_SECCOMP_FILTER=y\n\
CONFIG_CGROUPS=y\n\
CONFIG_PROC_FS=y\n\
CONFIG_SYSFS=y\n\
CONFIG_TMPFS=y\n\
CONFIG_OVERLAY_FS=y\n\
CONFIG_UNIX=y\n\
CONFIG_INET=y\n\
CONFIG_IPV6=y\n\
CONFIG_NET=y\n\
CONFIG_UTS_NS=y\n\
CONFIG_IPC_NS=y\n\
CONFIG_PID_NS=y\n\
CONFIG_NET_NS=y\n\
CONFIG_USER_NS=y\n";
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            let _ = enc.write_all(body.as_bytes());
            enc.finish().unwrap_or_default()
        })
        .clone()
}

fn synthetic_proc_partitions() -> &'static [u8] {
    b"major minor  #blocks  name\n\n"
}

fn synthetic_proc_diskstats() -> &'static [u8] {
    b""
}

fn synthetic_proc_self_auxv() -> &'static [u8] {
    &[0u8; 16]
}

fn synthetic_proc_self_limits() -> &'static [u8] {
    b"Limit                     Soft Limit           Hard Limit           Units\n\
Max cpu time              unlimited            unlimited            seconds\n\
Max file size             unlimited            unlimited            bytes\n\
Max data size             unlimited            unlimited            bytes\n\
Max stack size            8388608              unlimited            bytes\n\
Max core file size        0                    unlimited            bytes\n\
Max resident set          unlimited            unlimited            bytes\n\
Max processes             unlimited            unlimited            processes\n\
Max open files            1024                 4096                 files\n\
Max locked memory         65536                65536                bytes\n\
Max address space         unlimited            unlimited            bytes\n\
Max file locks            unlimited            unlimited            locks\n\
Max pending signals       unlimited            unlimited            signals\n\
Max msgqueue size         819200               819200               bytes\n\
Max nice priority         0                    0                    \n\
Max realtime priority     0                    0                    \n\
Max realtime timeout      unlimited            unlimited            us\n"
}

fn process_short_name(executable_path: &str) -> String {
    Path::new(executable_path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.chars().take(15).collect())
        .unwrap_or_else(|| "carrick".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_root_returns_directory() {
        let v = ProcVfs::new();
        let md = v.lookup("/proc").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
        assert_eq!(md.mode, 0o555);
    }

    #[test]
    fn lookup_known_file_returns_file() {
        let v = ProcVfs::new();
        let md = v.lookup("/proc/cpuinfo").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(md.mode, 0o444);
    }

    #[test]
    fn lookup_unknown_proc_is_enoent() {
        let v = ProcVfs::new();
        assert_eq!(v.lookup("/proc/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn open_cpuinfo_returns_bytes() {
        let v = ProcVfs::new();
        let h = v
            .open(
                "/proc/cpuinfo",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { path, contents, .. } => {
                assert_eq!(path, "/proc/cpuinfo");
                assert!(!contents.is_empty());
                let s = String::from_utf8_lossy(&contents);
                assert!(s.contains("processor"));
            }
            _ => panic!("expected Bytes variant, got {:?}", h),
        }
    }

    #[test]
    fn open_write_is_eacces() {
        let v = ProcVfs::new();
        let result = v.open(
            "/proc/cpuinfo",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(result, Err(LINUX_EACCES));
    }

    #[test]
    fn open_self_cmdline_uses_executable_path() {
        let v = ProcVfs::new();
        let argv = vec![
            "/usr/bin/test-exe".to_owned(),
            "--flag".to_owned(),
            "value".to_owned(),
        ];
        let h = v
            .open(
                "/proc/self/cmdline",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext {
                    executable_path: Some("/usr/bin/test-exe"),
                    argv: Some(&argv),
                    ..Default::default()
                },
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                assert_eq!(contents, b"/usr/bin/test-exe\0--flag\0value\0");
            }
            _ => panic!("expected Bytes variant"),
        }
    }

    #[test]
    fn proc_maps_uses_vfs_owned_context() {
        let ctx = SyntheticProcContext {
            executable_path: "/bin/demo".to_owned(),
            argv: vec!["/bin/demo".to_owned()],
            address_space_regions: Some(vec![ProcMapsEntry {
                start: LINUX_HEAP_BASE,
                end: LINUX_HEAP_BASE + 0x4000,
                read: true,
                write: true,
                execute: false,
                path: String::new(),
            }]),
            brk_current: LINUX_HEAP_BASE + 0x1234,
            mmap_next: LINUX_MMAP_BASE,
        };
        let maps = String::from_utf8(synthetic_file("/proc/self/maps", &ctx).unwrap()).unwrap();
        assert!(maps.contains("[heap]"));
        assert!(maps.contains(&format!("{:016x}", LINUX_HEAP_BASE + 0x1234)));
    }
}
