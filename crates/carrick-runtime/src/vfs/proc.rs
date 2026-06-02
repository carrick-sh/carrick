//! `/proc` mount.
//!
//! This module owns Carrick's synthetic procfs registry and renderers. The
//! dispatcher supplies live process/memory context, but adding a new synthetic
//! `/proc` file should require touching this module and its tests.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};
use crate::memory::{
    LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_HEAP_BASE, LINUX_HEAP_SIZE,
    LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE, LINUX_RLIMIT_STACK_SOFT,
    LINUX_SIGRETURN_TRAMPOLINE_BASE, LINUX_STACK_SIZE, LINUX_STACK_TOP,
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
    /// Guest environment (`KEY=VALUE`) as opaque bytes, surfaced via
    /// `/proc/self/environ` (env values need not be UTF-8).
    pub environ: Vec<Vec<u8>>,
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
    pub brk_current: u64,
    pub mmap_next: u64,
    /// Signal-disposition masks for `/proc/<pid>/status` (bit `signum-1`).
    pub sig_ignored: u64,
    pub sig_caught: u64,
    pub sig_shdpnd: u64,
}

/// The three writable user-namespace map files (only the `self/` forms; writing
/// another live process's map needs a parent relationship carrick does not yet
/// model — design §4.3). Phase 1 supports the self-map case, which is what
/// `unshare -Ur`, apt's sandbox, and bubblewrap exercise.
pub(crate) fn is_userns_map_path(path: &str) -> bool {
    matches!(
        path,
        "/proc/self/uid_map" | "/proc/self/gid_map" | "/proc/self/setgroups"
    )
}

/// The per-process tunables Linux exposes read-WRITE that carrick accepts but
/// does not act on (it has no live OOM/audit/timer-slack state). Making them
/// writable means systemd/container managers that write them at startup get a
/// successful write instead of EACCES/EBADF (and the warning that follows);
/// the read keeps returning the documented default.
pub(crate) fn is_writable_tunable_path(path: &str) -> bool {
    matches!(
        normalize_self_pid_path(path).as_ref(),
        "/proc/self/oom_score_adj"
            | "/proc/self/oom_adj"
            | "/proc/self/loginuid"
            | "/proc/self/timerslack_ns"
    )
}

/// Apply a write(2) to one of the user-namespace map files. Returns the
/// `write(2)` result: `Ok(bytes_written)` on success (the whole buffer is
/// "consumed" per kernel behavior), or `Err(positive_errno)` (EPERM / EINVAL)
/// to be returned as a negative errno. The write-once, setgroups-gate, ≤5-line
/// and unprivileged-single-id rules are enforced by [`crate::namespace::user`].
pub(crate) fn write_userns_map(path: &str, data: &[u8]) -> Result<usize, i64> {
    let text = std::str::from_utf8(data).map_err(|_| crate::namespace::user::EINVAL)?;
    let privileged = crate::namespace::process::is_map_write_privileged();
    // The writer's outside id for the unprivileged single-id rule. carrick runs
    // the guest as a single host identity; the parent-ns euid/egid is the host
    // identity, which for the default container is 0. We use the modeled creds
    // via cred_ipc's published self euid is not reachable here cheaply, so use
    // the namespace store's notion (identity ns → 0). The unprivileged path is
    // only reached after the guest unshared a userns, where the parent-ns id is
    // the pre-unshare euid; for the common rootful case `privileged` is true and
    // this value is unused.
    let euid_outside = 0;
    let egid_outside = 0;
    crate::namespace::process::with_user_mut(|ns| match path {
        "/proc/self/uid_map" => ns.write_uid_map(text, privileged, euid_outside),
        "/proc/self/gid_map" => ns.write_gid_map(text, privileged, egid_outside),
        "/proc/self/setgroups" => ns.write_setgroups(text),
        _ => Err(crate::namespace::user::EINVAL),
    })
    .map(|()| data.len())
}

/// The instant carrick's guest "booted" (first time anything asks). Drives
/// `/proc/uptime` and `/proc/stat`'s `btime` so they report seconds-since-boot
/// rather than seconds-since-the-UNIX-epoch (the old bug made uptime ~56 years
/// and btime 0). Lazily initialised; close enough to process start for any
/// uptime/age math a guest performs.
fn boot_instant() -> Instant {
    static BOOT: OnceLock<Instant> = OnceLock::new();
    *BOOT.get_or_init(Instant::now)
}

/// 16 cryptographically-random bytes (best-effort; all-zero on the rare
/// getrandom failure so we never panic in production — the no-panic gate).
fn random_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let _ = getrandom::fill(&mut buf);
    buf
}

/// Format 16 bytes as a version-4 UUID string (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`),
/// newline-terminated. Used for both `kernel/random/uuid` (fresh per read) and
/// `kernel/random/boot_id` (stable per run).
fn format_uuid_v4(mut b: [u8; 16]) -> Vec<u8> {
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant RFC 4122
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
    .into_bytes()
}

/// `/proc/sys/kernel/random/uuid`: a fresh random v4 UUID on every read — Linux
/// uses this as a cheap unique-id/entropy source, so it must NOT be static.
fn sysctl_random_uuid() -> Vec<u8> {
    format_uuid_v4(random_16())
}

/// `/proc/sys/kernel/random/boot_id`: a random v4 UUID generated once per
/// carrick run and stable thereafter (proc_sys_kernel(5)). Replaces the old
/// all-zero sentinel that made every guest look like the same boot.
fn sysctl_boot_id() -> Vec<u8> {
    static BOOT_ID: OnceLock<Vec<u8>> = OnceLock::new();
    BOOT_ID.get_or_init(|| format_uuid_v4(random_16())).clone()
}

/// A sysctl leaf value: a fixed byte string or a per-read generator.
enum Sysctl {
    Static(&'static [u8]),
    Dynamic(fn() -> Vec<u8>),
}

/// Single source of truth for the `/proc/sys/**` leaf files carrick serves.
/// `lookup`, `readdir`, `open`, and `synthetic_file` all derive from this table
/// so directory enumeration can never disagree with what `open()` will serve.
/// Values match the Docker linux/arm64 oracle (proc_sys_*(5)); where carrick
/// owns the real behaviour (overcommit, fd/pipe ceilings) they reflect that.
const SYSCTL_TABLE: &[(&str, Sysctl)] = &[
    // kernel.*
    ("/proc/sys/kernel/ostype", Sysctl::Static(b"Linux\n")),
    ("/proc/sys/kernel/osrelease", Sysctl::Static(b"6.6.0-carrick\n")),
    ("/proc/sys/kernel/version", Sysctl::Static(b"#1 SMP PREEMPT_DYNAMIC\n")),
    ("/proc/sys/kernel/hostname", Sysctl::Static(b"carrick\n")),
    // Default 64-bit Linux pid ceiling. LTP (setpgid02) reads this to bound pid
    // scans; without it tst_test aborts with ENOENT.
    ("/proc/sys/kernel/pid_max", Sysctl::Static(b"4194304\n")),
    // Highest capability number carrick models — libcap/systemd/runc loop
    // 0..=cap_last_cap dropping bounding-set caps.
    ("/proc/sys/kernel/cap_last_cap", Sysctl::Static(b"40\n")),
    ("/proc/sys/kernel/threads-max", Sysctl::Static(b"127760\n")),
    ("/proc/sys/kernel/ngroups_max", Sysctl::Static(b"65536\n")),
    // carrick has no autogroup scheduler, so the honest value is 0.
    (
        "/proc/sys/kernel/sched_autogroup_enabled",
        Sysctl::Static(b"0\n"),
    ),
    ("/proc/sys/kernel/overflowuid", Sysctl::Static(b"65534\n")),
    ("/proc/sys/kernel/overflowgid", Sysctl::Static(b"65534\n")),
    (
        "/proc/sys/kernel/random/uuid",
        Sysctl::Dynamic(sysctl_random_uuid),
    ),
    (
        "/proc/sys/kernel/random/boot_id",
        Sysctl::Dynamic(sysctl_boot_id),
    ),
    // vm.* — carrick freely satisfies large anon mmaps, so "always overcommit"
    // (1) is the honest match; Redis warns loudly on anything else.
    ("/proc/sys/vm/overcommit_memory", Sysctl::Static(b"1\n")),
    // Elasticsearch hard-fails to boot if this is < 262144.
    ("/proc/sys/vm/max_map_count", Sysctl::Static(b"262144\n")),
    // Lowest address a process may mmap — matches carrick's null-guard.
    ("/proc/sys/vm/mmap_min_addr", Sysctl::Static(b"65536\n")),
    ("/proc/sys/vm/swappiness", Sysctl::Static(b"60\n")),
    // fs.* — file-max/nr_open match NOFILE_HARD (the RLIMIT_NOFILE ceiling
    // carrick enforces). file-nr is exactly THREE tab-separated ints.
    ("/proc/sys/fs/file-max", Sysctl::Static(b"1048576\n")),
    ("/proc/sys/fs/file-nr", Sysctl::Static(b"256\t0\t1048576\n")),
    ("/proc/sys/fs/nr_open", Sysctl::Static(b"1048576\n")),
    ("/proc/sys/fs/pipe-max-size", Sysctl::Static(b"1048576\n")),
    ("/proc/sys/fs/overflowuid", Sysctl::Static(b"65534\n")),
    ("/proc/sys/fs/overflowgid", Sysctl::Static(b"65534\n")),
    // fs/inotify/* — file-watchers (chokidar/webpack/vite/fsnotify) read these.
    (
        "/proc/sys/fs/inotify/max_user_watches",
        Sysctl::Static(b"1048576\n"),
    ),
    (
        "/proc/sys/fs/inotify/max_user_instances",
        Sysctl::Static(b"8192\n"),
    ),
    (
        "/proc/sys/fs/inotify/max_queued_events",
        Sysctl::Static(b"16384\n"),
    ),
    // fs/mqueue/* (mq_overview(7) defaults).
    ("/proc/sys/fs/mqueue/msg_max", Sysctl::Static(b"10\n")),
    ("/proc/sys/fs/mqueue/msgsize_max", Sysctl::Static(b"8192\n")),
    ("/proc/sys/fs/mqueue/queues_max", Sysctl::Static(b"256\n")),
    // net/core/* — listen backlog + socket buffer ceilings.
    ("/proc/sys/net/core/somaxconn", Sysctl::Static(b"4096\n")),
    ("/proc/sys/net/core/rmem_max", Sysctl::Static(b"212992\n")),
    ("/proc/sys/net/core/wmem_max", Sysctl::Static(b"212992\n")),
    // net/ipv4/* — ip_local_port_range is exactly TWO tab-separated ints;
    // tcp_rmem/tcp_wmem are exactly THREE (min default max).
    (
        "/proc/sys/net/ipv4/ip_local_port_range",
        Sysctl::Static(b"32768\t60999\n"),
    ),
    (
        "/proc/sys/net/ipv4/tcp_rmem",
        Sysctl::Static(b"4096\t131072\t6291456\n"),
    ),
    (
        "/proc/sys/net/ipv4/tcp_wmem",
        Sysctl::Static(b"4096\t16384\t4194304\n"),
    ),
    ("/proc/sys/net/ipv4/tcp_fin_timeout", Sysctl::Static(b"60\n")),
    (
        "/proc/sys/net/ipv4/tcp_keepalive_time",
        Sysctl::Static(b"7200\n"),
    ),
    ("/proc/sys/net/ipv4/tcp_syncookies", Sysctl::Static(b"1\n")),
];

/// The rendered bytes for a `/proc/sys/**` leaf, or `None` if `path` is not a
/// served sysctl file.
fn sysctl_value(path: &str) -> Option<Vec<u8>> {
    SYSCTL_TABLE.iter().find_map(|(p, v)| {
        (*p == path).then(|| match v {
            Sysctl::Static(b) => b.to_vec(),
            Sysctl::Dynamic(f) => f(),
        })
    })
}

/// True iff `path` is a `/proc/sys` directory (the root or any intermediate
/// component on the way to a leaf). Derived from the table so it can never
/// drift from what `readdir`/`open` will serve.
fn sysctl_is_dir(path: &str) -> bool {
    if path == "/proc/sys" {
        return true;
    }
    if !path.starts_with("/proc/sys/") {
        return false;
    }
    let prefix = format!("{path}/");
    SYSCTL_TABLE.iter().any(|(p, _)| p.starts_with(&prefix))
}

/// Immediate children of a `/proc/sys` directory: sub-directories and leaf
/// files derived from `SYSCTL_TABLE` by taking the next path component after
/// `path`. `None` if `path` is not a sysctl directory.
fn sysctl_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    if !sysctl_is_dir(path) {
        return None;
    }
    let prefix = format!("{path}/");
    let mut children: Vec<(String, EntryKind)> = Vec::new();
    for (p, _) in SYSCTL_TABLE {
        let Some(rest) = p.strip_prefix(&prefix) else {
            continue;
        };
        let (name, kind) = match rest.split_once('/') {
            Some((dir, _)) => (dir.to_string(), EntryKind::Directory),
            None => (rest.to_string(), EntryKind::File),
        };
        if !children.iter().any(|(n, _)| *n == name) {
            children.push((name, kind));
        }
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
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
    entries.extend(
        children
            .into_iter()
            .map(|(name, kind)| DirEnt { name, kind }),
    );
    Some(entries)
}

/// A numeric `/proc/<self-pid>/<rest>` is the same object as `/proc/self/<rest>`
/// (carrick is one guest process), whether the pid is the host pid or the
/// guest's ns-pid. Rewrite it so the literal `/proc/self/*` renderers (which
/// hold the live `SyntheticProcContext`) serve it too — keeping `ls /proc/<pid>`
/// consistent with what `open()` resolves for the self process.
fn normalize_self_pid_path(path: &str) -> Cow<'_, str> {
    if let Some(rest) = path.strip_prefix("/proc/")
        && let Some((pid, sub)) = rest.split_once('/')
        && !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
    {
        let n: u32 = pid.parse().unwrap_or(0);
        if n != 0 && (n == std::process::id() || n == crate::namespace::pid::self_ns_pid()) {
            return Cow::Owned(format!("/proc/self/{sub}"));
        }
    }
    Cow::Borrowed(path)
}

pub(crate) fn synthetic_file(path: &str, ctx: &SyntheticProcContext) -> Option<Vec<u8>> {
    let normalized = normalize_self_pid_path(path);
    let path = normalized.as_ref();
    match path {
        "/proc/cmdline" => Some(synthetic_proc_cmdline().to_vec()),
        "/proc/config.gz" => Some(synthetic_proc_config_gz()),
        "/proc/cpuinfo" => Some(synthetic_proc_cpuinfo()),
        "/proc/devices" => Some(synthetic_proc_devices().to_vec()),
        "/proc/diskstats" => Some(synthetic_proc_diskstats().to_vec()),
        "/proc/filesystems" => Some(synthetic_proc_filesystems().to_vec()),
        "/proc/loadavg" => Some(synthetic_proc_loadavg().to_vec()),
        "/proc/locks" => Some(Vec::new()),
        "/proc/meminfo" => Some(synthetic_proc_meminfo().to_vec()),
        "/proc/modules" => Some(Vec::new()),
        "/proc/mounts" => Some(synthetic_proc_mounts().to_vec()),
        "/proc/partitions" => Some(synthetic_proc_partitions().to_vec()),
        "/proc/stat" => Some(synthetic_proc_stat()),
        "/proc/swaps" => Some(synthetic_proc_swaps().to_vec()),
        "/proc/uptime" => Some(synthetic_proc_uptime().into_bytes()),
        "/proc/version" => Some(synthetic_proc_version().to_vec()),
        "/proc/vmstat" => Some(synthetic_proc_vmstat().to_vec()),
        "/proc/self/auxv" => Some(synthetic_proc_self_auxv().to_vec()),
        "/proc/self/autogroup" => Some(b"/autogroup-0 nice 0\n".to_vec()),
        "/proc/self/cgroup" => Some(b"0::/\n".to_vec()),
        "/proc/self/cmdline" => Some(synthetic_proc_self_cmdline(&ctx.argv, &ctx.executable_path)),
        "/proc/self/comm" => Some(synthetic_proc_self_comm(&ctx.executable_path).into_bytes()),
        "/proc/self/environ" => Some(synthetic_proc_self_environ(&ctx.environ)),
        "/proc/self/io" => Some(synthetic_proc_self_io().to_vec()),
        "/proc/self/limits" => Some(synthetic_proc_self_limits().to_vec()),
        // The audit loginuid/sessionid "unset" sentinel ((uint32)-1), no newline.
        "/proc/self/loginuid" | "/proc/self/sessionid" => Some(b"4294967295".to_vec()),
        "/proc/self/maps" => Some(synthetic_proc_maps(ctx).into_bytes()),
        "/proc/self/mountinfo" => Some(synthetic_proc_self_mountinfo().to_vec()),
        "/proc/self/mountstats" => Some(Vec::new()),
        // oom_score is volatile (0 is acceptable); the two adj knobs default 0.
        "/proc/self/oom_score" | "/proc/self/oom_score_adj" | "/proc/self/oom_adj" => {
            Some(b"0\n".to_vec())
        }
        // 8-digit hex personality flags (default ADDR/Linux = 0), no newline.
        "/proc/self/personality" => Some(b"00000000".to_vec()),
        "/proc/self/schedstat" => Some(b"0 0 1\n".to_vec()),
        "/proc/self/smaps" => Some(synthetic_proc_smaps(ctx).into_bytes()),
        "/proc/self/smaps_rollup" => Some(synthetic_proc_smaps_rollup(ctx).into_bytes()),
        "/proc/self/stat" => Some(synthetic_proc_self_stat(&ctx.executable_path).into_bytes()),
        "/proc/self/statm" => Some(synthetic_proc_self_statm()),
        "/proc/self/status" => Some(synthetic_proc_self_status(ctx).into_bytes()),
        // A running/on-CPU task: syscall reports "running", wchan 0 (no newline).
        "/proc/self/syscall" => Some(b"running\n".to_vec()),
        "/proc/self/timerslack_ns" => Some(b"50000\n".to_vec()),
        "/proc/self/wchan" => Some(b"0".to_vec()),
        // User-namespace map files (user_namespaces(7)). For the initial
        // identity namespace these read as `0 0 4294967295` / `allow`, matching
        // observed `docker run` (docs/namespaces-design.md §1.2, §4.3). Writable
        // — see ProcVfs::open + the write(2) handler.
        "/proc/self/uid_map" => {
            Some(crate::namespace::process::with_user(|ns| ns.uid_map_text()).into_bytes())
        }
        "/proc/self/gid_map" => {
            Some(crate::namespace::process::with_user(|ns| ns.gid_map_text()).into_bytes())
        }
        "/proc/self/setgroups" => Some(
            crate::namespace::process::with_user(|ns| ns.setgroups_text())
                .as_bytes()
                .to_vec(),
        ),
        _ => {
            if let Some(v) = sysctl_value(path) {
                return Some(v);
            }
            // /proc/net/<f>, plus the namespace-correct /proc/self/net/<f> and
            // /proc/<pid>/net/<f> aliases, share one renderer (proc_net(5)).
            if let Some(name) = proc_net_basename(path)
                && let Some(v) = synthetic_proc_net_file(name)
            {
                return Some(v);
            }
            let self_comm = process_short_name(&ctx.executable_path);
            parse_proc_pid_path(path)
                .and_then(|(pid, rest)| synthetic_proc_pid_file(pid, rest, &self_comm))
        }
    }
}

/// The `<f>` of a `/proc/net/<f>`, `/proc/self/net/<f>`, `/proc/thread-self/net/<f>`
/// or `/proc/<pid>/net/<f>` path — the namespace-correct net paths every tool
/// reaches all resolve to the same per-file renderer. `None` otherwise.
fn proc_net_basename(path: &str) -> Option<&str> {
    if let Some(name) = path.strip_prefix("/proc/net/") {
        return (!name.contains('/')).then_some(name);
    }
    let rest = path.strip_prefix("/proc/")?;
    let (pid, tail) = rest.split_once('/')?;
    if pid != "self" && pid != "thread-self" && !pid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let name = tail.strip_prefix("net/")?;
    (!name.contains('/')).then_some(name)
}

/// The `/proc/net/*` files carrick serves — listed by `readdir` so `ls /proc/net`
/// enumerates and `synthetic_proc_net_file` stays in sync with what's openable.
const PROC_NET_FILES: &[&str] = &[
    "arp",
    "dev",
    "dev_mcast",
    "if_inet6",
    "igmp",
    "igmp6",
    "ipv6_route",
    "netstat",
    "packet",
    "raw",
    "raw6",
    "route",
    "snmp",
    "snmp6",
    "sockstat",
    "sockstat6",
    "tcp",
    "tcp6",
    "udp",
    "udp6",
    "unix",
];

/// True iff `path` is a `/proc/net` directory: the bare `/proc/net` or the
/// namespace-correct `/proc/self/net`, `/proc/thread-self/net`, `/proc/<pid>/net`.
fn proc_net_is_dir(path: &str) -> bool {
    if path == "/proc/net" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    let Some(pid) = rest.strip_suffix("/net") else {
        return false;
    };
    pid == "self" || pid == "thread-self" || (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
}

/// Directory listing for a `/proc/net` directory, else `None`.
fn proc_net_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    if !proc_net_is_dir(path) {
        return None;
    }
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
    entries.extend(PROC_NET_FILES.iter().map(|f| DirEnt {
        name: (*f).to_string(),
        kind: EntryKind::File,
    }));
    Some(entries)
}

/// For a `/proc/{self,thread-self,curproc,this,<pid>}/<rest>` path, the `<rest>`
/// after the process component. The magic process aliases and any numeric pid
/// all resolve here so `exe`/`cwd`/`root`/`ns/*` work uniformly.
fn proc_pid_subpath(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, sub) = rest.split_once('/')?;
    let ok = matches!(pid, "self" | "thread-self" | "curproc" | "this")
        || (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()));
    ok.then_some(sub)
}

/// `/proc/<pid>/ns/<type>` namespace symlinks. Each readlinks to `<type>:[<inode>]`
/// (namespaces(7)); the inodes are the standard initial-namespace numbers so a
/// same-namespace equality check (readlink ns/pid == another proc's ns/pid)
/// holds across the single guest carrick models. `*_for_children` mirror their
/// base type's inode.
const PROC_NS_TYPES: &[(&str, u64)] = &[
    ("cgroup", 4026531835),
    ("ipc", 4026531839),
    ("mnt", 4026531840),
    ("net", 4026531992),
    ("pid", 4026531836),
    ("pid_for_children", 4026531836),
    ("time", 4026531834),
    ("time_for_children", 4026531834),
    ("user", 4026531837),
    ("uts", 4026531838),
];

/// True iff `path` is a `/proc/<pid>/ns` directory (self/thread-self/… aliases).
fn proc_ns_is_dir(path: &str) -> bool {
    proc_pid_subpath(path) == Some("ns")
}

/// Directory listing for a `/proc/<pid>/ns` directory (one symlink per ns type).
fn proc_ns_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    if !proc_ns_is_dir(path) {
        return None;
    }
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
    entries.extend(PROC_NS_TYPES.iter().map(|(name, _)| DirEnt {
        name: (*name).to_string(),
        kind: EntryKind::Symlink,
    }));
    Some(entries)
}

/// The `<type>:[<inode>]` readlink target for a `/proc/<pid>/ns/<type>` path.
fn proc_ns_link_target(path: &str) -> Option<String> {
    let t = proc_pid_subpath(path)?.strip_prefix("ns/")?;
    PROC_NS_TYPES
        .iter()
        .find(|(name, _)| *name == t)
        .map(|(name, ino)| format!("{name}:[{ino}]"))
}

/// If `path` is a *leaf* `/proc` magic symlink, its readlink-target length (for
/// the `st_size` an lstat reports). Drives `lookup_nofollow` reporting
/// `S_IFLNK` for the per-pid `exe`/`cwd`/`root` and `ns/<type>` links.
///
/// Deliberately does NOT include the bare `/proc/self`, `/proc/thread-self` or
/// `/proc/net` links: those must stay *traversable directories* so a path walk
/// into `/proc/self/<file>` descends rather than trying to follow a symlink to
/// a per-pid directory carrick doesn't fully serve (which would ENOTDIR every
/// `/proc/self/*` open — the intermediate-component check at
/// `dispatch/fs.rs` `validate_intermediate_dirs`). `readlink` still resolves
/// them (a readlink doesn't require the target to lstat as a symlink), so
/// `readlink /proc/self` → the pid and `readlink /proc/net` → self/net work.
fn proc_magic_symlink_size(path: &str) -> Option<u64> {
    let rest = proc_pid_subpath(path)?;
    if matches!(rest, "exe" | "cwd" | "root") {
        return Some(0);
    }
    proc_ns_link_target(path).map(|t| t.len() as u64)
}

/// The `<tgid>/task/<tid>` readlink target for `/proc/thread-self`. ProcVfs has
/// no per-thread context, so this is the single-threaded approximation
/// (tid == tgid); the dispatcher overrides it with the live tid when threaded.
fn proc_thread_self_target() -> String {
    let p = crate::namespace::pid::self_ns_pid();
    format!("{p}/task/{p}")
}

/// Metadata for a `/proc` magic symlink: `S_IFLNK` mode 0o777, `size` = target
/// length (what an lstat reports as `st_size`).
fn proc_symlink_metadata(size: u64) -> Metadata {
    Metadata {
        kind: EntryKind::Symlink,
        mode: 0o777,
        size,
        uid: 0,
        gid: 0,
        mtime_secs: 0,
        mtime_nanos: 0,
    }
}

/// Host interfaces mapped to Linux-plausible names: `lo0`→`lo` (always present),
/// the first ethernet-like uplink (`enN`)→`eth0`; Darwin-only pseudo-interfaces
/// (awdl/llw/utun/bridge/gif/stf/…) are dropped so a guest never sees macOS-isms
/// or tries `if_nametoindex("en0")`. Feeds dev/igmp/igmp6/dev_mcast so the iface
/// NAME correlates across all of /proc/net.
fn linux_interfaces() -> Vec<(u32, String, bool, bool)> {
    let mut out: Vec<(u32, String, bool, bool)> = Vec::new();
    let mut have_eth = false;
    for (_idx, name, v4, v6) in host_mc_interfaces() {
        if name == "lo0" || name == "lo" {
            if !out.iter().any(|(_, n, _, _)| n == "lo") {
                // Loopback always carries both IPv4 (127.0.0.1) and IPv6 (::1).
                out.push((1, "lo".to_owned(), true, true));
            }
        } else if name.starts_with("en") && !have_eth {
            have_eth = true;
            out.push((2, "eth0".to_owned(), v4, v6));
        }
    }
    if !out.iter().any(|(_, n, _, _)| n == "lo") {
        out.insert(0, (1, "lo".to_owned(), true, true));
    }
    out
}

/// Render `/proc/net/<name>` (and its `self/net` / `<pid>/net` aliases). carrick
/// is host-socket-passthrough, so the socket tables (tcp/udp/unix/…) are emitted
/// header-only — the high-fidelity idle case; a present, correctly-headered file
/// beats ENOENT for ss/netstat/lsof/node_exporter. Counters tables (snmp/netstat/
/// sockstat) carry the exact LABELS parsers key on, with zero values.
fn synthetic_proc_net_file(name: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = match name {
        "dev" => return Some(synthetic_proc_net_dev()),
        "igmp" => return Some(synthetic_proc_net_igmp()),
        "igmp6" => return Some(synthetic_proc_net_igmp6()),
        "dev_mcast" => return Some(synthetic_proc_net_dev_mcast()),
        "if_inet6" => synthetic_proc_net_if_inet6(),
        "tcp" => b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_vec(),
        "tcp6" => b"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".to_vec(),
        "udp" => b"   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "udp6" => b"   sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "raw" => b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "raw6" => b"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n".to_vec(),
        "unix" => b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec(),
        "packet" => b"sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n".to_vec(),
        "arp" => b"IP address       HW type     Flags       HW address            Mask     Device\n".to_vec(),
        "route" => synthetic_proc_net_route(),
        "ipv6_route" => synthetic_proc_net_ipv6_route(),
        "snmp" => synthetic_proc_net_snmp(),
        "snmp6" => synthetic_proc_net_snmp6(),
        "netstat" => synthetic_proc_net_netstat(),
        "sockstat" => b"sockets: used 0\nTCP: inuse 0 orphan 0 tw 0 alloc 0 mem 0\nUDP: inuse 0 mem 0\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n".to_vec(),
        "sockstat6" => b"TCP6: inuse 0\nUDP6: inuse 0\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n".to_vec(),
        _ => return None,
    };
    Some(bytes)
}

/// `/proc/net/if_inet6`: one row per IPv6 interface (proc_net(5)). Loopback's
/// `::1/128` plus a row per mapped uplink; glibc's `__check_pf` reads this.
fn synthetic_proc_net_if_inet6() -> Vec<u8> {
    let mut s = String::new();
    for (idx, name, _v4, v6) in linux_interfaces() {
        if name == "lo" {
            s.push_str(&format!(
                "00000000000000000000000000000001 {idx:02x} 80 10 80 {name:>9}\n"
            ));
        } else if v6 {
            s.push_str(&format!(
                "fe800000000000000000000000000001 {idx:02x} 40 20 80 {name:>9}\n"
            ));
        }
    }
    s.into_bytes()
}

/// `/proc/net/dev`: the two verbatim header lines (proc_net(5) quotes them
/// exactly) then one all-zero-counter row per Linux-mapped interface.
fn synthetic_proc_net_dev() -> Vec<u8> {
    let mut s = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for (_idx, name, _v4, _v6) in linux_interfaces() {
        s.push_str(&format!(
            "{name:>6}: 0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n"
        ));
    }
    s.into_bytes()
}

/// `/proc/net/dev_mcast`: the standard all-nodes multicast MAC memberships per
/// interface (333300000001 = IPv6 all-nodes, 01005e000001 = IPv4 all-hosts).
fn synthetic_proc_net_dev_mcast() -> Vec<u8> {
    let mut s = String::new();
    for (idx, name, v4, v6) in linux_interfaces() {
        if v6 {
            s.push_str(&format!("{idx:<4} {name:<15} 1     0     333300000001\n"));
        }
        if v4 {
            s.push_str(&format!("{idx:<4} {name:<15} 1     0     01005e000001\n"));
        }
    }
    s.into_bytes()
}

/// `/proc/net/route`: header + an on-link default route via the primary uplink
/// and a loopback route. Addresses are little-endian hex (proc_net(5)).
fn synthetic_proc_net_route() -> Vec<u8> {
    let mut s = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    let eth = linux_interfaces()
        .into_iter()
        .find(|(_, n, _, _)| n == "eth0")
        .map(|(_, n, _, _)| n);
    if let Some(eth) = eth {
        // Default route, on-link (gateway 0.0.0.0), mask 0.0.0.0.
        s.push_str(&format!(
            "{eth}\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
        ));
    }
    s.into_bytes()
}

/// `/proc/net/ipv6_route`: loopback rows in the fixed 32-hex-digit layout, no
/// header (proc_net(5)). `::1/128` and `::/0` on lo.
fn synthetic_proc_net_ipv6_route() -> Vec<u8> {
    b"00000000000000000000000000000001 80 00000000000000000000000000000000 00 \
00000000000000000000000000000000 00000000 00000001 00000000 00000001 lo\n"
        .to_vec()
}

/// `/proc/net/snmp`: the paired `Label: names` / `Label: values` lines per
/// protocol group. Static-but-correctly-labelled (cumulative counters), which
/// is what node_exporter/SNMP collectors key on.
fn synthetic_proc_net_snmp() -> Vec<u8> {
    b"Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates\n\
Ip: 1 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
IcmpMsg: InType3 OutType3\n\
IcmpMsg: 0 0\n\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
Udp: 0 0 0 0 0 0 0 0\n\
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
UdpLite: 0 0 0 0 0 0 0 0\n".to_vec()
}

/// `/proc/net/snmp6`: flat `Label\tvalue` IPv6 counter list (zeros).
fn synthetic_proc_net_snmp6() -> Vec<u8> {
    b"Ip6InReceives\t0\n\
Ip6InHdrErrors\t0\n\
Ip6InTooBigErrors\t0\n\
Ip6InNoRoutes\t0\n\
Ip6InDelivers\t0\n\
Ip6OutRequests\t0\n\
Ip6OutNoRoutes\t0\n\
Icmp6InMsgs\t0\n\
Icmp6OutMsgs\t0\n\
Udp6InDatagrams\t0\n\
Udp6OutDatagrams\t0\n".to_vec()
}

/// `/proc/net/netstat`: the `TcpExt:`/`IpExt:` label line + matching zero-value
/// line. Read positionally-by-name, so the label set matters, values can be 0.
fn synthetic_proc_net_netstat() -> Vec<u8> {
    b"TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPHPHits TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPSlowStartRetrans TCPTimeouts\n\
TcpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts ReasmOverlaps\n\
IpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n".to_vec()
}

/// `(index, name, has_ipv4, has_ipv6)` for each host interface, via getifaddrs.
/// Used to synthesize `/proc/net/igmp[6]` so a guest's `Interface.MulticastAddrs`
/// reports the standard multicast groups every Linux interface joins.
#[cfg(target_os = "macos")]
fn host_mc_interfaces() -> Vec<(u32, String, bool, bool)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, (u32, bool, bool)> = BTreeMap::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Vec::new();
    }
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let idx = {
            let c = std::ffi::CString::new(name.clone()).unwrap_or_default();
            unsafe { libc::if_nametoindex(c.as_ptr()) }
        };
        let entry = map.entry(name).or_insert((idx, false, false));
        if idx != 0 {
            entry.0 = idx;
        }
        if !ifa.ifa_addr.is_null() {
            match unsafe { (*ifa.ifa_addr).sa_family } as i32 {
                libc::AF_INET => entry.1 = true,
                libc::AF_INET6 => entry.2 = true,
                _ => {}
            }
        }
    }
    unsafe { libc::freeifaddrs(head) };
    map.into_iter()
        .map(|(name, (idx, v4, v6))| (idx, name, v4, v6))
        .collect()
}
#[cfg(not(target_os = "macos"))]
fn host_mc_interfaces() -> Vec<(u32, String, bool, bool)> {
    vec![(1, "lo".to_owned(), true, true)]
}

/// `/proc/net/igmp`: one block per IPv4 interface listing the all-hosts group
/// (224.0.0.1), matching the format Go's `parseProcNetIGMP` reads (the group is
/// the address in NATIVE/little-endian hex).
fn synthetic_proc_net_igmp() -> Vec<u8> {
    let mut s = String::from("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    for (idx, name, v4, _v6) in linux_interfaces() {
        if !v4 {
            continue;
        }
        s.push_str(&format!("{idx}\t{name:<10}:     1      V3\n"));
        // 224.0.0.1 = 0xE0000001; native (LE) byte order -> "010000E0".
        s.push_str("\t\t\t\t010000E0     1 0:00000000\t\t0\n");
    }
    s.into_bytes()
}

/// `/proc/net/igmp6`: the all-nodes link-local (ff02::1) and interface-local
/// (ff01::1) groups per IPv6 interface — the address is straight network-order
/// hex, as Go's `parseProcNetIGMP6` reads.
fn synthetic_proc_net_igmp6() -> Vec<u8> {
    let mut s = String::new();
    for (idx, name, _v4, v6) in linux_interfaces() {
        if !v6 {
            continue;
        }
        s.push_str(&format!(
            "{idx:<4} {name:<16}ff020000000000000000000000000001     1 0000000C 0\n"
        ));
        s.push_str(&format!(
            "{idx:<4} {name:<16}ff010000000000000000000000000001     1 00000008 0\n"
        ));
    }
    s.into_bytes()
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

/// Translate a guest-supplied (namespace) pid to a HOST pid; identity when no
/// PID namespace is active. `None` for an ns-pid that maps to no live process.
/// The synthetic `/proc/<pid>` machinery validates against HOST tids/pids
/// (`current_thread_states`/`is_guest_process`), so a numeric `/proc/<ns-pid>`
/// must be translated before it can be matched (without this, every
/// `/proc/<pid>` under a PID namespace missed → ENOSYS).
fn ns_pid_to_host(ns_pid: u32) -> Option<u32> {
    if crate::namespace::pid::enabled() {
        crate::namespace::pid::ns_to_host_or_self(ns_pid)
    } else {
        Some(ns_pid)
    }
}

/// The backing HOST pid for a `/proc/<pid>` DIRECTORY path (the pid component
/// only, no sub-path), or `None` if the path isn't a numeric process directory
/// or the pid isn't a live process we expose. Used both to gate the directory
/// open and to let `pidfd_send_signal` treat a `/proc/<pid>` directory fd as a
/// pidfd (Linux allows a `/proc/<pid>` dir fd anywhere a pidfd is expected).
pub(crate) fn proc_pid_dir_host_pid(path: &str) -> Option<u32> {
    let p = path.strip_suffix('/').unwrap_or(path);
    let comp = p.strip_prefix("/proc/")?;
    if comp.contains('/') {
        return None; // a sub-path (/proc/<pid>/task, …), not the pid dir itself
    }
    // `self`/`thread-self` resolve to the calling process (the same mapping
    // parse_proc_pid_path uses for sub-path file reads), so the bare /proc/self
    // directory is openable/stat-able/scandir-able — not just /proc/self/<file>.
    let host_pid = if comp == "self" || comp == "thread-self" {
        std::process::id()
    } else {
        ns_pid_to_host(comp.parse().ok()?)?
    };
    synthetic_task_dir(host_pid)?; // gate: a live process (own thread or guest)
    Some(host_pid)
}

/// `(., .., <tid>...)` entries for a `/proc/<pid>/task/` path.
fn proc_task_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    let p = path.strip_suffix('/').unwrap_or(path);
    let ns_pid: u32 = p
        .strip_prefix("/proc/")?
        .strip_suffix("/task")?
        .parse()
        .ok()?;
    let tids = synthetic_task_dir(ns_pid_to_host(ns_pid)?)?;
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

/// Per-process files Carrick exposes under a FOREIGN `/proc/<pid>/` (matching
/// what `synthetic_proc_pid_file` serves for another guest process).
const PROC_PID_FILES: &[&str] = &["cmdline", "comm", "stat", "status"];

/// The richer file set under the SELF process dir — every `/proc/self/<f>`
/// flat file `synthetic_file` actually serves — so `ls /proc/self` enumerates
/// what `open()` can resolve (proc(5)), not just the foreign 4-file subset.
const PROC_SELF_FILES: &[&str] = &[
    "auxv",
    "autogroup",
    "cgroup",
    "cmdline",
    "comm",
    "environ",
    "gid_map",
    "io",
    "limits",
    "loginuid",
    "maps",
    "mountinfo",
    "mountstats",
    "oom_adj",
    "oom_score",
    "oom_score_adj",
    "personality",
    "schedstat",
    "sessionid",
    "setgroups",
    "smaps",
    "smaps_rollup",
    "stat",
    "statm",
    "status",
    "syscall",
    "timerslack_ns",
    "uid_map",
    "wchan",
];

/// Directory listing for `/proc/<pid>` when `pid` is a known process (an own
/// guest thread or a guest process), else `None`. The SELF dir is populated
/// with the full set of files/symlinks/sub-dirs carrick serves; a foreign pid
/// gets the subset its synthetic renderer can actually answer.
fn proc_pid_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    // Gate on a numeric /proc/<pid> for a live process (ns-pid → host pid).
    let host_pid = proc_pid_dir_host_pid(path)?;
    let is_self = host_pid == std::process::id();
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "task".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    let files = if is_self {
        // Sub-directories and magic symlinks only the self dir fully serves.
        for dir in ["ns", "net"] {
            entries.push(DirEnt {
                name: dir.to_string(),
                kind: EntryKind::Directory,
            });
        }
        for link in ["exe", "cwd", "root"] {
            entries.push(DirEnt {
                name: link.to_string(),
                kind: EntryKind::Symlink,
            });
        }
        PROC_SELF_FILES
    } else {
        PROC_PID_FILES
    };
    entries.extend(files.iter().map(|f| DirEnt {
        name: (*f).to_string(),
        kind: EntryKind::File,
    }));
    Some(entries)
}

/// Guest process pids (this process + its guest descendants) for enumerating
/// `/proc`. libproc's all-pids list filtered by `is_guest_process`.
#[cfg(target_os = "macos")]
fn enumerate_guest_pids() -> Vec<u32> {
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; count as usize + 16];
    let cap = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), cap) };
    if got <= 0 {
        return Vec::new();
    }
    pids.truncate(got as usize);
    pids.into_iter()
        .filter(|&p| p > 0 && crate::host_proc::is_guest_process(p as u32))
        .map(|p| p as u32)
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn enumerate_guest_pids() -> Vec<u32> {
    Vec::new()
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
        if path == "/proc"
            || sysctl_is_dir(path)
            || proc_net_is_dir(path)
            || proc_ns_is_dir(path)
            || proc_task_dir_entries(path).is_some()
            || proc_pid_dir_entries(path).is_some()
        {
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
        // Magic symlinks (exe/cwd/root/ns/<type>, and the bare process aliases
        // when not caught as directories above). A follow-stat lands here too,
        // so faccessat(F_OK)/`test -e` see the link exist.
        if let Some(size) = proc_magic_symlink_size(path) {
            return Ok(proc_symlink_metadata(size));
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

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        // lstat must report the magic symlinks as `S_IFLNK` BEFORE the
        // directory interpretation (e.g. `/proc/self` and `/proc/net` are
        // symlinks to lstat, directories only when followed).
        if let Some(size) = proc_magic_symlink_size(path) {
            return Ok(proc_symlink_metadata(size));
        }
        self.lookup(path)
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        // Context-free magic links (the dispatcher handles exe/cwd/root, which
        // need live state). `/proc/self` → the caller's ns-pid; `/proc/net` →
        // the namespace-correct self/net; `/proc/<pid>/ns/<t>` → `<t>:[<ino>]`.
        match path {
            "/proc/self" | "/proc/curproc" | "/proc/this" => Ok(PathBuf::from(
                crate::namespace::pid::self_ns_pid().to_string(),
            )),
            "/proc/thread-self" => Ok(PathBuf::from(proc_thread_self_target())),
            "/proc/net" => Ok(PathBuf::from("self/net")),
            _ => proc_ns_link_target(path)
                .map(PathBuf::from)
                .ok_or(crate::linux_abi::LINUX_EINVAL),
        }
    }

    fn readdir(&self, path: &str) -> Result<Vec<super::DirEnt>, VfsError> {
        if path == "/proc" {
            // Top-level: `.`/`..`, `self`, a representative set of synthetic
            // files, and every guest process pid (so `ps`/`ls /proc` enumerate).
            // `self`/`thread-self` readlink to the caller's pid dir, but carrick
            // models them as traversable directories (so `/proc/self/<file>`
            // resolves without following into an unserved per-pid tree); report
            // them as directories for getdents consistency with lstat.
            let mut entries = vec![
                DirEnt {
                    name: ".".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "..".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "self".to_string(),
                    kind: EntryKind::Directory,
                },
                DirEnt {
                    name: "thread-self".to_string(),
                    kind: EntryKind::Directory,
                },
            ];
            // Every top-level synthetic file carrick actually serves, so
            // `ls /proc` is consistent with what open() resolves (proc(5)).
            for name in [
                "cmdline",
                "config.gz",
                "cpuinfo",
                "devices",
                "diskstats",
                "filesystems",
                "loadavg",
                "locks",
                "meminfo",
                "modules",
                "mounts",
                "partitions",
                "stat",
                "swaps",
                "uptime",
                "version",
                "vmstat",
            ] {
                entries.push(DirEnt {
                    name: name.to_string(),
                    kind: EntryKind::File,
                });
            }
            // `/proc/sys` and `/proc/net` are both directories here (net readlinks
            // to self/net but is served as a traversable dir).
            entries.push(DirEnt {
                name: "sys".to_string(),
                kind: EntryKind::Directory,
            });
            entries.push(DirEnt {
                name: "net".to_string(),
                kind: EntryKind::Directory,
            });
            // Enumerated host pids must be shown as the NAMESPACE pids the guest
            // sees (what getpid()/$!/status report), or a guest can't correlate
            // `ls /proc` with its own pids. Identity when no PID namespace is
            // active; drop host pids that map to no ns-pid (host_to_ns → 0).
            for host_pid in enumerate_guest_pids() {
                let ns_pid = crate::namespace::pid::host_to_ns_or_self(host_pid);
                if ns_pid == 0 {
                    continue;
                }
                entries.push(DirEnt {
                    name: ns_pid.to_string(),
                    kind: EntryKind::Directory,
                });
            }
            return Ok(entries);
        }
        if let Some(entries) = sysctl_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_net_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_ns_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_task_dir_entries(path) {
            return Ok(entries);
        }
        if let Some(entries) = proc_pid_dir_entries(path) {
            return Ok(entries);
        }
        Err(LINUX_ENOTDIR)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        // Opening the /proc directory itself: serve our synthetic listing
        // (`.`/`..`, `self`, the representative top-level files, and every
        // guest process pid) so `getdents64` / `ls /proc` and `ps` enumerate.
        // Without this branch the open falls through to the (empty) rootfs
        // `/proc` directory and `readdir` is never reached. Mirrors `DevVfs`.
        if path == "/proc" {
            let entries = self.readdir("/proc").unwrap_or_default();
            return Ok(VfsHandle::Directory {
                path: "/proc".to_string(),
                entries,
                status_flags: 0,
            });
        }
        if let Some(entries) = sysctl_dir_entries(path)
            .or_else(|| proc_net_dir_entries(path))
            .or_else(|| proc_ns_dir_entries(path))
            .or_else(|| proc_task_dir_entries(path))
            .or_else(|| proc_pid_dir_entries(path))
        {
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags: 0,
            });
        }
        let synth_ctx = SyntheticProcContext {
            executable_path: ctx.executable_path.unwrap_or("").to_owned(),
            argv: ctx.argv.unwrap_or(&[]).to_vec(),
            environ: ctx.environ.unwrap_or(&[]).to_vec(),
            address_space_regions: ctx.address_space_regions.map(|regions| regions.to_vec()),
            brk_current: ctx.brk_current,
            mmap_next: ctx.mmap_next,
            sig_ignored: ctx.sig_ignored,
            sig_caught: ctx.sig_caught,
            sig_shdpnd: ctx.sig_shdpnd,
        };
        let Some(contents) = synthetic_file(path, &synth_ctx) else {
            return Err(crate::linux_abi::LINUX_ENOSYS);
        };
        // The user-namespace map files and the rw tunables (oom_score_adj/…)
        // are writable; the dispatcher routes write(2) on their SyntheticFile to
        // the appropriate handler. All other /proc files stay read-only.
        if flags.write && !is_userns_map_path(path) && !is_writable_tunable_path(path) {
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
        mmap_end = LINUX_MMAP_BASE + crate::memory::mmap_arena_size(),
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
        // Real Linux /proc/self/maps reports page-aligned VMA bounds. Some
        // consumers (Apple Rosetta's VM tracker) assert on this. Round to 16 KiB
        // (carrick's HVF page; also satisfies a 4 KiB check) — start down, end up.
        const PAGE: u64 = 0x4000;
        let start = start & !(PAGE - 1);
        let end = end.div_ceil(PAGE) * PAGE;
        out.push_str(&format!(
            "{start:016x}-{end:016x} {r}{w}{x}p 00000000 00:00 0                          {label}\n",
        ));
    }
    out
}

fn label_for_region(region: &ProcMapsEntry, executable_path: &str) -> (u64, u64, String) {
    let mut start = region.start;
    let end = region.end;
    let label = if start == LINUX_HEAP_BASE {
        "[heap]".to_owned()
    } else if start == LINUX_MMAP_BASE {
        "[carrick-mmap]".to_owned()
    } else if start == LINUX_STACK_TOP.saturating_sub(LINUX_STACK_SIZE) {
        // Report the [stack] VMA as the RLIMIT_STACK extent (8 MiB below the top).
        // glibc's pthread_getattr_np derives the main-thread C-stack bounds from
        // this line and runtimes (CPython) calibrate their recursion guard to it,
        // so it must equal the reported RLIMIT_STACK. Today LINUX_STACK_SIZE ==
        // LINUX_RLIMIT_STACK_SOFT so this is a no-op, but it keeps the [stack] VMA
        // pinned to the reported limit should we ever back extra guard-page slack
        // (LINUX_STACK_SIZE > LINUX_RLIMIT_STACK_SOFT) below it.
        start = LINUX_STACK_TOP.saturating_sub(LINUX_RLIMIT_STACK_SOFT);
        "[stack]".to_owned()
    } else if start == LINUX_EL0_TRAMPOLINE_BASE {
        "[carrick-trampoline]".to_owned()
    } else if start == LINUX_SIGRETURN_TRAMPOLINE_BASE {
        "[carrick-sigreturn]".to_owned()
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
    // One "processor" block per Linux-visible logical CPU so the count agrees with
    // sched_getaffinity, /proc/stat and /sys/.../cpu/online. Go/nproc count
    // CPUs via sched_getaffinity, but lscpu and some runtimes parse this.
    let ncpu = crate::host_facts::logical_cpu_count();
    let mut out = String::new();
    for cpu in 0..ncpu {
        // NOTE: the kernel emits `CPU architecture: 8` with NO tab before the
        // colon (unlike the other rows); some strict parsers split on `: `.
        out.push_str(&format!(
            "processor\t: {cpu}\n\
BogoMIPS\t: 48.00\n\
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n\
CPU implementer\t: 0x61\n\
CPU architecture: 8\n\
CPU variant\t: 0x0\n\
CPU part\t: 0x000\n\
CPU revision\t: 0\n\
\n"
        ));
    }
    out.into_bytes()
}

fn synthetic_proc_version() -> &'static [u8] {
    b"Linux version 6.6.0-carrick (carrick@bootstrap) (rustc) #1 SMP PREEMPT_DYNAMIC\n"
}

fn synthetic_proc_loadavg() -> &'static [u8] {
    b"0.00 0.00 0.00 1/1 1\n"
}

fn synthetic_proc_uptime() -> String {
    // Field 1 is seconds since (guest) boot; field 2 is cumulative idle time
    // across all CPUs (>= field 1 on a multi-CPU box). Both 2-dp floats. The
    // old code emitted epoch-seconds here, yielding a ~56-year "uptime".
    let up = boot_instant().elapsed().as_secs_f64();
    let idle = up * crate::host_facts::logical_cpu_count().max(1) as f64;
    format!("{up:.2} {idle:.2}\n")
}

/// Boot time in seconds since the Epoch, for `/proc/stat`'s `btime` line:
/// now - uptime. Non-zero so `start_epoch = btime + starttime/HZ` math works.
fn boot_epoch_secs() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(boot_instant().elapsed().as_secs())
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
Active(anon):          0 kB\n\
Inactive(anon):        0 kB\n\
Active(file):          0 kB\n\
Inactive(file):        0 kB\n\
Unevictable:           0 kB\n\
Mlocked:               0 kB\n\
SwapTotal:             0 kB\n\
SwapFree:              0 kB\n\
Dirty:                 0 kB\n\
Writeback:             0 kB\n\
AnonPages:             0 kB\n\
Mapped:                0 kB\n\
Shmem:                 0 kB\n\
KReclaimable:          0 kB\n\
Slab:                  0 kB\n\
SReclaimable:          0 kB\n\
SUnreclaim:            0 kB\n\
KernelStack:           0 kB\n\
PageTables:            0 kB\n\
SecPageTables:         0 kB\n\
NFS_Unstable:          0 kB\n\
Bounce:                0 kB\n\
WritebackTmp:          0 kB\n\
CommitLimit:    16777216 kB\n\
Committed_AS:          0 kB\n\
VmallocTotal:   17179869184 kB\n\
VmallocUsed:           0 kB\n\
VmallocChunk:          0 kB\n\
Percpu:                0 kB\n\
AnonHugePages:         0 kB\n\
ShmemHugePages:        0 kB\n\
ShmemPmdMapped:        0 kB\n\
FileHugePages:         0 kB\n\
FilePmdMapped:         0 kB\n\
HugePages_Total:       0\n\
HugePages_Free:        0\n\
HugePages_Rsvd:        0\n\
HugePages_Surp:        0\n\
Hugepagesize:       2048 kB\n\
Hugetlb:               0 kB\n"
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
    out.push_str(&format!(
        "intr 0\n\
ctxt 0\n\
btime {btime}\n\
processes 1\n\
procs_running 1\n\
procs_blocked 0\n\
softirq 0\n",
        btime = boot_epoch_secs(),
    ));
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

/// The guest's committed virtual size in kB for `/proc/self/status` VmSize.
/// Sums the guest's own VMAs (clamping the heap to the current break and the
/// mmap arena to its used high-water mark, exactly as `/proc/self/maps` does)
/// so the 512 GiB reserved mmap window never leaks into the reported size.
/// Falls back to the host virtual size minus the reserved arena when VMA info
/// isn't available (the default context used for a size-only stat).
fn guest_committed_vm_kb(ctx: &SyntheticProcContext, host_virtual_bytes: u64) -> u64 {
    if let Some(regions) = ctx.address_space_regions.as_deref() {
        let mut total = 0u64;
        for r in regions {
            let mut end = r.end;
            if r.start == LINUX_HEAP_BASE && ctx.brk_current > r.start && ctx.brk_current <= r.end {
                end = ctx.brk_current;
            } else if r.start == LINUX_MMAP_BASE && ctx.mmap_next > r.start && ctx.mmap_next <= r.end
            {
                end = ctx.mmap_next;
            }
            total = total.saturating_add(end.saturating_sub(r.start));
        }
        return total / 1024;
    }
    let arena = crate::memory::mmap_arena_size();
    host_virtual_bytes.saturating_sub(arena) / 1024
}

fn synthetic_proc_self_status(ctx: &SyntheticProcContext) -> String {
    let comm = process_short_name(&ctx.executable_path);
    let sigign_hex = ctx.sig_ignored;
    let sigcgt_hex = ctx.sig_caught;
    let shdpnd_hex = ctx.sig_shdpnd;
    // Live thread count for the `Threads:` line — CPython reads this to decide
    // whether os.fork() must emit the multi-threaded-fork DeprecationWarning
    // (test_threading.test_*_after_fork). Was hardcoded 1, so a guest with live
    // worker threads looked single-threaded and the warning never fired.
    let nthreads = crate::thread::current_thread_states().len().max(1);
    let ncpu = crate::host_facts::logical_cpu_count();
    let cpus_hex = cpus_allowed_hex(ncpu);
    let cpus_list = cpus_allowed_list(ncpu);
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    // VmSize must reflect the guest's committed virtual size, NOT carrick's host
    // virtual size — which includes the 512 GiB sparse mmap window and made the
    // guest look like a ~521 GB process (tripping RSS/VSZ sanity + OOM
    // heuristics). Derive it from the guest's own VMAs when known (clamping the
    // heap to brk and the mmap arena to its used high-water mark, like
    // /proc/self/maps does); else subtract the reserved arena from the host size.
    let vsize_kb = guest_committed_vm_kb(ctx, host.virtual_bytes);
    let rss_kb = host.resident_bytes / 1024;
    let peak_kb = vsize_kb.max(host.maxrss_bytes / 1024);
    let hwm_kb = host.maxrss_bytes / 1024;
    // Pid/Tgid must match what getpid()/gettid() return — in a PID namespace
    // that is the ns-local pid (1 for the container init), not the host pid;
    // identity otherwise. LTP gettid01 reads "Pid:" and asserts it equals
    // getpid(). A single-threaded process has Pid == Tgid.
    let pid = crate::namespace::pid::self_ns_pid();
    // PPid is the ns-translated parent: 0 for the init, the parent's ns-pid for
    // others (was hardcoded 0, which diverged from Docker for non-init members).
    // Preserve the historical `PPid: 0` for non-namespaced runs (run-elf) so
    // that path is unchanged. The kernel's NStgid/NSpid/NSpgid/NSsid quartet is
    // intentionally omitted — NSpgid/NSsid need pgid/sid translation that stays
    // host-level in Phase 2, so a partial quartet would diverge worse than its
    // absence (§5.3, §6.6).
    let ppid = if crate::namespace::pid::enabled() {
        crate::namespace::pid::self_ns_ppid()
    } else {
        0
    };
    // Capabilities: report the modeled set (Docker default 00000000a80425fb,
    // or a full set inside a freshly-created user namespace), NOT the all-zero
    // set — capability-probing tools (apt/dpkg/setpriv) refuse to proceed if
    // they think they hold nothing (docs/namespaces-design.md §4.4).
    let cap_lines = crate::namespace::process::cap_status_lines();
    format!(
        "Name:\t{comm}\n\
Umask:\t0022\n\
State:\tR (running)\n\
Tgid:\t{pid}\n\
Ngid:\t0\n\
Pid:\t{pid}\n\
PPid:\t{ppid}\n\
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
RssAnon:\t{rss_kb:>8} kB\n\
RssFile:\t       0 kB\n\
RssShmem:\t       0 kB\n\
VmData:\t       0 kB\n\
VmStk:\t       0 kB\n\
VmExe:\t       0 kB\n\
VmLib:\t       0 kB\n\
VmPTE:\t       0 kB\n\
VmSwap:\t       0 kB\n\
CoreDumping:\t0\n\
THP_enabled:\t1\n\
Threads:\t{nthreads}\n\
SigQ:\t0/63880\n\
SigPnd:\t0000000000000000\n\
ShdPnd:\t{shdpnd_hex:016x}\n\
SigBlk:\t0000000000000000\n\
SigIgn:\t{sigign_hex:016x}\n\
SigCgt:\t{sigcgt_hex:016x}\n\
{cap_lines}\
NoNewPrivs:\t0\n\
Seccomp:\t0\n\
Seccomp_filters:\t0\n\
Speculation_Store_Bypass:\tthread vulnerable\n\
SpeculationIndirectBranch:\tconditional enabled\n\
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

/// `/proc/self/environ`: the guest environment as NUL-separated `KEY=VALUE`
/// entries (proc_pid_environ(5)), reflecting the actual launched env. The
/// entries are opaque bytes (not necessarily UTF-8). mode r-------- in Linux;
/// carrick serves it read-only like the other self files.
fn synthetic_proc_self_environ(environ: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in environ {
        bytes.extend_from_slice(entry);
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
    let nthreads = crate::thread::current_thread_states().len().max(1);
    proc_stat_line(pid, &comm, 'R', ppid, pid, pid, nthreads)
}

fn proc_stat_line(
    pid: u32,
    comm: &str,
    state: char,
    ppid: u32,
    pgrp: u32,
    session: u32,
    num_threads: usize,
) -> String {
    // Field 20 is num_threads: CPython's os.fork() reads it from /proc/self/stat
    // to decide whether to emit the multi-threaded-fork DeprecationWarning
    // (test_threading.test_*_after_fork). Was a hardcoded 1.
    //
    // The line must carry exactly 52 space-separated fields through field 52
    // (exit_code) per proc_pid_stat(5); a strict parser that splits and indexes
    // the tail (Go runtime, ps, monitoring agents) reads a short array if any
    // are missing. The final `0` is field 52.
    format!(
        "{pid} ({comm}) {state} {ppid} {pgrp} {session} 0 -1 4194560 0 0 0 0 0 0 0 0 \
20 0 {num_threads} 0 1 10485760 256 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 \
17 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
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
    // Worker threads are addressed by their (untranslated) registry tid, but the
    // MAIN thread is addressed by its ns-pid (== tgid) under a PID namespace,
    // which the registry keys by the host id instead. Match either so a
    // /proc/self/task/<tgid>/comm read of the main thread still resolves.
    let host_pid = if crate::namespace::pid::enabled() {
        crate::namespace::pid::ns_to_host_or_self(pid).unwrap_or(pid)
    } else {
        pid
    };
    if let Some(&(tid, state)) = own_threads
        .iter()
        .find(|(t, _)| *t as u32 == pid || *t as u32 == host_pid)
    {
        let ppid = unsafe { libc::getppid() } as u32;
        let me = std::process::id();
        // Per-thread name (prctl PR_SET_NAME / pthread_setname_np), falling back
        // to the process comm for a thread that never named itself.
        let name = per_thread_comm(tid, self_comm);
        match rest {
            "stat" => {
                return Some(
                    proc_stat_line(pid, &name, state, ppid, me, me, own_threads.len().max(1))
                        .into_bytes(),
                );
            }
            "comm" => return Some(format!("{name}\n").into_bytes()),
            "cmdline" => {
                let mut b = name.into_bytes();
                b.push(0);
                return Some(b);
            }
            "status" => {
                return Some(
                    format!(
                        "Name:\t{name}\nState:\t{state} ({long})\nTgid:\t{me}\n\
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

    // PID namespace (§5.3): the guest addresses `/proc/<ns_pid>/…` by ns-pid.
    // Translate it to the host pid for the host-backed lookups, but keep the
    // ns-pid for the displayed `Pid:` field; translate the host ppid/pgid back
    // to ns-pids for display. Identity when namespaces are off (host pid == the
    // value the guest passed).
    let ns_enabled = crate::namespace::pid::enabled();
    let host_pid = if ns_enabled {
        match crate::namespace::pid::ns_to_host_or_self(pid) {
            Some(h) => h,
            None => return None,
        }
    } else {
        pid
    };
    if !crate::host_proc::is_guest_process(host_pid) {
        return None;
    }
    let info = crate::host_proc::pid_info(host_pid)?;
    let comm = if info.comm.is_empty() {
        "carrick".to_owned()
    } else {
        info.comm.clone()
    };
    // Display pids are ns-local: the requested ns-pid for self, and the
    // ns-translation of the host ppid/pgid (0 / reparent handled by the
    // translation). When ns is off these are the raw host values.
    let disp_ppid = if ns_enabled {
        crate::namespace::pid::host_to_ns_or_self(info.ppid)
    } else {
        info.ppid
    };
    let disp_pgid = if ns_enabled {
        crate::namespace::pid::host_to_ns_pgid(info.pgid)
    } else {
        info.pgid
    };
    match rest {
        // Another guest process: we don't track its thread registry, so report
        // a single thread (num_threads=1). The multi-threaded-fork warning only
        // reads the caller's OWN /proc/self/stat, which uses the live count.
        "stat" => Some(
            proc_stat_line(pid, &comm, info.state, disp_ppid, disp_pgid, disp_pgid, 1).into_bytes(),
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
                ppid = disp_ppid,
                // Report the modeled container credentials, NOT the macOS host
                // uid/gid (501/20) `host_proc` reads — a sibling guest process
                // is root:0 in the default rootful container, consistent with
                // its own getuid()==0 and with /proc/self/status.
                uid = crate::cred_ipc::read_target(host_pid as i32).unwrap_or(0),
                gid = 0,
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
    // `self` (and `thread-self`) resolve to this process; the `task/<tid>/`
    // recursion in synthetic_proc_pid_file then picks the specific thread.
    // glibc's pthread_getname_np opens /proc/self/task/<tid>/comm.
    let pid: u32 = match pid_str {
        "self" | "thread-self" => std::process::id(),
        _ => pid_str.parse().ok()?,
    };
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

/// `/proc/devices`: char + block driver-major map. MAKEDEV/udev/busybox-mdev
/// parse this to resolve driver names to majors before `mknod`. Kept
/// consistent with the device nodes carrick exposes under `/dev`.
fn synthetic_proc_devices() -> &'static [u8] {
    b"Character devices:\n\
  1 mem\n\
  4 tty\n\
  4 ttyS\n\
  5 /dev/tty\n\
  5 /dev/console\n\
  5 /dev/ptmx\n\
 10 misc\n\
136 pts\n\
\n\
Block devices:\n\
254 virtblk\n"
}

/// `/proc/swaps`: header only (no swap configured). `free`/`swapon -s`/systemd
/// read this; an empty-but-headered file beats ENOENT.
fn synthetic_proc_swaps() -> &'static [u8] {
    b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
}

/// `/proc/vmstat`: the small set of keys real readers (psutil, node_exporter,
/// JVM GC tooling) touch. Values 0 — carrick has no global page accounting.
fn synthetic_proc_vmstat() -> &'static [u8] {
    b"nr_free_pages 0\n\
nr_anon_pages 0\n\
nr_mapped 0\n\
nr_file_pages 0\n\
nr_dirty 0\n\
nr_writeback 0\n\
pgpgin 0\n\
pgpgout 0\n\
pswpin 0\n\
pswpout 0\n\
pgfault 0\n\
pgmajfault 0\n\
oom_kill 0\n"
}

/// `/proc/self/io`: the 7 labeled I/O-accounting lines (proc_pid_io(5)).
/// carrick does not track per-process byte/syscall counts yet, so 0s — still
/// far better than ENOENT for monitoring tools that open this.
fn synthetic_proc_self_io() -> &'static [u8] {
    b"rchar: 0\n\
wchar: 0\n\
syscr: 0\n\
syscw: 0\n\
read_bytes: 0\n\
write_bytes: 0\n\
cancelled_write_bytes: 0\n"
}

/// `/proc/self/mountinfo` (proc_pid_mountinfo(5)): the richer mount table
/// modern tooling (systemd, findmnt, container runtimes) parses instead of the
/// legacy /proc/mounts. Synthetic mount-ids/major:minor; consistent with the
/// mounts carrick actually provides (overlay root + proc/sys/dev/pts/shm).
fn synthetic_proc_self_mountinfo() -> &'static [u8] {
    b"23 0 0:23 / / ro,relatime - overlay overlay ro\n\
24 23 0:24 / /proc rw,relatime - proc proc rw\n\
25 23 0:25 / /sys rw,relatime - sysfs sysfs rw\n\
26 23 0:26 / /dev rw,nosuid - tmpfs tmpfs rw,mode=755\n\
27 26 0:27 / /dev/pts rw,relatime - devpts devpts rw\n\
28 26 0:28 / /dev/shm rw,nosuid,nodev - tmpfs shm rw\n"
}

/// The standard per-VMA smaps field block (proc(5)). The kB values are
/// approximate (carrick has no per-page residency accounting); the LABELS and
/// ordering are what memory profilers parse. `size_kb` is the VMA extent.
fn smaps_region_fields(size_kb: u64) -> String {
    let pg = crate::linux_abi::LINUX_PAGE_SIZE / 1024;
    format!(
        "Size:           {size_kb:>8} kB\n\
KernelPageSize: {pg:>8} kB\n\
MMUPageSize:    {pg:>8} kB\n\
Rss:                   0 kB\n\
Pss:                   0 kB\n\
Pss_Dirty:             0 kB\n\
Shared_Clean:          0 kB\n\
Shared_Dirty:          0 kB\n\
Private_Clean:         0 kB\n\
Private_Dirty:         0 kB\n\
Referenced:            0 kB\n\
Anonymous:             0 kB\n\
LazyFree:              0 kB\n\
AnonHugePages:         0 kB\n\
ShmemPmdMapped:        0 kB\n\
FilePmdMapped:         0 kB\n\
Shared_Hugetlb:        0 kB\n\
Private_Hugetlb:       0 kB\n\
Swap:                  0 kB\n\
SwapPss:               0 kB\n\
Locked:                0 kB\n\
VmFlags: rd mr mw me\n"
    )
}

/// Parse the `start-end ...` of one `/proc/self/maps` line into its size in kB.
fn maps_line_size_kb(line: &str) -> u64 {
    let Some(range) = line.split_whitespace().next() else {
        return 0;
    };
    let Some((lo, hi)) = range.split_once('-') else {
        return 0;
    };
    match (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) {
        (Ok(lo), Ok(hi)) => hi.saturating_sub(lo) / 1024,
        _ => 0,
    }
}

/// `/proc/self/smaps`: each maps line followed by the standard kB-labeled
/// per-region fields (proc(5)). Built from the same maps rendering so the VMA
/// list always agrees with `/proc/self/maps`.
fn synthetic_proc_smaps(ctx: &SyntheticProcContext) -> String {
    let maps = synthetic_proc_maps(ctx);
    let mut out = String::new();
    for line in maps.lines() {
        out.push_str(line);
        out.push('\n');
        out.push_str(&smaps_region_fields(maps_line_size_kb(line)));
    }
    out
}

/// `/proc/self/smaps_rollup`: a `[rollup]` header line + aggregate fields.
/// Rss/Pss approximated from host RSS; labels/order per proc(5).
fn synthetic_proc_smaps_rollup(ctx: &SyntheticProcContext) -> String {
    let host = crate::host_proc::self_resource_usage().unwrap_or_default();
    let rss_kb = host.resident_bytes / 1024;
    // The rollup header spans the whole user address range, ending at the
    // reported stack top, mirroring what the kernel emits.
    let hi = LINUX_STACK_TOP;
    let _ = ctx;
    format!(
        "{:016x}-{hi:016x} ---p 00000000 00:00 0                          [rollup]\n\
Rss:            {rss_kb:>8} kB\n\
Pss:            {rss_kb:>8} kB\n\
Pss_Dirty:             0 kB\n\
Pss_Anon:       {rss_kb:>8} kB\n\
Pss_File:              0 kB\n\
Pss_Shmem:             0 kB\n\
Shared_Clean:          0 kB\n\
Shared_Dirty:          0 kB\n\
Private_Clean:         0 kB\n\
Private_Dirty:  {rss_kb:>8} kB\n\
Referenced:     {rss_kb:>8} kB\n\
Anonymous:      {rss_kb:>8} kB\n\
LazyFree:              0 kB\n\
AnonHugePages:         0 kB\n\
ShmemPmdMapped:        0 kB\n\
FilePmdMapped:         0 kB\n\
Shared_Hugetlb:        0 kB\n\
Private_Hugetlb:       0 kB\n\
Swap:                  0 kB\n\
SwapPss:               0 kB\n\
Locked:                0 kB\n",
        0u64,
    )
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

/// The name to report in /proc/<pid>/task/<tid>/comm: the thread's own
/// prctl/pthread-set name if it has one, else the process comm (`fallback`).
fn per_thread_comm(tid: crate::thread::ThreadId, fallback: &str) -> String {
    crate::thread::current_thread_name(tid)
        .map(|n| {
            let len = n.iter().position(|&b| b == 0).unwrap_or(n.len());
            String::from_utf8_lossy(&n[..len]).into_owned()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
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

    #[cfg(target_os = "macos")]
    #[test]
    fn proc_pid_dir_enumerates_and_lists_files() {
        // Mark this process as the guest root so is_guest_process(self) is true,
        // then /proc and /proc/<self> enumerate. Restore the root afterwards so
        // sibling tests are unaffected.
        let me = std::process::id();
        crate::host_proc::set_root_guest_pid(me);
        let v = ProcVfs::new();

        // /proc/<self> is a directory listing the RICH per-process surface
        // (files + magic symlinks + sub-dirs) since it is the self pid.
        let pid_path = format!("/proc/{me}");
        assert_eq!(v.lookup(&pid_path).unwrap().kind, EntryKind::Directory);
        let by_name: std::collections::HashMap<String, EntryKind> = v
            .readdir(&pid_path)
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.kind))
            .collect();
        for want in [
            "stat", "comm", "cmdline", "status", "maps", "limits", "auxv", "io", "cgroup",
            "statm",
        ] {
            assert_eq!(by_name.get(want), Some(&EntryKind::File), "file {want}");
        }
        for dir in ["task", "ns", "net"] {
            assert_eq!(by_name.get(dir), Some(&EntryKind::Directory), "dir {dir}");
        }
        for link in ["exe", "cwd", "root"] {
            assert_eq!(by_name.get(link), Some(&EntryKind::Symlink), "link {link}");
        }
        // Every listed flat file must actually open (readdir ⇄ open in sync).
        for (name, kind) in &by_name {
            if *kind == EntryKind::File {
                let p = format!("{pid_path}/{name}");
                assert!(
                    synthetic_file(&p, &demo_ctx()).is_some()
                        || synthetic_file(&format!("/proc/self/{name}"), &demo_ctx()).is_some(),
                    "listed file {name} does not open"
                );
            }
        }
        // /proc enumerates this guest process (as its ns-pid; identity here).
        let root = v.readdir("/proc").unwrap();
        assert!(
            root.iter().any(|d| d.name == me.to_string()),
            "/proc should list the guest pid {me}"
        );

        crate::host_proc::set_root_guest_pid(0);
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
    fn writable_tunables_open_for_write_others_eacces() {
        let v = ProcVfs::new();
        for p in [
            "/proc/self/oom_score_adj",
            "/proc/self/oom_adj",
            "/proc/self/loginuid",
            "/proc/self/timerslack_ns",
        ] {
            let h = v.open(
                p,
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            );
            assert!(h.is_ok(), "{p} should open for write, got {h:?}");
        }
        // A read-only tunable (oom_score) still rejects a write-open.
        assert_eq!(
            v.open(
                "/proc/self/oom_score",
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default()
            ),
            Err(LINUX_EACCES)
        );
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
        // Reserve a 64 KiB heap region but set the program break partway in, at an
        // unaligned offset. Real Linux reports page-aligned VMA bounds, so the [heap]
        // line must end at the break rounded UP to carrick's 16 KiB page — not at the
        // raw break, and not at the full region end. 0x1234 rounds up to 0x4000.
        let ctx = SyntheticProcContext {
            executable_path: "/bin/demo".to_owned(),
            argv: vec!["/bin/demo".to_owned()],
            environ: vec![b"PATH=/usr/bin".to_vec(), b"HOME=/root".to_vec()],
            address_space_regions: Some(vec![ProcMapsEntry {
                start: LINUX_HEAP_BASE,
                end: LINUX_HEAP_BASE + 0x10000,
                read: true,
                write: true,
                execute: false,
                path: String::new(),
            }]),
            brk_current: LINUX_HEAP_BASE + 0x1234,
            mmap_next: LINUX_MMAP_BASE,
            sig_ignored: 0,
            sig_caught: 0,
            sig_shdpnd: 0,
        };
        let maps = String::from_utf8(synthetic_file("/proc/self/maps", &ctx).unwrap()).unwrap();
        assert!(maps.contains("[heap]"));
        // The heap ends at the page-aligned break (0x1234 → 0x4000), proving the
        // VFS-owned brk_current drives the end rather than the reserved region end.
        assert!(maps.contains(&format!("{:016x}", LINUX_HEAP_BASE + 0x4000)));
        assert!(!maps.contains(&format!("{:016x}", LINUX_HEAP_BASE + 0x10000)));
    }

    fn ctx() -> SyntheticProcContext {
        SyntheticProcContext::default()
    }

    #[test]
    fn sysctl_dirs_resolve_as_directories() {
        let v = ProcVfs::new();
        for dir in [
            "/proc/sys",
            "/proc/sys/kernel",
            "/proc/sys/kernel/random",
            "/proc/sys/vm",
            "/proc/sys/fs",
            "/proc/sys/fs/inotify",
            "/proc/sys/fs/mqueue",
            "/proc/sys/net",
            "/proc/sys/net/core",
            "/proc/sys/net/ipv4",
        ] {
            assert_eq!(
                v.lookup(dir).unwrap().kind,
                EntryKind::Directory,
                "{dir} should be a directory"
            );
            assert!(v.readdir(dir).is_ok(), "{dir} should readdir");
        }
    }

    #[test]
    fn sysctl_readdir_lists_children() {
        let v = ProcVfs::new();
        let kernel: Vec<String> = v
            .readdir("/proc/sys/kernel")
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        for want in ["ostype", "osrelease", "cap_last_cap", "pid_max", "random"] {
            assert!(kernel.iter().any(|n| n == want), "kernel/ missing {want}");
        }
        // `random` is enumerated as a sub-directory, not a leaf.
        let random_kind = v
            .readdir("/proc/sys/kernel")
            .unwrap()
            .into_iter()
            .find(|d| d.name == "random")
            .unwrap()
            .kind;
        assert_eq!(random_kind, EntryKind::Directory);
    }

    #[test]
    fn sysctl_leaf_values_match_oracle() {
        for (path, want) in [
            ("/proc/sys/kernel/ostype", "Linux\n"),
            ("/proc/sys/kernel/cap_last_cap", "40\n"),
            ("/proc/sys/vm/overcommit_memory", "1\n"),
            ("/proc/sys/vm/max_map_count", "262144\n"),
            ("/proc/sys/net/core/somaxconn", "4096\n"),
            ("/proc/sys/fs/inotify/max_user_watches", "1048576\n"),
            ("/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n"),
            ("/proc/sys/net/ipv4/tcp_rmem", "4096\t131072\t6291456\n"),
            ("/proc/sys/fs/file-nr", "256\t0\t1048576\n"),
        ] {
            let got = synthetic_file(path, &ctx()).unwrap();
            assert_eq!(String::from_utf8(got).unwrap(), want, "{path}");
        }
    }

    #[test]
    fn sysctl_uuid_is_fresh_v4_each_read() {
        let a = String::from_utf8(synthetic_file("/proc/sys/kernel/random/uuid", &ctx()).unwrap())
            .unwrap();
        let b = String::from_utf8(synthetic_file("/proc/sys/kernel/random/uuid", &ctx()).unwrap())
            .unwrap();
        assert_eq!(a.trim_end().len(), 36, "uuid is 36 chars: {a:?}");
        assert_eq!(a.as_bytes()[14], b'4', "version-4 nibble");
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'), "variant");
        assert_ne!(a, b, "uuid must differ each read");
    }

    #[test]
    fn sysctl_boot_id_is_stable_and_nonzero() {
        let a = synthetic_file("/proc/sys/kernel/random/boot_id", &ctx()).unwrap();
        let b = synthetic_file("/proc/sys/kernel/random/boot_id", &ctx()).unwrap();
        assert_eq!(a, b, "boot_id stable within a run");
        assert_ne!(
            String::from_utf8(a).unwrap().trim_end(),
            "00000000-0000-4000-8000-000000000000",
            "boot_id must not be the all-zero sentinel"
        );
    }

    #[test]
    fn uptime_is_seconds_since_boot_not_epoch() {
        let up = synthetic_proc_uptime();
        let first: f64 = up.split_whitespace().next().unwrap().parse().unwrap();
        // A freshly-booted guest's uptime is small — certainly not ~1.78e9
        // (the old epoch-seconds bug).
        assert!(first < 1_000_000.0, "uptime field 1 should be small: {up:?}");
    }

    #[test]
    fn self_stat_has_exactly_52_fields() {
        let line = String::from_utf8(
            synthetic_file("/proc/self/stat", &demo_ctx()).unwrap(),
        )
        .unwrap();
        let n = line.trim_end().split(' ').count();
        assert_eq!(n, 52, "stat must have 52 fields: {line:?}");
    }

    #[test]
    fn self_status_has_new_labels_and_sane_vmsize() {
        let s =
            String::from_utf8(synthetic_file("/proc/self/status", &demo_ctx()).unwrap()).unwrap();
        for label in [
            "RssAnon:",
            "RssFile:",
            "RssShmem:",
            "NoNewPrivs:",
            "Seccomp:",
            "Seccomp_filters:",
            "CoreDumping:",
            "Speculation_Store_Bypass:",
        ] {
            assert!(s.contains(label), "status missing {label}");
        }
        // SigQ must carry a non-zero denominator (the pending-signal limit).
        assert!(s.contains("SigQ:\t0/63880"), "SigQ denominator: {s}");
        // VmSize must be derived from the guest VMAs, NOT the 521 GB host window.
        let vmsize_line = s.lines().find(|l| l.starts_with("VmSize:")).unwrap();
        let kb: u64 = vmsize_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        assert!(kb < 64 * 1024 * 1024, "VmSize should be sane, got {kb} kB");
    }

    #[test]
    fn self_environ_is_nul_separated_and_byte_exact() {
        // Includes a non-UTF-8 value to prove env is served as opaque bytes,
        // not lossily round-tripped through String.
        let ctx = SyntheticProcContext {
            environ: vec![
                b"PATH=/usr/bin".to_vec(),
                vec![b'X', b'=', 0xff, 0xfe],
                b"HOME=/root".to_vec(),
            ],
            ..SyntheticProcContext::default()
        };
        let out = synthetic_file("/proc/self/environ", &ctx).unwrap();
        assert_eq!(
            out,
            b"PATH=/usr/bin\0X=\xff\xfe\0HOME=/root\0".to_vec(),
            "environ must be NUL-separated and byte-exact"
        );
    }

    #[test]
    fn self_io_has_seven_labeled_lines() {
        let io = String::from_utf8(synthetic_file("/proc/self/io", &ctx()).unwrap()).unwrap();
        for label in [
            "rchar:",
            "wchar:",
            "syscr:",
            "syscw:",
            "read_bytes:",
            "write_bytes:",
            "cancelled_write_bytes:",
        ] {
            assert!(io.contains(label), "io missing {label}");
        }
        assert_eq!(io.lines().count(), 7);
    }

    #[test]
    fn devices_has_char_and_block_sections() {
        let d = String::from_utf8(synthetic_file("/proc/devices", &ctx()).unwrap()).unwrap();
        assert!(d.contains("Character devices:"));
        assert!(d.contains("Block devices:"));
        assert!(d.contains("136 pts"));
    }

    #[test]
    fn smaps_pairs_maps_lines_with_fields() {
        let s = String::from_utf8(synthetic_file("/proc/self/smaps", &demo_ctx()).unwrap()).unwrap();
        assert!(s.contains("[heap]"), "smaps includes the maps lines");
        assert!(s.contains("Rss:"), "smaps includes per-region fields");
        assert!(s.contains("VmFlags:"));
        let rollup =
            String::from_utf8(synthetic_file("/proc/self/smaps_rollup", &demo_ctx()).unwrap())
                .unwrap();
        assert!(rollup.contains("[rollup]"));
        assert!(rollup.contains("Pss:"));
    }

    #[test]
    fn flat_self_files_present() {
        for (path, needle) in [
            ("/proc/self/cgroup", "0::/"),
            ("/proc/self/oom_score", "0"),
            ("/proc/self/oom_score_adj", "0"),
            ("/proc/self/personality", "00000000"),
            ("/proc/self/loginuid", "4294967295"),
            ("/proc/self/timerslack_ns", "50000"),
            ("/proc/self/syscall", "running"),
            ("/proc/self/wchan", "0"),
            ("/proc/self/mountinfo", " / / "),
            ("/proc/vmstat", "pgfault"),
            ("/proc/swaps", "Filename"),
        ] {
            let got = String::from_utf8(synthetic_file(path, &ctx()).unwrap_or_default()).unwrap();
            assert!(got.contains(needle), "{path} should contain {needle:?}, got {got:?}");
        }
    }

    #[test]
    fn net_files_present_with_headers() {
        // Header-bearing socket tables and the namespace-correct aliases all
        // resolve to the same renderer.
        for (path, needle) in [
            ("/proc/net/dev", "Inter-|"),
            ("/proc/net/tcp", "local_address"),
            ("/proc/net/tcp6", "local_address"),
            ("/proc/net/udp", "rem_address"),
            ("/proc/net/unix", "RefCount Protocol"),
            ("/proc/net/route", "Iface\tDestination"),
            ("/proc/net/snmp", "Tcp: RtoAlgorithm"),
            ("/proc/net/netstat", "TcpExt:"),
            ("/proc/net/sockstat", "sockets: used"),
            ("/proc/net/arp", "IP address"),
            ("/proc/self/net/tcp", "local_address"),
            ("/proc/1/net/dev", "Inter-|"),
        ] {
            let got = String::from_utf8(synthetic_file(path, &ctx()).unwrap_or_default()).unwrap();
            assert!(got.contains(needle), "{path} should contain {needle:?}");
        }
    }

    #[test]
    fn self_is_traversable_dir_that_readlinks_to_pid() {
        let v = ProcVfs::new();
        // Modeled as a traversable directory (so /proc/self/<file> descends),
        // but readlink still yields the pid for tools that resolve it.
        assert_eq!(
            v.lookup_nofollow("/proc/self").unwrap().kind,
            EntryKind::Directory
        );
        assert_eq!(v.lookup("/proc/self").unwrap().kind, EntryKind::Directory);
        assert_eq!(
            v.readlink("/proc/self").unwrap().to_string_lossy(),
            crate::namespace::pid::self_ns_pid().to_string()
        );
    }

    #[test]
    fn net_dir_readlinks_to_self_net() {
        let v = ProcVfs::new();
        assert_eq!(
            v.lookup_nofollow("/proc/net").unwrap().kind,
            EntryKind::Directory
        );
        assert_eq!(v.readlink("/proc/net").unwrap().to_string_lossy(), "self/net");
    }

    #[test]
    fn thread_self_readlinks_to_task_tid() {
        let v = ProcVfs::new();
        let t = v.readlink("/proc/thread-self").unwrap();
        let p = crate::namespace::pid::self_ns_pid();
        assert_eq!(t.to_string_lossy(), format!("{p}/task/{p}"));
    }

    #[test]
    fn exe_cwd_root_lstat_as_symlinks() {
        let v = ProcVfs::new();
        for link in [
            "/proc/self/exe",
            "/proc/self/cwd",
            "/proc/self/root",
            "/proc/1/exe",
            "/proc/thread-self/exe",
        ] {
            assert_eq!(
                v.lookup_nofollow(link).unwrap().kind,
                EntryKind::Symlink,
                "{link} should lstat as a symlink"
            );
            // faccessat(F_OK)/`test -e` path goes through follow-lookup too.
            assert_eq!(v.lookup(link).unwrap().kind, EntryKind::Symlink, "{link}");
        }
    }

    #[test]
    fn ns_dir_and_links() {
        let v = ProcVfs::new();
        assert_eq!(
            v.lookup("/proc/self/ns").unwrap().kind,
            EntryKind::Directory
        );
        let names: Vec<String> = v
            .readdir("/proc/self/ns")
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        for want in ["net", "pid", "user", "mnt", "uts", "ipc", "cgroup"] {
            assert!(names.iter().any(|n| n == want), "ns/ missing {want}");
        }
        assert_eq!(
            v.lookup_nofollow("/proc/self/ns/net").unwrap().kind,
            EntryKind::Symlink
        );
        let t = v.readlink("/proc/self/ns/net").unwrap();
        assert_eq!(t.to_string_lossy(), "net:[4026531992]");
        // Same-namespace equality: self and a pid resolve to the same inode.
        assert_eq!(
            v.readlink("/proc/1/ns/pid").unwrap(),
            v.readlink("/proc/self/ns/pid").unwrap()
        );
    }

    #[test]
    fn top_level_readdir_has_self_threadself_net_sys() {
        let v = ProcVfs::new();
        let by_name: std::collections::HashMap<String, EntryKind> = v
            .readdir("/proc")
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.kind))
            .collect();
        // Traversable directories (carrick model); readlink still resolves them.
        for dir in ["self", "thread-self", "net", "sys"] {
            assert_eq!(by_name.get(dir), Some(&EntryKind::Directory), "{dir}");
        }
    }

    #[test]
    fn proc_net_resolves_as_directory_with_self_alias() {
        let v = ProcVfs::new();
        for dir in ["/proc/net", "/proc/self/net", "/proc/1/net"] {
            assert_eq!(
                v.lookup(dir).unwrap().kind,
                EntryKind::Directory,
                "{dir} should be a directory"
            );
            let names: Vec<String> =
                v.readdir(dir).unwrap().into_iter().map(|d| d.name).collect();
            for want in ["dev", "tcp", "unix", "route"] {
                assert!(names.iter().any(|n| n == want), "{dir} missing {want}");
            }
        }
    }

    #[test]
    fn proc_top_level_readdir_breadth() {
        let v = ProcVfs::new();
        let names: Vec<String> =
            v.readdir("/proc").unwrap().into_iter().map(|d| d.name).collect();
        for want in [
            "sys", "net", "devices", "vmstat", "swaps", "modules", "locks", "config.gz",
        ] {
            assert!(names.iter().any(|n| n == want), "/proc missing {want}");
        }
    }

    #[test]
    fn net_dev_uses_linux_iface_names_not_darwin() {
        let dev = String::from_utf8(synthetic_proc_net_dev()).unwrap();
        assert!(dev.contains("lo:"), "dev lists lo");
        // Never leak macOS pseudo-interfaces into the guest.
        for darwin in ["en0", "awdl0", "llw0", "utun", "lo0"] {
            assert!(!dev.contains(darwin), "dev must not leak {darwin}: {dev}");
        }
    }

    /// A context with a small populated address space (heap + mmap) so
    /// status/stat/smaps render realistically.
    fn demo_ctx() -> SyntheticProcContext {
        SyntheticProcContext {
            executable_path: "/bin/demo".to_owned(),
            argv: vec!["/bin/demo".to_owned()],
            environ: vec![b"PATH=/usr/bin".to_vec(), b"HOME=/root".to_vec()],
            address_space_regions: Some(vec![ProcMapsEntry {
                start: LINUX_HEAP_BASE,
                end: LINUX_HEAP_BASE + 0x10000,
                read: true,
                write: true,
                execute: false,
                path: String::new(),
            }]),
            brk_current: LINUX_HEAP_BASE + 0x4000,
            mmap_next: LINUX_MMAP_BASE,
            sig_ignored: 0,
            sig_caught: 0,
            sig_shdpnd: 0,
        }
    }

    #[test]
    fn stat_btime_is_nonzero_recent() {
        let stat = String::from_utf8(synthetic_proc_stat()).unwrap();
        let btime_line = stat.lines().find(|l| l.starts_with("btime ")).unwrap();
        let btime: u64 = btime_line.trim_start_matches("btime ").parse().unwrap();
        // After ~2020 and before far-future — a real epoch boot time.
        assert!(btime > 1_600_000_000, "btime should be a recent epoch: {btime}");
    }
}
