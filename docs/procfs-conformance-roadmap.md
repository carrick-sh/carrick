# carrick procfs conformance roadmap

Empirical audit (2026-06-01): carrick `/proc` vs Docker linux/arm64 oracle + proc(5), clean-room (no Linux source). Source: `crates/carrick-runtime/src/vfs/proc.rs`.


## HIGH severity

### `/proc/self (the directory: lookup/readdir/open-as-dir)` — missing
- **carrick:** stat /proc/self -> ENOENT (cannot statx); ls /proc/self -> ENOENT; ls /proc/self/ -> ENOENT; readlink /proc/self -> rc=1. Yet /proc/self/<file> reads (status/stat/maps/exe) DO resolve. Root cause: proc_pid_dir_host_pid (proc.rs:257) only accepts a NUMERIC /proc/<pid>; 'self'/'thread-self' are not handled, so proc_pid_dir_entries()/lookup()/open-as-dir all return None for /proc/self. parse_proc_pid_path (proc.rs:993) DOES map 'self' for file reads, creating the asymmetry.
- **docker:** stat /proc/self -> 'symbolic link'; stat -L -> 'directory'; ls /proc/self lists 51 entries; readlink /proc/self -> the pid.
- **implement:** Teach proc_pid_dir_host_pid (and the readdir/lookup/open dir paths) to resolve the 'self' and 'thread-self' components to std::process::id() the same way parse_proc_pid_path already does, so /proc/self resolves as a directory (and as a symlink for readlink/stat reporting the pid). Then `ls /proc/self`, scandir(/proc/self), stat(/proc/self) work.
- **impact:** Any tool that scandir()/glob()s /proc/self (ls /proc/self, find /proc/self, python os.listdir('/proc/self'), shells doing /proc/self/fd/* expansion, container/cgroup probes, debuggers enumerating fds) gets ENOENT. Also `stat /proc/self` failing breaks code that statx()es the dir before reading children.

### `/proc/self/<pid> readdir contents (PROC_PID_FILES)` — readdir_incomplete
- **carrick:** ls /proc/<numeric-self-pid> -> only 'cmdline comm stat status task' (5 entries). PROC_PID_FILES (proc.rs:296) = &["cmdline","comm","stat","status"] and omits the entire fd/, exe, cwd, root symlinks, limits, maps, io, status-adjacent files.
- **docker:** ls /proc/self -> 51 entries (auxv, cgroup, cmdline, comm, environ, exe, fd, fdinfo, io, limits, loginuid, maps, mountinfo, mounts, mountstats, net, ns, oom_score, oom_score_adj, personality, sched..., schedstat, sessionid, setgroups, smaps, smaps_rollup, stack, stat, statm, status, syscall, task, timerslack_ns, uid_map, gid_map, wchan, ...).
- **implement:** Expand PROC_PID_FILES to list every file/symlink carrick actually serves (limits, maps, statm, auxv, cmdline, comm, environ, io, status, stat, cgroup, ...) plus the fd/ and task/ dirs and exe/cwd/root symlinks, matching what synthetic_file/synthetic_proc_pid_file handle. Keep readdir entries in sync with what open() can serve.
- **impact:** Enumeration-driven tools (ps, top reading /proc/<pid>/*, libproc-style scanners, glob '/proc/self/*') see a process that appears to have only 4 files; tools that iterate then open each file silently skip limits/maps/io/etc.

### `/proc/self (the magic symlink itself)` — missing
- **carrick:** NOT a symlink. `test -L /proc/self` -> NOT_SYMLINK; `stat /proc/self` -> ENOENT ('cannot statx'); `readlink /proc/self` -> empty. ProcVfs only knows /proc, numeric /proc/<pid> dirs, and flat synthetic files; the literal token 'self' is never modeled as an entry or symlink. The flat files /proc/self/status etc. work only because synthetic_file() matches the literal string '/proc/self/status'; /proc/self as a path component does not resolve.
- **docker:** `test -L /proc/self` -> IS_SYMLINK; `stat -c '%F %A'` -> 'symbolic link lrwxrwxrwx'; `readlink /proc/self` -> the caller's own pid (e.g. '7'). proc_pid(5): /proc/self is a symlink to /proc/<pid-of-caller>.
- **implement:** Model /proc/self (and /proc/thread-self, /proc/curproc, /proc/this) as a symlink whose readlink target is the decimal ns-pid string (self_ns_pid()). lstat must report S_IFLNK mode 0o777. This makes `stat`, `test -L`, `realpath`, and any tool that lstat()s /proc/self before walking into it behave correctly. proc_pid(5).
- **impact:** realpath(3)/canonicalize, Go's os.Executable fallbacks, glibc/systemd/util-linux probes that lstat /proc/self or readlink it; anything resolving /proc/self via a path walk that first checks it's a symlink (rare but real for tools that special-case the magic link).

### `/proc/self/fd/<N> (readlink target for stdio + inherited fds)` — wrong_value
- **carrick:** readlink /proc/self/fd/0,1,2 ALL return empty (0 bytes written). The readlinkat handler (fs.rs:5392) only resolves an fd to a target when fd_open_paths or open_file(n).open_path() has a recorded path. stdin/stdout/stderr (and pipes/sockets/eventfds) have no recorded path, so readlink returns an empty string instead of '/dev/null' / 'pipe:[N]' / 'socket:[N]' / 'anon_inode:[...]'. `test -e /proc/self/fd/0` -> MISSING.
- **docker:** `readlink /proc/self/fd/0` -> '/dev/null'; fd 1/2 -> 'pipe:[1065502]'; an opened file fd -> its path; `ls -la /proc/self/fd` lists 0..3 as symlinks (lrwx------). proc_pid_fd(5): each entry is a symlink to the open file; non-file descriptions render as 'pipe:[ino]', 'socket:[ino]', 'anon_inode:[type]'.
- **implement:** In readlinkat, when proc_self_fd_number resolves but there is no open_path, synthesize a target from the OpenDescription kind: regular/host file -> its path; pipe -> 'pipe:[<ino>]'; socket -> 'socket:[<ino>]' (reuse the inode the fd_table already assigns for socket: links at fd_table.rs:488); eventfd/epoll/signalfd/timerfd/inotify -> 'anon_inode:[eventfd]' etc.; stdio bound to /dev/null -> '/dev/null'. Never return an empty string for an open fd. proc_pid_fd(5).
- **impact:** `ls -la /proc/self/fd`, shells/loggers that readlink fd 1 to detect tty-vs-pipe, lsof-style introspection, Python's os.readlink('/proc/self/fd/N'), and anything emulating dup-by-path. Empty target breaks fd-introspection and 'are we piped?' heuristics.

### `/proc/self/fd/ (directory listing)` — missing
- **carrick:** `ls /proc/self/fd` -> ENOENT; shell glob /proc/self/fd/* does not expand (literal). ProcVfs has no readdir for the 'fd' component; it is not a recognized directory.
- **docker:** `ls -la /proc/self/fd` -> directory dr-x------ containing one symlink per open fd (0,1,2,3...). opendir+getdents enumerate them.
- **implement:** Add a synthetic /proc/<pid>/fd (and /proc/self/fd) directory whose readdir enumerates the guest's currently-open fd numbers (from the fd table), each entry an S_IFLNK. Gate lstat/open of the dir to S_IFDIR mode 0o500. proc_pid_fd(5).
- **impact:** Very common: the canonical 'close all fds above N' loop (`for fd in /proc/self/fd/*`), Python's _close_open_fds / subprocess fd cleanup, shell fd enumeration, container runtimes. ENOENT forces fallback to closefrom/brute-force or breaks fd accounting.

### `/proc/sys (and all subdirs: /proc/sys/kernel, /proc/sys/vm, /proc/sys/fs, /proc/sys/net/*, /proc/sys/fs/inotify, /proc/sys/fs/mqueue)` — readdir_incomplete
- **carrick:** ENOENT for the directories themselves. `ls /proc/sys` -> 'No such file or directory'; same for every sys subdir. ProcVfs::lookup only treats /proc, /proc/<pid>, /proc/<pid>/task as directories; readdir returns ENOTDIR for any other path. The handful of served leaf files (osrelease, hostname, pid_max, boot_id, vm/mmap_min_addr) are hardcoded paths in synthetic_file() and resolve only because lookup falls through to the synthetic_file().is_some() File branch — but you cannot enumerate them.
- **docker:** Real directories, listable via opendir/readdir; e.g. `ls /proc/sys/kernel` shows osrelease, pid_max, ... hundreds of entries.
- **implement:** Make /proc/sys and its intermediate components (kernel, vm, fs, fs/inotify, fs/mqueue, net, net/core, net/ipv4, kernel/random, kernel/yama) resolve as directories in ProcVfs::lookup (kind=Directory, mode 0o555) and have readdir() list the sysctl leaf names carrick actually serves. Driving this from a static table of (path -> value-or-generator) lets lookup, readdir, open, and synthetic_file all share one source of truth. Per proc(5), /proc/sys is a directory hierarchy; tools that walk it (sysctl -a, systemd, container runtimes that snapshot /proc/sys) currently see nothing.
- **impact:** Anything that enumerates sysctls breaks: `sysctl -a`, container init that iterates /proc/sys/net to apply settings, Java/JVM ergonomics probes, and any code doing opendir('/proc/sys/...'). Also any open of a sys file via a path whose intermediate component is checked with stat()/access() first (common in libs) fails because the parent dir is ENOENT.

### `/proc/sys/kernel/random/uuid` — missing
- **carrick:** ENOENT.
- **docker:** `22592583-2959-4ad3-9f0e-8c33030e5418\n` — fresh random UUIDv4 on EVERY read.
- **implement:** Serve a freshly-generated random version-4 UUID string on each open/read (proc_sys_kernel(5): 'each read returns a randomly generated 128-bit UUID in standard UUID format', newline-terminated). carrick already has boot_id formatting code (synthetic_proc_boot_id) to model the textual layout; reuse it but randomize per read instead of fixed. Must NOT be static — programs use it as an entropy/unique-id source.
- **impact:** This is a commonly-used cheap source of randomness/unique IDs: libuuid fallback, Python `uuid` in some paths, dbus machine-id generation, many language stdlibs. ENOENT forces a fallback (sometimes /dev/urandom, sometimes failure). A STATIC value here (if naively added) would be a correctness bug producing duplicate UUIDs.

### `/proc/sys/kernel/cap_last_cap` — missing
- **carrick:** ENOENT.
- **docker:** `40\n` (highest valid capability number).
- **implement:** Serve a single newline-terminated integer = highest capability number carrick models (e.g. `40` to match the 6.12 oracle, or a value consistent with whatever capget/prctl(PR_CAPBSET) carrick supports). proc_sys_kernel(5) -> capabilities(7). This MUST be consistent with capability syscalls carrick honors.
- **impact:** libcap, systemd, runc/containerd, and Docker-in-Docker read cap_last_cap to iterate the capability bounding set (they loop 0..=cap_last_cap doing prctl(PR_CAPBSET_DROP)). ENOENT makes libcap fall back to a compiled-in guess and modern container runtimes log errors or refuse to drop caps. High impact for any container/systemd workload.

### `/proc/sys/vm/overcommit_memory` — missing
- **carrick:** ENOENT.
- **docker:** `1\n` (single integer, 0/1/2 mode).
- **implement:** Serve a single newline-terminated integer mode. Redis, some JVM/Go allocators, and many DBs read this. Report a mode consistent with carrick's actual mmap/brk behavior: since carrick freely satisfies large anon mmaps (heuristic/always-overcommit semantics), `1` (always overcommit) is the honest match; the oracle also reports `1`.
- **impact:** Redis logs a loud WARNING and degrades fork/save behavior when overcommit_memory != 1 or is unreadable; PostgreSQL and the JVM read it for memory-pressure heuristics. ENOENT triggers fallback warnings across major server runtimes. High impact for the 'apt install + run a server' demos.

### `/proc/sys/vm/max_map_count` — missing
- **carrick:** ENOENT.
- **docker:** `262144\n` (single integer, max VMAs per process).
- **implement:** Serve a single newline-terminated integer, default `262144` (modern Linux). proc(5)/vm docs: ceiling on number of mmap regions per process. Should be >= whatever carrick's address_space_regions tracking allows.
- **impact:** Elasticsearch refuses to start if max_map_count < 262144 (hard bootstrap check); JVM (ZGC/G1), many memory-mapped DBs (RocksDB/LMDB), and Go's runtime read it. ENOENT -> bootstrap-check failures or conservative fallbacks. High for server workloads.

### `/proc/sys/fs/inotify/max_user_watches, max_user_instances, max_queued_events` — missing
- **carrick:** ENOENT for all three.
- **docker:** `1048576\n`, `8192\n`, `16384\n` (each a single integer).
- **implement:** Serve each as a single newline-terminated integer (max_user_watches=1048576, max_user_instances=8192, max_queued_events=16384 match the oracle). These must be consistent with carrick's inotify emulation limits. proc_sys_fs(5) under inotify/.
- **impact:** VERY commonly read: file-watchers everywhere — Node/webpack/vite/chokidar, VS Code, esbuild, Go fsnotify, systemd-path — read max_user_watches and either warn loudly ('ENOSPC / increase max_user_watches') or cap their watch count. esbuild/webpack dev servers and `npm`-based dev tooling are core Node workloads; ENOENT here is a frequent, visible failure mode.

### `/proc/sys/net/core/somaxconn` — missing
- **carrick:** ENOENT.
- **docker:** `4096\n`.
- **implement:** Serve a single newline-terminated integer = the listen(2) backlog ceiling (proc_sys_net(5) -> listen(2)). Modern default is 4096 (older 128). Should equal the cap carrick actually applies to the listen() backlog when forwarding to the host socket.
- **impact:** Nginx, Node http.Server, Redis, Go net/http, Python's socketserver, and Java NIO all read somaxconn to size their listen backlog and log warnings when it's small or unreadable. Redis prints a 'somaxconn is lower than X' WARNING. High impact for the http-server / nginx demos.

### `/proc/uptime` — wrong_value
- **carrick:** WRONG VALUE/SEMANTICS: prints '1780327693.00 1780327693.00' — it formats SystemTime::now() seconds-since-UNIX-epoch as the uptime (synthetic_proc_uptime at proc.rs:635-641 does duration_since(UNIX_EPOCH).as_secs()). Format (two 2-dp floats) is correct; the value is ~56 years of 'uptime' and the two fields are identical.
- **docker:** Two space-separated floats with 2 decimals: '61943.23 616791.70' (uptime_secs idle_secs). First field is seconds-since-boot, a small number on a fresh container.
- **implement:** Record a process-start Instant once (e.g. a OnceLock<Instant> set at runtime boot) and report uptime = start.elapsed().as_secs_f64(); the idle field can be uptime*ncpu (or a smaller plausible value), and MUST differ from / be >= the uptime field. Never emit epoch seconds. Keep the existing '{:.2} {:.2}' format.
- **impact:** systemd, sysinfo crate, `uptime`/`w`, container health probes, and many language stdlibs (Go runtime, Python psutil, Node os.uptime via sysinfo) read field 0 as seconds-since-boot. A ~1.78e9 'uptime' yields nonsense ('uptime 20629 days') and breaks any code computing absolute boot time = now - uptime (it lands at epoch 0 / 1970), and any rate/age math (e.g. process age = uptime - starttime_jiffies/HZ goes hugely negative).

### `/proc/net (the directory itself, and /proc/self/net)` — wrong_structure
- **carrick:** /proc/net is a real mount point ('procnet' VFS, mount.rs:279), NOT a symlink: readlink /proc/net returns empty. Worse, ls /proc/net and ls -ld /proc/net both fail with ENOENT - the procnet directory does not enumerate (readdir unimplemented) even though individual hardcoded files (if_inet6/igmp/igmp6) resolve. /proc/self/net/* is entirely unhandled: cat /proc/self/net/tcp -> ENOENT.
- **docker:** /proc/net is a symlink: readlink /proc/net -> self/net; ls -ld /proc/net shows lrwxrwxrwx ... /proc/net -> self/net. /proc/self/net/ is the real directory (~70 entries). proc_net(5): 'since Linux 2.6.25, /proc/net is a symbolic link to the directory /proc/self/net'.
- **implement:** Make /proc/net a symlink to self/net (proc_net(5)) OR at minimum make the procnet directory readdir-able and route /proc/<pid>/net/<f> and /proc/self/net/<f> to the same synthesizer as /proc/net/<f>. Today any tool that opens /proc/self/net/<anything> (the canonical path many libraries use) gets ENOENT, and any tool that lists /proc/net to discover files fails outright.
- **impact:** Programs that read the namespace-correct path /proc/self/net/dev|tcp|... (common in Go net, container/cgroup tooling, monitoring agents) get ENOENT. Tools that enumerate /proc/net (netstat -i scanning, some Java NetworkInterface fallbacks, ss table discovery) hit a readdir ENOENT before any per-file read.

### `/proc/net/dev` — missing
- **carrick:** ENOENT (cat /proc/net/dev: No such file or directory).
- **docker:** Present. Exact two header lines: 'Inter-|   Receive ... |  Transmit' and ' face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed', then one space-padded row per interface (lo, tunl0, ...) with 16 counters.
- **implement:** Synthesize from host getifaddrs (already used by host_mc_interfaces). Emit the two verbatim header lines (proc_net(5) / proc(5) quote them exactly), then one '  <name>: <16 counters>' row per interface - at least a lo: row with all-zero counters and a primary interface row. Map host iface names to Linux-plausible names (lo, eth0) rather than leaking en0/awdl0.
- **impact:** netstat -i, ip -s link fallbacks, Node os.networkInterfaces() stat paths, Go gopsutil net.IOCounters, and many monitoring agents parse /proc/net/dev; ENOENT makes them report zero interfaces or error.

### `/proc/net/tcp and /proc/net/tcp6` — missing
- **carrick:** ENOENT for both.
- **docker:** Present, header-only when no sockets: '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode' (tcp6 has wider 32-hex-digit address columns + remote_address). proc(5) column order: sl, local_address, rem_address, st, tx_queue, rx_queue, tr, tm->when, retrnsmt, uid, timeout, inode.
- **implement:** Emit at least the verbatim header line (Docker emits header even with zero sockets). Because carrick is host-socket-passthrough it cannot list real guest sockets faithfully; a present file with the correct header + zero data rows matches the common idle case and is far better than ENOENT. Optionally enumerate guest-tracked listening/connected sockets into rows (sl local_addr:port rem_addr:port st ... inode) using the socket registry if available.
- **impact:** ss/lsof -i/netstat -t, JVM (sun.net), Go net diagnostics, and tests that enumerate sockets read these; ENOENT vs an empty-but-headered table is the difference between 'no connections' and 'tool errors out'.

### `/proc/self` — wrong_structure
- **carrick:** ENOENT as a standalone object: `readlink /proc/self` -> 'No such file or directory'; `ls -ld /proc/self` -> ENOENT; `stat -c %F /proc/self` -> 'cannot statx /proc/self'. Sub-paths (/proc/self/comm, /proc/self/maps) DO work via parse_proc_pid_path which maps the literal string "self" to std::process::id(). But the bare `self` component is neither a VFS lookup() hit nor a readlink target. In ProcVfs::readdir("/proc") `self` is emitted as EntryKind::Directory (not a symlink), and ProcVfs::lookup() has no case for "/proc/self" itself, so stat/readlink/-e fall through to ENOENT.
- **docker:** Magic symlink resolving to the caller's own /proc/<pid> dir. `readlink /proc/self` -> e.g. "8"; `stat -c %F /proc/self` -> "symbolic link"; `ls -ld /proc/self` and `[ -e /proc/self ]` succeed. Sub-paths like /proc/self/status work because the symlink resolves first.
- **implement:** Model /proc/self as a magic symbolic link (proc(5): 'resolves to the process's own /proc/pid directory'). lookup("/proc/self") must return Metadata{kind: Symlink} and a readlink handler must return the decimal self ns-pid (crate::namespace::pid::self_ns_pid()). Likewise expose it in readdir as EntryKind::Symlink, not Directory. Many tools `stat /proc/self`, `realpath /proc/self`, or `readlink /proc/self` to discover their own pid; today those fail. (Note sub-path reads already work, so impact is limited to direct operations on the link itself.)
- **impact:** Any program that readlink/realpath/stats /proc/self directly to learn its pid or canonical path (systemd-style pid discovery, some Go/Rust self-exe probes, `realpath /proc/self/exe` chains that stat each component). glibc/ps tools mostly use sub-paths so the common case survives, but direct-link consumers break.

### `/proc (top-level readdir: numeric pid dirs)` — wrong_value
- **carrick:** Lists numeric dirs named by HOST pids from libproc proc_listallpids filtered by is_guest_process (observed 43771, 43772, 43925...). These do NOT match the ns-pids the guest sees (shell $! = 5, status Pid: = 5/8) NOR the names under /proc/<pid>/task. So `ls /proc` shows pids that getpid()/$!/status never produce — a guest cannot correlate them. enumerate_guest_pids() returns raw host pids without host_to_ns translation.
- **docker:** Lists numeric dirs whose names are the NAMESPACE pids visible to the container (init=1, and the spawned `sleep` showed `10`, matching what the shell's $! reported and what /proc/<pid>/status Pid: said). Plus self, thread-self, and ~60 static files/dirs.
- **implement:** Translate each enumerated host pid through crate::namespace::pid::host_to_ns_or_self before emitting it as a /proc/<n> dir name (mirroring what synthetic_proc_pid_file already does for the displayed Pid: field). The readdir name must equal the value the guest's getpid()/wait()/$! returns. When the PID namespace is off this is identity (still fine). Drop host pids that don't map into the guest ns.
- **impact:** `ps`, `pgrep`, `top`, busybox `ps`, and any code that lists /proc and then opens /proc/<that-name>/... will scan unreachable host pids and miss/mislabel the real guest processes. Process-enumeration tooling is fundamentally inconsistent with getpid().


## MEDIUM severity

### `/proc/self/io` — missing
- **carrick:** ENOENT (/bin/cat: No such file or directory).
- **docker:** Present, 7 lines: rchar/wchar/syscr/syscw/read_bytes/write_bytes/cancelled_write_bytes (e.g. 'rchar: 2075' ...). proc_pid_io(5).
- **implement:** Synthesize the 7 labeled lines in order. Pull rchar/wchar/syscr/syscw from carrick's per-process byte/syscall counters if tracked; otherwise report plausible monotonic counters (even 0s are better than ENOENT). Format exactly 'rchar: N\n...cancelled_write_bytes: N\n' per proc_pid_io(5).
- **impact:** Monitoring/benchmark tools (iotop-like, language runtime self-instrumentation, CI perf harnesses, some glibc/io accounting) that open /proc/self/io get ENOENT and may abort or log errors.

### `/proc/self/oom_score, /proc/self/oom_score_adj, /proc/self/oom_adj` — missing
- **carrick:** All three ENOENT.
- **docker:** All present: oom_score -> integer (e.g. 666); oom_score_adj -> '0'; oom_adj -> '0'. oom_score_adj/oom_adj are rw.
- **implement:** Serve oom_score as a single integer line (e.g. '0\n' is acceptable since it is volatile), and oom_score_adj/oom_adj as '0\n'. Ideally make oom_score_adj/oom_adj writable (accept and store the value) since systemd/container managers write them; at minimum read-as-0 avoids ENOENT.
- **impact:** Container init systems, systemd, and OOM-tuning daemons read/write oom_score_adj on startup; ENOENT can make them log warnings or refuse to lower their OOM priority. Health-check scripts reading oom_score break.

### `/proc/self/cgroup` — missing
- **carrick:** ENOENT.
- **docker:** Present: '0::/' (cgroup v2 unified hierarchy line). cgroups(7) format: hierarchy-ID:controller-list:cgroup-path.
- **implement:** Serve a static cgroup v2 line '0::/\n' (matches the Docker oracle exactly). This is a fixed, safe value requiring no live state.
- **impact:** Runtime self-detection (Java/Node/Go reading cgroup memory limits, systemd, container-aware libraries, 'am I in a container' probes) reads /proc/self/cgroup; ENOENT breaks cgroup-limit detection and can cause wrong heap-sizing or crashes in cgroup-aware allocators.

### `/proc/self/smaps, /proc/self/smaps_rollup` — missing
- **carrick:** Both ENOENT.
- **docker:** Both present. smaps_rollup: a '[rollup]' header line followed by ~22 labeled kB fields (Rss/Pss/Pss_Dirty/Pss_Anon/.../Locked). smaps: per-VMA maps line + the same per-region fields.
- **implement:** carrick already synthesizes /proc/self/maps; build smaps by emitting each maps line followed by the standard kB-labeled fields (Size/Rss/Pss/Shared_*/Private_*/Referenced/Anonymous/Swap/...). For smaps_rollup, emit one '[rollup]' header + the aggregate fields (can reuse statm/host RSS for Rss/Pss approximations). Field LABELS/order must match proc(5); volatile kB values may approximate.
- **impact:** Medium: memory profilers (heaptrack, memory-cgroup tooling), some JVM/Go diagnostics, and 'how much PSS am I using' self-instrumentation read smaps_rollup; ENOENT makes them fall back or error. Lower-frequency than maps but real.

### `/proc/self/mountinfo, /proc/self/mountstats` — missing
- **carrick:** Both ENOENT. Note carrick DOES serve /proc/mounts and /proc/self/mounts-style content elsewhere, but not the richer mountinfo format.
- **docker:** mountinfo present: per-mount lines 'mount-id parent-id major:minor root mount-point options - fstype source super-options' (e.g. overlay '/', proc on /proc, tmpfs on /dev). mountstats present (NFS-oriented, often sparse).
- **implement:** Synthesize mountinfo from carrick's mount table in the proc_pid_mountinfo(5) 11+-field format (reuse the same mount set that backs /proc/mounts; assign synthetic mount-id/parent-id/major:minor). mountstats can be an empty or minimal file. This keeps mountinfo and mounts consistent.
- **impact:** Medium: systemd, util-linux findmnt(1), container runtimes, and bind-mount/overlay-aware tools parse /proc/self/mountinfo (NOT the legacy /proc/mounts) for propagation flags and mount IDs; ENOENT breaks mount enumeration in modern tooling.

### `/proc/self/environ` — missing
- **carrick:** ENOENT.
- **docker:** Present, NUL-separated KEY=VALUE pairs (HOSTNAME=..., HOME=/root, PATH=..., PWD=/). mode r--------.
- **implement:** Serve the guest process environment as NUL-separated KEY=VALUE entries (carrick already has argv via SyntheticProcContext; add the environ slice the same way and emit it like cmdline). Must reflect the ACTUAL launched env (-e flags / image env), not a static set.
- **impact:** Medium: language runtimes and libraries that re-read their own environment via /proc/self/environ (some glibc paths, security tools, ps -e wide, CRIU, debuggers) get ENOENT; also breaks 'inspect a child's env' patterns reading /proc/<pid>/environ.

### `/proc/self/stat (field count)` — wrong_fields
- **carrick:** 51 fields (proc_stat_line, proc.rs:836-853). The trailing field (field 52, exit_code) is absent; the line ends one field short. Fields 1-20 incl num_threads (field 20) are present and correct, but the tail (fields after starttime, incl the cgtime/start_data/end_data/arg_start.../exit_code block) is largely zeros and one field short of 52.
- **docker:** 52 space-separated fields (full proc_pid_stat(5) set through field 52 exit_code).
- **implement:** Add the missing trailing field so the line has exactly 52 space-separated fields (append a final '0' for exit_code). Verify with `cat /proc/self/stat | tr ' ' '\n' | wc -l` == 52 against the oracle. Also note vsize (field 23) is hardcoded 10485760 and rss (field 24) 256 regardless of actual size; acceptable as volatile but ideally sourced from host RSS for consistency with statm/status.
- **impact:** Medium: parsers that split on whitespace and index high fields (Go runtime, glibc sysconf paths, ps, monitoring agents that read field 52/exit_code or count fields) read past the end or get a short array; off-by-one at the tail can mis-attribute a value or panic on a strict parser.

### `/proc/self/auxv` — wrong_value
- **carrick:** 16 bytes, all zero (synthetic_proc_self_auxv returns &[0u8;16], proc.rs:1090). That is effectively just an AT_NULL pair (or two zero words) with no real AT_* entries.
- **docker:** 336 bytes of ELF auxiliary vector (multiple AT_* type/value 8-byte pairs: AT_HWCAP, AT_PAGESZ, AT_PHDR, AT_RANDOM, AT_EXECFN, AT_PLATFORM, ... terminated by AT_NULL).
- **implement:** Emit the SAME auxv carrick already constructs on the guest stack at exec time (it must compute AT_PAGESZ, AT_HWCAP/AT_HWCAP2, AT_RANDOM, AT_PHDR/AT_PHENT/AT_PHNUM, AT_ENTRY, AT_EXECFN, AT_PLATFORM, AT_CLKTCK, AT_UID/EUID/GID/EGID, AT_SECURE, terminated by AT_NULL). Mirror that exact byte image into /proc/self/auxv instead of 16 zero bytes.
- **impact:** Medium-high: glibc/musl init, the dynamic loader, libgcc unwinder, Go runtime, and CPython read /proc/self/auxv to recover AT_HWCAP (CPU feature dispatch), AT_PAGESZ, AT_RANDOM (stack canary / hash seed), and AT_PHDR. A 16-byte all-zero auxv makes feature detection see no HWCAP and getauxval(AT_*)-via-/proc return 0, which can disable optimized code paths or, for tools that fall back to reading /proc (not the stack auxv), break entirely.

### `/proc/self/status (missing field labels)` — wrong_fields
- **carrick:** Omits NStgid/NSpid/NSpgid/NSsid (deliberate per code comment), RssAnon/RssFile/RssShmem, Seccomp/Seccomp_filters, CoreDumping, NoNewPrivs, Speculation_Store_Bypass. SigQ is '0/0' (denominator 0; Docker shows the RLIMIT_SIGPENDING limit e.g. 63880). Groups is empty ('Groups:\t\n') vs Docker 'Groups:\t0 '. VmSize is reported as ~546918752 kB (~521 GB, from the 512GB mmap window) vs Docker's realistic 2416 kB. Fields that ARE present (Name/State/Pid/Tgid/PPid/Threads/Sig*/Cap*/Cpus_allowed*) are correctly formatted.
- **docker:** Includes NStgid/NSpid/NSpgid/NSsid, RssAnon/RssFile/RssShmem, Seccomp/Seccomp_filters, CoreDumping, NoNewPrivs, Speculation_Store_Bypass, SigQ with a nonzero denominator (0/63880), Groups with the gid list. Full set per proc_pid_status(5).
- **implement:** (1) Add RssAnon/RssFile/RssShmem lines (can split VmRSS, e.g. RssFile=VmRSS, RssAnon=0) so RSS-decomposing tools parse. (2) Add Seccomp:\t0 and Seccomp_filters:\t0, NoNewPrivs:\t0, CoreDumping:\t0 — cheap statics that runtimes probe. (3) Fix SigQ to '0/<RLIMIT_SIGPENDING>' using the same pending-signal limit carrick reports in /proc/self/limits rather than '0/0'. (4) Optionally add the NStgid/NSpid quartet (the code comment explains the deliberate omission due to pgid/sid translation; at least NStgid/NSpid are safe to add as the ns-pid). (5) The VmSize ~521GB value is the 512GB sparse mmap window leaking through host virtual_bytes — clamp/derive a realistic VmSize (e.g. from statm or summed maps) so it does not look like a 521 GB process.
- **impact:** Medium: container/security tooling greps Seccomp:/NoNewPrivs: (Docker, gVisor-aware tools, hardening checks) — absent lines read as not-confined; RSS-accounting tools that need RssAnon/RssFile (memory profilers) get nothing; SigQ 0/0 makes signal-queue-limit checks think the queue limit is zero; the 521 GB VmSize can trip RSS/VSZ sanity checks and OOM-estimation heuristics.

### `/proc/self/cwd (and root) symlinks` — missing
- **carrick:** /proc/self/exe resolves correctly (readlink -> /usr/bin/readlink, rc=0), but /proc/self/cwd -> rc=1 (ENOENT). root symlink likely also absent.
- **docker:** cwd -> / and root -> / symlinks present (readlink works); exe -> /usr/bin/<prog>.
- **implement:** Add /proc/self/cwd and /proc/self/root as readlink-able symlinks resolving to the guest's current working directory and root respectively (carrick tracks cwd for the process; reuse it). Mirror the existing /proc/self/exe handling.
- **impact:** Medium: getcwd fallbacks, shells, and tools that readlink('/proc/self/cwd') to discover the working dir (some build systems, find -L, daemons that re-chdir) get ENOENT; chroot/container introspection reading /proc/self/root also breaks.

### `/proc/self/fdinfo/ and /proc/self/fdinfo/<N>` — missing
- **carrick:** `ls /proc/self/fdinfo` -> ENOENT; `cat /proc/self/fdinfo/0` -> ENOENT. Not modeled at all.
- **docker:** `ls /proc/self/fdinfo` -> 0 1 2 3; `cat /proc/self/fdinfo/0` -> 'pos:\t0\nflags:\t0400002\nmnt_id:\t203\nino:\t5\n'. proc_pid_fdinfo(5): pos (decimal), flags (octal incl O_CLOEXEC), mnt_id (decimal), ino; plus per-type lines (eventfd-count, tfd/events/data for epoll, sigmask, clockid/ticks).
- **implement:** Add /proc/<pid>/fdinfo as a synthetic directory listing the open fds, and /proc/<pid>/fdinfo/<N> as a synthetic file rendering at minimum 'pos:\t<offset>\nflags:\t<octal status flags|access mode>\nmnt_id:\t<id>\n' from the OpenDescription (carrick already tracks offset and status_flags). Octal flags field is what callers parse (e.g. to read O_NONBLOCK/O_APPEND). proc_pid_fdinfo(5).
- **impact:** libuv/Node and some runtimes read fdinfo flags to recover an fd's O_NONBLOCK/append/access mode after inheritance; epoll-introspection and 'what is this fd pointing at' tooling. Lower frequency than fd/ but real for runtime fd-recovery.

### `/proc/self/cwd and /proc/self/root (symlinks)` — missing
- **carrick:** readlink /proc/self/cwd -> empty, ret=1 (ENOENT); /proc/self/root -> empty. Neither is handled in the readlinkat special-cases (only /proc/self/exe and /proc/self/fd/N are) nor by ProcVfs.
- **docker:** `readlink /proc/self/cwd` -> '/' (or current dir after cd); `readlink /proc/self/root` -> '/'. proc_pid(5): cwd is a symlink to the process CWD; root to its root dir.
- **implement:** Special-case /proc/{self,thread-self,curproc,this}/cwd in readlinkat to return self.cwd(), and .../root to return the guest root ('/'). lstat must report S_IFLNK. The cwd is already tracked (self.cwd() exists and is used in set_executable_identity).
- **impact:** getcwd fallbacks, tools that readlink /proc/self/cwd to log the working dir, and chroot/container introspection. Programs that lstat /proc/self/cwd to detect their root.

### `/proc/self/exe (lstat/stat of the symlink)` — wrong_structure
- **carrick:** `readlink /proc/self/exe` WORKS ('/usr/bin/readlink', resolves symlink chain). But `stat /proc/self/exe` -> ENOENT ('cannot statx'). The readlinkat handler resolves the target, yet there is no lstat/statx path that recognizes /proc/self/exe as an existing symlink, so stat() fails.
- **docker:** `stat -c '%F' /proc/self/exe` -> 'symbolic link'; readlink works.
- **implement:** Make lstat/statx of /proc/{self,thread-self,...}/exe report an existing S_IFLNK (mode 0o777, size = target length). The same magic-symlink set (exe, cwd, root, fd/N) should be lstat-able as symlinks, not just readlink-able. proc_pid(5).
- **impact:** Programs that stat /proc/self/exe before reading it (existence/type checks), Go's os.Executable on some paths, build tools and self-relocating binaries that lstat the magic link. ENOENT makes them think they have no exe link.

### `/proc/self/ns/ + /proc/self/ns/<type> (namespace symlinks)` — missing
- **carrick:** `ls /proc/self/ns` -> ENOENT; readlink of every ns symlink -> empty. Not modeled, despite carrick modeling user/pid namespaces internally (namespace::pid/user).
- **docker:** `ls -la /proc/self/ns` -> 11 symlinks: cgroup,ipc,mnt,net,pid,pid_for_children,time,time_for_children,user,uts; `readlink /proc/self/ns/net` -> 'net:[4026532822]', pid -> 'pid:[4026532820]', user -> 'user:[4026531837]'. namespaces(7): each is 'type:[inode]'.
- **implement:** Add /proc/<pid>/ns as a synthetic dir with one symlink per supported ns type; readlink returns '<type>:[<inode>]' using a stable per-ns inode (e.g. the 4026531836+ initial-ns constants for the identity ns, and a distinct stable inode once the guest unshares). carrick already knows whether pid/user ns are enabled, so it can return either the initial-ns inode or a per-instance one. namespaces(7).
- **impact:** Container tooling and setns-based code compare ns symlink targets to decide if two processes share a namespace (e.g. `readlink /proc/self/ns/pid` == `readlink /proc/1/ns/pid`); nsenter, runc/podman introspection, and unshare verification. Empty targets break same-namespace equality checks.

### `/proc/self/task/ listing + /proc/self/task/<tid>/comm` — wrong_value
- **carrick:** `ls /proc/self/task` -> ENOENT (the 'task' under the literal 'self' is not modeled; only NUMERIC /proc/<pid>/task readdir works). Separately, `cat /proc/self/task/1/comm` -> 'carrick' (WRONG; should be the exe basename like 'cat'). The numeric-pid task path resolves but the main-thread tid (ns-pid 1) does not match the registry tid, so it falls through to is_guest_process/pid_info with an empty info.comm and defaults to 'carrick' instead of using the live executable basename.
- **docker:** `ls /proc/self/task` -> the tid(s); `cat /proc/self/task/<tid>/comm` -> the process comm (e.g. 'cat'). proc_pid_task(5): one dir per thread, files mirror /proc/<pid>.
- **implement:** (1) Make 'self'/'thread-self' resolve as a path PREFIX so /proc/self/task[/...] reaches the same code as /proc/<pid>/task (parse_proc_pid_path already maps 'self' for files; the readdir/dir gating in proc.rs proc_task_dir_entries/proc_pid_dir_host_pid must accept 'self' too). (2) In synthetic_proc_pid_file, when the requested tid is the main thread (ns-pid == tgid) and no registry/host comm is found, fall back to the exe basename (process_short_name of executable_path) instead of the literal 'carrick'. proc_pid_task(5).
- **impact:** glibc pthread_getname_np / pthread_setname_np round-trips read /proc/self/task/<tid>/comm; thread-name tooling, Java/Go thread introspection, and `ls /proc/self/task`-based thread enumeration. Wrong comm ('carrick') leaks the host runtime name into guest thread names.

### `/proc/<pid>/fd (numeric-pid form of the fd directory)` — readdir_incomplete
- **carrick:** `ls /proc/1/fd` -> ENOENT. proc_pid_dir_entries (proc.rs:300) lists only cmdline/comm/stat/status/task for a numeric pid dir; 'fd' and 'fdinfo' and 'ns' are absent from PROC_PID_FILES, and there is no readdir/lookup for /proc/<pid>/fd.
- **docker:** `ls -la /proc/<pid>/fd` enumerates the process's fds (same as /proc/self/fd).
- **implement:** Extend the numeric /proc/<pid> directory to expose fd/, fdinfo/, ns/, cwd, root, exe, maps as subentries (currently only cmdline/comm/stat/status/task). Route /proc/<pid>/fd[/N] through the same fd-resolution as /proc/self/fd (proc_self_fd_number already accepts the numeric form, but the directory listing and lstat do not). proc_pid(5).
- **impact:** Tools that introspect another guest process's fds by pid (ps/lsof-like, supervisors checking a child's open fds). Also makes `ls /proc/<pid>` look implausibly bare to anything enumerating the standard per-process tree.

### `/proc/sys/kernel/ostype` — missing
- **carrick:** ENOENT.
- **docker:** `Linux\n`
- **implement:** Serve the static string `Linux\n` (proc_sys_kernel(5): ostype is a substring of /proc/version; on Linux it is always 'Linux'). Trivial constant.
- **impact:** Read by some runtime/version-detection paths and by `sysctl kernel.ostype`. Low individual impact but cheap; part of completing the kernel.* set.

### `/proc/sys/kernel/version` — missing
- **carrick:** ENOENT.
- **docker:** `#1 SMP Wed May 13 14:27:18 UTC 2026\n` (build-number + SMP + compile timestamp).
- **implement:** Serve a fixed string matching the documented format from proc_sys_kernel(5)/proc(5): starts with `#<buildnum>`, optionally `SMP`, then a date, newline-terminated. e.g. `#1 SMP PREEMPT carrick\n` or a stable timestamp. Substring of /proc/version (which carrick already synthesizes via synthetic_proc_version) — derive from that to stay consistent.
- **impact:** Read by SMP/preempt detection and `sysctl kernel.version`. Should mirror /proc/version which carrick already serves — currently inconsistent (version syscall content exists but the sysctl file does not).

### `/proc/sys/kernel/threads-max` — missing
- **carrick:** ENOENT.
- **docker:** `127760\n` (single integer, system thread ceiling).
- **implement:** Serve a single newline-terminated integer. proc_sys_kernel(5): writable min 20, max 0x3fffffff; pick a plausible static like `127760` or compute from host RAM. Runtimes (Go runtime, JVM, glibc pthread limits, some thread-pool sizers) read this to bound max thread count.
- **impact:** Thread-pool / concurrency sizing in Go runtime, JVM, and libc fall back to defaults or mis-size when ENOENT; some asserts/health checks log warnings.

### `/proc/sys/kernel/random/boot_id` — wrong_value
- **carrick:** `00000000-0000-4000-8000-000000000000\n` — present, correct UUID format, but a fixed all-zero sentinel.
- **docker:** `1c90ebea-2b18-4478-9eca-5b8ae304919a\n` — random per-boot, stable within a boot.
- **implement:** Generate a random UUIDv4 once per carrick run (per guest 'boot') and return it stably for the lifetime of that run, rather than the all-zero constant. proc_sys_kernel(5): boot_id is randomly generated at boot and constant thereafter. systemd, journald, and various 'machine session' IDs derive from boot_id; an all-zero value can collide across concurrent guests or be rejected as invalid.
- **impact:** systemd-journald and any code keying caches/sessions on boot_id will treat all carrick guests as the same boot; potential collisions and 'invalid boot id' rejections. Format is fine so most readers parse it, but the value is wrong.

### `/proc/sys/kernel/ngroups_max` — missing
- **carrick:** ENOENT.
- **docker:** `65536\n` (max supplementary groups per process).
- **implement:** Serve single newline-terminated integer. proc_sys_kernel(5): read-only upper limit on a process's group memberships. Use `65536` (modern Linux default) and keep it consistent with what getgroups/setgroups carrick enforces.
- **impact:** glibc `sysconf(_SC_NGROUPS_MAX)` and `initgroups()` read this to size their group buffer; nss/PAM and login paths allocate based on it. ENOENT -> fallback to NGROUPS_MAX compile constant (usually fine, but mismatched limits can truncate group lists).

### `/proc/sys/fs/file-max` — missing
- **carrick:** ENOENT.
- **docker:** `1634978\n` (single integer, system-wide open-file limit).
- **implement:** Serve a single newline-terminated integer (proc_sys_fs(5)). Pick a large plausible value (e.g. 1048576 or higher) consistent with the file-nr third field below. Should be >= guest RLIMIT_NOFILE ceiling.
- **impact:** Some servers (nginx worker_rlimit tuning, MySQL, Java) read file-max to validate/size fd limits and warn or cap themselves when it's missing or small. Medium.

### `/proc/sys/fs/file-nr` — missing
- **carrick:** ENOENT.
- **docker:** `544\t0\t1634978\n` — exactly THREE tab-separated fields: allocated, free, max.
- **implement:** Serve three integers separated by tabs, newline-terminated, per proc_sys_fs(5): (1) allocated file handles, (2) free file handles (usually 0 on modern kernels), (3) max (== file-max). e.g. derive allocated from carrick's open-fd bookkeeping or a static small number; field 3 must equal the file-max value served above. If naively added, getting the field COUNT/order wrong (e.g. 1 or 2 fields) is itself a wrong_structure bug — must be exactly 3 tab-separated.
- **impact:** Monitoring agents (collectd, node_exporter, Datadog) and some health checks parse file-nr's three fields; a wrong field count makes them error. Medium.

### `/proc/sys/fs/nr_open` — missing
- **carrick:** ENOENT.
- **docker:** `1048576\n`.
- **implement:** Serve `1048576\n` (single integer; proc_sys_fs(5) documents default 1048576 — the ceiling to which RLIMIT_NOFILE may be raised). Must be >= the max RLIMIT_NOFILE carrick lets a guest set via setrlimit.
- **impact:** systemd, container runtimes, and high-fd servers read nr_open before raising RLIMIT_NOFILE; if missing they may fail to raise the soft limit or use a wrong ceiling. Medium-high for servers that open many sockets.

### `/proc/sys/fs/pipe-max-size` — missing
- **carrick:** ENOENT.
- **docker:** `1048576\n`.
- **implement:** Serve a single newline-terminated integer = the max size a guest may set on a pipe via fcntl(F_SETPIPE_SZ) (pipe(7)). Use `1048576` and keep it consistent with carrick's pipe-capacity handling (carrick already tracks per-pipe capacity per task #13). Should equal the actual upper bound carrick enforces for F_SETPIPE_SZ.
- **impact:** Programs that grow pipe buffers (shells, Go's pipe pool, some build tools) read pipe-max-size to clamp F_SETPIPE_SZ requests; ENOENT -> they may attempt a too-large resize and get EPERM/EINVAL unexpectedly. Medium.

### `/proc/sys/net/core/rmem_max, wmem_max` — missing
- **carrick:** ENOENT for both.
- **docker:** `212992\n` each (single integer, max SO_RCVBUF/SO_SNDBUF).
- **implement:** Serve each as a single newline-terminated integer (212992 matches the oracle/common default). proc_sys_net(5): max socket send/recv buffer a guest may set via setsockopt(SO_SNDBUF/SO_RCVBUF). Should reflect the ceiling carrick honors when translating those setsockopts to the host.
- **impact:** High-throughput network code (Go, Java Netty, iperf, some Python servers) reads rmem_max/wmem_max to clamp buffer-size requests; ENOENT -> they may request buffers the host rejects, or fall back to conservative sizes. Medium.

### `/proc/sys/net/ipv4/ip_local_port_range` — missing
- **carrick:** ENOENT.
- **docker:** `32768\t60999\n` — exactly TWO tab-separated integers (low, high ephemeral port).
- **implement:** Serve two integers (low high) separated by a tab, newline-terminated, per proc_sys_net_ipv4(5). Use `32768\t60999` to match the oracle/common default. Getting it to one field or space-separated would be a wrong_structure bug — must be two tab-separated ints. Should reflect the ephemeral range carrick/host actually allocates from on autobind.
- **impact:** Connection-pool sizers and load-test tools (and some firewalls/observability agents) read this to estimate available ephemeral ports; a few clients (e.g. high-concurrency HTTP clients) use it to detect port exhaustion. Medium.

### `/proc/sys/net/ipv4/tcp_rmem, tcp_wmem` — missing
- **carrick:** ENOENT for both.
- **docker:** `4096\t131072\t6291456\n` and `4096\t16384\t4194304\n` — exactly THREE tab-separated ints (min, default, max).
- **implement:** Serve three tab-separated integers (min default max), newline-terminated, per proc_sys_net_ipv4(5). Match the oracle triples (tcp_rmem 4096 131072 6291456; tcp_wmem 4096 16384 4194304). Field count MUST be exactly 3 tab-separated — a 1-field value is a wrong_structure bug.
- **impact:** TCP-tuning code and benchmarks (iperf3, some Java/Go server frameworks, kernel-tuning scripts) parse the three-tuple; observability agents export it. Medium; parsers expecting 3 fields error on the wrong shape.

### `/proc/stat (btime field)` — wrong_value
- **carrick:** 'btime 0'. The cpu line structure, per-cpu count (matches ncpu), and processes/procs_running/procs_blocked/softirq lines are all structurally correct; only btime is hardcoded 0. (proc.rs:672-691.)
- **docker:** 'btime 1780265710' — boot time in seconds since the Epoch (a real, recent value). cpu/cpuN lines have 10 columns (ok in carrick), intr/ctxt/softirq counters are volatile (ok zeroed).
- **implement:** Compute btime once as (now_epoch_secs - uptime_secs) using the same boot Instant introduced for /proc/uptime, and emit it. proc_stat(5): btime is 'boot time, in seconds since the Epoch'. A plausible recent value (e.g. process-start epoch) is enough; it must be non-zero and roughly = now - uptime.
- **impact:** psutil.boot_time(), Go gopsutil, `who -b`, and tools that derive a process's wall-clock start (start_epoch = btime + starttime_jiffies/CLK_TCK) read btime. btime=0 makes every process appear to have started at 1970, breaking process-age displays and any monitoring that keys on absolute start time.

### `/proc/devices` — missing
- **carrick:** ENOENT (not in synthetic_file dispatch).
- **docker:** Present. Two sections: 'Character devices:' then 'Block devices:', each a list of '<major> <name>' lines (e.g. '  1 mem', '  5 /dev/tty', '136 pts'; block '  7 loop', '254 virtblk').
- **implement:** Add a synthetic /proc/devices that mirrors the device nodes carrick actually exposes under /dev. proc(5)/makedev usage: header 'Character devices:' then lines '%3d %s' for each char major (at minimum 1 mem, 5 /dev/tty + /dev/console + /dev/ptmx, 4 tty/ttyS, 10 misc, 136 pts, 1 mem with null/zero/random/urandom all under major 1), blank line, 'Block devices:' header (can be empty list). Keep it consistent with carrick's DevVfs.
- **impact:** MAKEDEV, udev, busybox mdev, and some installers/`mknod` wrappers parse /proc/devices to map driver names to major numbers before creating nodes. LVM/util-linux and a few test suites read it to discover the 'pts'/'misc' majors. ENOENT makes those tools fail or fall back to wrong majors.

### `/proc/vmstat` — missing
- **carrick:** ENOENT.
- **docker:** Present. Many 'key value' lines (nr_free_pages, nr_anon_pages, pgfault, pgmajfault, pgpgin/out, oom_kill, etc.).
- **implement:** Synthesize a minimal /proc/vmstat with the small set of keys real readers touch: nr_free_pages, nr_anon_pages, nr_mapped, nr_file_pages, nr_dirty, nr_writeback, pgfault, pgmajfault, pgpgin, pgpgout, pswpin, pswpout, oom_kill — each '<name> <decimal>\n'. Values may be 0/derived from host RSS; format is one token + space + integer per line.
- **impact:** Go runtime (runtime/os_linux reads pgmajfault-style stats indirectly via gopsutil), psutil.swap_memory()/vmstat, monitoring agents (node_exporter, collectd), and `vmstat -s` parse it. JVM and some GC tooling read pgmajfault. ENOENT causes psutil to raise and agents to drop the metric.

### `/proc/net/udp and /proc/net/udp6` — missing
- **carrick:** ENOENT for both.
- **docker:** Present, header-only when idle: '   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops' (udp6 wide-address variant).
- **implement:** Emit the verbatim header line; data rows optional (same passthrough caveat as tcp). The udp header has extra trailing columns (ref pointer drops) vs tcp - preserve them.
- **impact:** netstat -u, ss -u, DNS/UDP diagnostics; idle case is just the header so a headered empty file is high-fidelity.

### `/proc/net/unix` — missing
- **carrick:** ENOENT.
- **docker:** Present with header 'Num       RefCount Protocol Flags    Type St Inode Path'. proc(5): columns Num, RefCount, Protocol(0), Flags, Type, St, Inode, Path.
- **implement:** Emit the verbatim header line. carrick emulates AF_UNIX via a path registry (project_unix_socket_emulation) - could optionally list registered/bound unix sockets as rows (with Path for named ones). At minimum the header avoids ENOENT.
- **impact:** lsof, ss -x, systemd/dbus-style tooling enumerate unix sockets here; ENOENT breaks socket discovery and any test asserting the header exists.

### `/proc/net/route` — missing
- **carrick:** ENOENT.
- **docker:** Present. Header 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT' (tab-delimited), rows with addresses as native-endian hex (e.g. default route eth0 00000000 010011AC 0003 ...).
- **implement:** Synthesize the verbatim header plus a plausible default route + local subnet route. Addresses are LITTLE-ENDIAN hex of the IPv4 address. A minimal lo/eth0 default-route table (header + 1-2 rows) satisfies most parsers; derive the iface/gateway from host routing if accessible, else emit header-only.
- **impact:** Java InetAddress default-route detection, Go/Node 'find default gateway' logic, busybox route, container network probes parse this; ENOENT yields 'no route' / detection failure.

### `/proc/net/snmp` — missing
- **carrick:** ENOENT.
- **docker:** Present. Paired label/value lines for Ip:, Icmp:, IcmpMsg(optional), Tcp:, Udp:, UdpLite:. e.g. 'Ip: Forwarding DefaultTTL InReceives ... OutTransmits' then 'Ip: 1 64 0 ...'; 'Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ...' then 'Tcp: 1 200 120000 -1 0 ...'.
- **implement:** Synthesize the standard label rows with the exact column names observed (Ip/Icmp/Tcp/Udp groups, each a 'Label: names' line followed by a 'Label: values' line). Static-but-correctly-labelled zero/default values (Ip Forwarding=1 DefaultTTL=64, Tcp RtoMin=200 RtoMax=120000 MaxConn=-1) are acceptable since these are cumulative counters; the label set and pairing are what parsers require.
- **impact:** Node/Go process metrics, prometheus node_exporter netstat collector, and SNMP-style monitoring parse this by label name; ENOENT zeroes out all IP/TCP/UDP stats collectors.

### `/proc/net/netstat` — missing
- **carrick:** ENOENT.
- **docker:** Present. Two stanza pairs: 'TcpExt: <~130 names>' + values line, and 'IpExt: <names>' + values line.
- **implement:** Synthesize the TcpExt:/IpExt: label line + matching zero-value line. The names are read positionally-by-name, so emit the standard label set and zeros. (The exact TcpExt label list is long; replicate the names observed from the Docker oracle, not from kernel source.)
- **impact:** prometheus node_exporter netstat collector, ss --info fallbacks, TCP-tuning diagnostics; ENOENT drops all extended TCP/IP counters.

### `/proc/net/sockstat and /proc/net/sockstat6` — missing
- **carrick:** ENOENT for both.
- **docker:** Present. sockstat: 'sockets: used N' then 'TCP: inuse..orphan..tw..alloc..mem..', 'UDP: inuse..mem..', 'UDPLITE: inuse..', 'RAW: inuse..', 'FRAG: inuse..memory..'. sockstat6: 'TCP6: inuse N' etc.
- **implement:** Synthesize the fixed multi-line layout with the observed labels and plausible/zero counts (e.g. 'sockets: used 3', 'TCP: inuse 0 orphan 0 tw 0 alloc 0 mem 0'). Format is strictly positional per line, so labels + line order matter.
- **impact:** prometheus node_exporter sockstat collector, JVM/Go socket-pressure checks, and tools sizing connection pools from 'sockets: used'; ENOENT zeroes the collector.

### `/proc/thread-self` — missing
- **carrick:** Completely absent. `readlink /proc/thread-self` and `ls /proc/thread-self` -> ENOENT. parse_proc_pid_path() maps the STRING "thread-self" to std::process::id() for SUB-paths only (/proc/thread-self/comm would resolve), but the bare link and a top-level `ls /proc` entry are missing, and it is not in ProcVfs::readdir's static list.
- **docker:** Present as a magic symlink. `readlink /proc/thread-self` -> e.g. "8/task/8" (resolves to /proc/self/task/<tid>). Appears in `ls /proc`.
- **implement:** Add /proc/thread-self as a magic symlink whose readlink yields '<tgid>/task/<tid>' (proc(5): 'resolves to the process's own /proc/self/task/tid directory'). Use self ns-pid for tgid and current gettid/registry tid for tid. Add it to the top-level readdir list as EntryKind::Symlink. Sub-path resolution already half-works via parse_proc_pid_path.
- **impact:** Thread-aware libraries (glibc pthread introspection, some sanitizers/profilers, libuv/Go in rare paths) that resolve /proc/thread-self to find the current TID dir. Lower frequency than /proc/self but a documented standard entry that is entirely missing.

### `/proc/<pid>/task/<tid>` — wrong_value
- **carrick:** task dir name is the HOST tid (observed `ls /proc/$P/task` -> 43778) while /proc/$P/status reports `Pid: 8` and `Tgid: 8`. The tid under task/ does not equal the pid the same subtree advertises. synthetic_task_dir() for a foreign guest process returns vec![pid.to_string()] of the HOST pid; for own threads it returns raw registry tids without ns translation. proc_stat_line inside reads pid as passed.
- **docker:** For a single-threaded process the task dir contains exactly one entry whose name == the pid (tid==pid). `ls /proc/10/task` -> `10`, matching `Pid:` in status.
- **implement:** For a foreign single-threaded guest process, the task entry must be the ns-pid (host_to_ns_or_self of the host pid), so task/<tid> == the dir's own pid. For the current process's own threads, translate the main thread's registry tid to its ns-pid (== tgid) and keep worker tids consistent with what gettid() returns to the guest. Ensures /proc/<pid>/task/<pid> is the self-consistent single-thread entry Linux guarantees.
- **impact:** Thread enumerators (glibc, JVM/Go runtimes walking task/, `ls /proc/<pid>/task`, top -H) get a tid that doesn't match the process pid and can't be re-opened consistently; per-thread stat/comm lookups keyed on the listed tid may then miss.

### `/proc/<pid>/ (per-process subtree contents)` — readdir_incomplete
- **carrick:** proc_pid_dir_entries() emits only `.`,`..`,`task`,`cmdline`,`comm`,`stat`,`status` (PROC_PID_FILES = 4 files). Confirmed: every one of exe, cwd, root, fd, maps, environ is ENOENT for a foreign pid (`[ -e /proc/$P/exe ]` etc. all ENOENT). Even /proc/self/{maps,limits,statm,auxv,...} exist as synthetic_file entries but are NOT enumerated for a NUMERIC /proc/<pid> dir and are entirely absent for foreign pids.
- **docker:** readdir yields ~45 entries incl exe, cwd, root, fd, fdinfo, environ, maps, smaps, mountinfo, ns/, attr/, status, stat, statm, cmdline, comm, auxv, limits, io, wchan, oom_score, etc.
- **implement:** Broaden the per-pid model: (a) list the synthetic files we already render (maps, statm, limits, auxv) in the numeric pid dir too, not just under /proc/self; (b) add the magic symlinks exe/cwd/root and the fd/ directory for at least the self pid (exe readlink already works at the dispatcher level for /proc/self/exe — see separate finding — but is absent from readdir and for foreign pids). For foreign guest pids, surface exe/cwd via host_proc where derivable. Cite proc(5)/proc_pid(5): exe is a symlink to the executable, cwd to the cwd, fd/ holds per-fd symlinks.
- **impact:** Tools that introspect another process (ps reading cmdline is fine, but anything reading /proc/<pid>/exe, /proc/<pid>/fd, /proc/<pid>/maps, /proc/<pid>/environ — e.g. lsof, gdb attach, container runtimes, language self-inspection of children) find the files missing for non-self pids and the dir under-populated.

### `/proc/self/exe (stat/-e vs readlink)` — wrong_structure
- **carrick:** SPLIT behavior: `readlink /proc/self/exe` correctly returns the binary path (/usr/bin/readlink) and `cat /proc/self/exe` returns ELF magic 7f 45 4c 46 — so the dispatcher special-cases the readlink/open. BUT `ls -la /proc/self/exe`, `[ -e /proc/self/exe ]`, and `stat /proc/self/exe` all report ENOENT, because ProcVfs::lookup()/synthetic_file have no /proc/self/exe case (it is not a synthetic_file key). So the path is invisible to stat()/faccessat() while readable via readlink/open.
- **docker:** Symlink to the running executable. readlink, `[ -e ]`, `stat`, and open(read) all succeed; ls -la shows it as a symlink.
- **implement:** Make /proc/self/exe (and /proc/<pid>/exe) a first-class VFS symlink so lookup() returns kind: Symlink and faccessat/statx succeed, instead of only being intercepted at the readlink/open dispatcher layer. The readlink target logic already exists; reuse it for lstat. Same for cwd/root once added.
- **impact:** Programs that `access("/proc/self/exe", F_OK)` or lstat it before reading (common defensive pattern, also `test -e`, shell `[ -e ]`, some self-relocation code) wrongly conclude the binary path is unavailable even though readlink would have worked.


## LOW severity

### `/proc/self/personality` — missing
- **carrick:** ENOENT.
- **docker:** Present: '00000000' (8 hex digits, no newline).
- **implement:** Serve '00000000' (8-digit lowercase hex of the personality flags; 0 for the default ADDR/Linux personality), matching the oracle.
- **impact:** Low: tools probing execution-domain/ADDR_NO_RANDOMIZE personality (some test harnesses, gdb, setarch-style tooling) read it; ENOENT is a minor divergence but trivially fixable.

### `/proc/self/sessionid, /proc/self/loginuid` — missing
- **carrick:** Both ENOENT.
- **docker:** Present: both '4294967295' (the (uint32)-1 'unset' sentinel), no newline. loginuid is rw.
- **implement:** Serve sessionid as '4294967295' and loginuid as '4294967295' (the unset audit sentinel observed in the oracle). loginuid is technically writable; accepting+ignoring a write is enough to avoid EACCES surprises.
- **impact:** Low-medium: PAM/audit-aware tooling and login(1)/sshd-style code read loginuid; sudo and audit subsystems read both. ENOENT is usually tolerated but diverges from a real container.

### `/proc/self/timerslack_ns` — missing
- **carrick:** ENOENT.
- **docker:** Present: '50000' (default 50us slack), rw.
- **implement:** Serve '50000\n' (the observed default). Optionally accept writes (store per-process) since it is rw, but read-only is fine for parity.
- **impact:** Low: power/latency-tuning daemons and some real-time frameworks read/write it; rarely load-bearing for general workloads.

### `/proc/self/autogroup` — missing
- **carrick:** ENOENT.
- **docker:** Present: '/autogroup-NNNN nice 0'.
- **implement:** Serve '/autogroup-0 nice 0\n' (the value is volatile; structure is '/autogroup-<id> nice <n>'). Low priority.
- **impact:** Low: only scheduler-introspection/CONFIG_SCHED_AUTOGROUP-aware tools read it.

### `/proc/self/schedstat` — missing
- **carrick:** ENOENT.
- **docker:** Present: '0 0 1' (three fields: cpu-time-on-cpu ns, run-queue wait ns, timeslices run).
- **implement:** Serve a 3-field line, e.g. '0 0 1\n' (matches oracle structure; exact values are volatile). If carrick tracks per-thread on-CPU ns, populate field 1.
- **impact:** Low: scheduler-profiling tools and some latency benchmarks read it. Note /proc/self/sched returned ENOENT in the Docker oracle TOO (host kernel did not expose it in this container), so carrick's missing /proc/self/sched is NOT a divergence here.

### `/proc/self/wchan` — missing
- **carrick:** ENOENT.
- **docker:** Present: '0' (no newline) for a running task (symbolic name or 0).
- **implement:** Serve '0' (a running/on-CPU task has wchan 0). Trivial static value matching the oracle.
- **impact:** Low: ps's WCHAN column and hang-diagnosis tools read it; ENOENT just yields a blank column.

### `/proc/self/syscall` — missing
- **carrick:** ENOENT.
- **docker:** Present: '63 0x3 0xffff... ... <sp> <pc>' (syscall number + 6 arg regs + SP + PC) per proc_pid_syscall(5); 'running' when on-CPU, or '-1 <sp> <pc>' when blocked outside a syscall.
- **implement:** Hard to make truthful without live register capture. Cheapest conformant option: serve the literal 'running\n' (the documented representation for an on-CPU task) so the file is present and parseable. Avoid fabricating register values that mislead a tracer.
- **impact:** Low: mostly debuggers/strace-adjacent introspection read it; few normal workloads depend on it. Presence (even 'running') beats ENOENT for tools that stat-then-read.

### `/proc/self/{map_files,attr}` — missing
- **carrick:** Both -> ENOENT. Not modeled.
- **docker:** `ls /proc/self/map_files` -> 'addr-addr' entries (one symlink per file-backed VMA); `ls /proc/self/attr` -> current,exec,fscreate,keycreate,prev,sockcreate; `cat attr/current` -> EINVAL (no LSM).
- **implement:** Low priority. attr/ is LSM (SELinux/AppArmor) state; a reasonable stub is /proc/self/attr/current readable as 'unconfined\n' or returning the same EINVAL Docker shows, but most non-LSM workloads tolerate its absence. map_files/ duplicates /proc/self/maps info and is rarely required. Defer unless a target workload reads them. proc_pid(5).
- **impact:** AppArmor/SELinux-aware daemons read attr/current; CRIU and some profilers read map_files. Niche for carrick's current targets, hence low.

### `/proc/sys/kernel/sched_autogroup_enabled` — missing
- **carrick:** ENOENT.
- **docker:** `1\n` (0/1 toggle).
- **implement:** Serve `0\n` or `1\n` (single boolean integer; sched(7)). carrick has no autogroup scheduler, so `0` is the honest value. Low priority but trivial and part of completing kernel.*.
- **impact:** Mostly read by `sysctl -a` and a few schedulers/benchmarks; rarely load-bearing. Honest value is 0.

### `/proc/sys/kernel/overflowuid, /proc/sys/kernel/overflowgid` — missing
- **carrick:** ENOENT for both.
- **docker:** `65534\n` each (single integer).
- **implement:** Serve `65534\n` for both (proc_sys_fs(5)/proc(5): default 65534, the 'nobody' overflow id used when a uid/gid exceeds a filesystem's bit width). These kernel/ copies duplicate the fs/ copies; add fs/overflowuid and fs/overflowgid too.
- **impact:** NFS/idmap and some container uid-shift tooling read overflow ids. Low for typical workloads; cheap to add.

### `/proc/sys/vm/swappiness` — missing
- **carrick:** ENOENT.
- **docker:** `60\n` (single integer 0-200).
- **implement:** Serve `60\n` (single integer, the long-standing default). carrick has no swap, so the value is advisory; 60 matches the oracle and most distros.
- **impact:** Read by `sysctl -a`, some tuning daemons, and a few DB installers that warn on high swappiness. Low; cheap to add.

### `/proc/sys/fs/mqueue/msg_max, msgsize_max, queues_max` — missing
- **carrick:** ENOENT for all three.
- **docker:** `10\n`, `8192\n`, `256\n`.
- **implement:** Serve each as a single newline-terminated integer (msg_max=10, msgsize_max=8192, queues_max=256 per the oracle and mq_overview(7)). Must match the limits carrick enforces on mq_open/mq_send if POSIX mqueues are supported at all; if mqueues are unsupported it's acceptable to omit, but the defaults are cheap.
- **impact:** Only relevant to POSIX message-queue workloads (rare in the target runtimes); glibc's mq_* and a few RT apps read these. Low priority.

### `/proc/sys/net/ipv4/tcp_fin_timeout, tcp_keepalive_time, tcp_syncookies` — missing
- **carrick:** ENOENT for all three.
- **docker:** `60\n`, `7200\n`, `1\n` (each single integer).
- **implement:** Serve each as a single newline-terminated integer matching the oracle (tcp_fin_timeout=60, tcp_keepalive_time=7200, tcp_syncookies=1). proc_sys_net_ipv4(5). Advisory in carrick (host owns the real TCP stack), so static defaults are fine.
- **impact:** Mostly read by tuning scripts, `sysctl -a`, and a few load balancers/health checks. Low; complete the net.ipv4 set for tidiness.

### `/proc/meminfo` — wrong_fields
- **carrick:** 26 fields, structurally well-formed ('%-15s %8d kB'). Has the big three (MemTotal/MemFree/MemAvailable) + the classic set. MISSING the SReclaimable/SUnreclaim/KReclaimable breakdown, all HugePages_* / Hugepagesize lines, Active(anon)/Inactive(file) split, Unevictable, Mlocked, Percpu. Values are static (MemTotal 16777216 kB hardcoded, not tied to host RAM).
- **docker:** ~55 fields incl MemTotal/MemFree/MemAvailable (present in carrick), plus Active(anon)/Inactive(anon)/Active(file)/Inactive(file), Unevictable, Mlocked, KReclaimable, SReclaimable, SUnreclaim, Percpu, AnonHugePages, Hugepagesize, HugePages_Total/Free/Rsvd/Surp, Hugetlb, SecPageTables, Zswap.
- **implement:** Add the commonly-parsed missing lines so field-scanners don't fault: at minimum HugePages_Total/HugePages_Free/HugePages_Rsvd/HugePages_Surp (the only numeric-without-kB lines) and Hugepagesize: 2048 kB, plus SReclaimable/SUnreclaim/KReclaimable and Mlocked/Unevictable as 0. Also derive MemTotal from host physical RAM (sysctl hw.memsize) rather than the hardcoded 16 GiB so it agrees with sysinfo()/MemAvailable. proc_meminfo(5) defines all these labels.
- **impact:** Mostly tolerant readers (glibc sysconf, Go, psutil scan by label and skip absent ones). The real bites: (a) anything reading Hugepagesize (DPDK, JVM -XX:+UseLargePages, mongodb THP checks) gets a default/abort on ENOENT-of-line; (b) hardcoded MemTotal can disagree with sysinfo(2)/host, confusing memory-limit autotuning (JVM ergonomics, Node --max-old-space). Low because the parse-by-label scheme rarely hard-fails.

### `/proc/cpuinfo` — wrong_fields
- **carrick:** Same per-CPU block set and count (matches ncpu) — structurally correct and the fields runtimes parse (processor, Features, CPU implementer/part) are present. Differences: (1) carrick writes 'CPU architecture\t: 8' (extra tab) where Docker writes 'CPU architecture: 8'; (2) shorter Features list (no jscvt/fcma/sha3/i8mm/bf16/bti); (3) appends a trailing 'Hardware\t: Carrick' line Docker lacks.
- **docker:** One block per CPU: processor / BogoMIPS / Features / CPU implementer / CPU architecture / CPU variant / CPU part / CPU revision. NOTE Docker uses label 'CPU architecture:' (no tab before colon) and a long Features list (jscvt fcma sha3 sha512 i8mm bf16 bti afp ...). No trailing 'Hardware:' line on this linuxkit aarch64 kernel.
- **implement:** Drop the extra tab so it's 'CPU architecture: 8' to match the kernel's exact label (some strict parsers split on ': '). Optionally drop the trailing 'Hardware: Carrick' line (aarch64 server kernels omit it) and only advertise Features the guest can actually use. Low priority: the canonical aarch64 parse keys on 'processor' and 'Features'/'CPU implementer', which are correct.
- **impact:** Go (runtime detects CPU features from Features/HWCAP not cpuinfo), OpenSSL, numpy/OpenBLAS, and `lscpu` parse cpuinfo. The extra tab on 'CPU architecture' is cosmetically off but rarely parsed; the short Features list is conservative-correct (won't advertise an absent feature). nproc/Go count via sched_getaffinity, not this file, so count is moot. Mostly cosmetic.

### `/proc/diskstats` — wrong_value
- **carrick:** Present but EMPTY (synthetic_proc_diskstats returns b""). Also note /proc/partitions returns only the header 'major minor  #blocks  name\n\n' with no rows.
- **docker:** Present and populated: one line per block dev with 17+ fields '<major> <minor> <name> <reads> ...'.
- **implement:** Empty diskstats is mostly acceptable (no block devices in the guest), but for parity with /proc/partitions consider emitting one synthetic line for the rootfs-backing device if carrick exposes one, with 17 fields all but name/major/minor zero. proc(5) diskstats format: 'major minor devname rd_ios rd_merges rd_sectors rd_ticks wr_ios wr_merges wr_sectors wr_ticks ios_in_progress tot_ticks rq_ticks ...'. Lower priority than the others.
- **impact:** psutil.disk_io_counters() returns empty (tolerated, returns {}), iostat shows nothing. Empty is far better than ENOENT and few container workloads need it. Low.

### `/proc/{swaps,modules,misc,interrupts,softirqs,buddyinfo,zoneinfo,key-users,crypto,consoles,locks,slabinfo,kallsyms}` — missing
- **carrick:** All ENOENT.
- **docker:** All present. swaps: header + swap entries; modules: lsmod source; interrupts/softirqs: per-CPU tables; consoles: tty list; locks: file-lock table (empty body but file exists, header-less); slabinfo: 'slabinfo - version: 2.1' + table; kallsyms: '<addr> <type> <symbol>' lines.
- **implement:** Add cheap static/empty stubs for the few that programs actually probe: /proc/swaps (header line 'Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n' + no rows — swapon/-s, free, systemd read it), /proc/modules (empty body — lsmod/kmod tolerate empty), and /proc/locks (empty body — lslocks, and glibc/util-linux sometimes stat it). kallsyms can stay ENOENT (needs root to be meaningful) or emit a single '0000000000000000 D _stext' style line. crypto/zoneinfo/buddyinfo/slabinfo/interrupts/softirqs/consoles/key-users/misc are rarely read by application runtimes — leave for later.
- **impact:** swaps absence makes `free`/systemd/`swapon -s` report no swap (usually fine) but some tools (e.g. early systemd, lxc checks) error on ENOENT; modules ENOENT breaks `lsmod` and a few container-introspection tools; locks ENOENT breaks `lslocks`. The rest (crypto/zoneinfo/etc.) are diagnostic and almost never on a runtime's hot path. Low overall — emit swaps+modules+locks stubs first.

### `/proc/pressure/{cpu,memory,io}` — missing
- **carrick:** ENOENT (the /proc/pressure directory and files don't exist).
- **docker:** Present (PSI). Each: 'some avg10=.. avg60=.. avg300=.. total=..' (+ 'full ...' for memory/io).
- **implement:** Optionally synthesize static-idle PSI files: cpu -> 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n'; memory/io add a 'full ...' line. proc(5)/PSI format. Only worth it if a target workload (cgroup v2 pressure-aware schedulers, systemd-oomd, some Go/Rust schedulers) probes them; most apps treat ENOENT as 'PSI unsupported' gracefully.
- **impact:** systemd-oomd and a few cgroup-v2-aware autoscalers read PSI; on ENOENT they cleanly disable PSI-based logic, so impact is low. Skip unless a concrete consumer needs it.

### `/proc/net/ipv6_route` — missing
- **carrick:** ENOENT.
- **docker:** Present. Rows of 32-hex dest prefix, prefixlen, src, ... metric, refcnt, use, flags, iface (e.g. lo ::1/128, default). Space-delimited fixed-width hex, no header line.
- **implement:** Synthesize at least the loopback rows (::/0 + ::1/128 on lo) in the observed fixed hex layout (no header). carrick already builds if_inet6 for lo, so the corresponding ipv6_route lo rows can be emitted from the same data.
- **impact:** IPv6 default-route detection in Go/Java/Node; lower priority since most workloads use IPv4, but ENOENT breaks v6 routing probes.

### `/proc/net/arp` — missing
- **carrick:** ENOENT.
- **docker:** Present, header-only when empty: 'IP address       HW type     Flags       HW address            Mask     Device'. proc(5) columns: IP address, HW type, Flags, HW address, Mask, Device.
- **implement:** Emit the verbatim header line (Docker shows header even with an empty ARP cache). Data rows can be empty.
- **impact:** arp(8), some service-discovery and L2 tooling; idle is header-only so a headered file is faithful.

### `/proc/net/snmp6` — missing
- **carrick:** ENOENT.
- **docker:** Present. One 'Label<tab>value' line per metric (Ip6InReceives, Ip6InHdrErrors, ...). Long flat list of tab-separated label/value pairs.
- **implement:** Synthesize the flat 'Ip6...<tab><count>' label list with zeros. Lower priority (IPv6 counters); label set must match for parsers.
- **impact:** node_exporter snmp6 collector and IPv6 stats tooling; minor.

### `/proc/net/packet` — missing
- **carrick:** ENOENT.
- **docker:** Present. Header 'sk               RefCnt Type Proto  Iface R Rmem   User   Inode' plus rows for AF_PACKET sockets.
- **implement:** Emit the verbatim header line; data rows can be empty (most workloads have no AF_PACKET sockets). Low priority.
- **impact:** tcpdump/packet-capture tooling diagnostics; rarely parsed by app workloads.

### `/proc/net/raw and /proc/net/raw6` — missing
- **carrick:** ENOENT.
- **docker:** raw present, header-only when idle: '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops'.
- **implement:** Emit the verbatim header line; data rows empty. Low priority.
- **impact:** ping/raw-socket diagnostics, ss -w; idle is header-only.

### `/proc/net/dev_mcast` — missing
- **carrick:** ENOENT.
- **docker:** Present. Rows '<idx>    <iface>         <users> <global> <mac-hex>' e.g. '11   eth0            1     0     333300000001'. No header line.
- **implement:** Synthesize per-interface multicast MAC rows (the standard 333300000001 IPv6-all-nodes + 01005e000001 IPv4-all-hosts) using the same host_mc_interfaces() data that already feeds igmp/igmp6. No header line. Use Linux-plausible iface names.
- **impact:** L2 multicast diagnostics, some Go Interface.MulticastAddrs paths; minor.

### `/proc/net/igmp` — wrong_value
- **carrick:** PRESENT with the correct header and the correct native-endian group hex format - format is OK. BUG: leaks host macOS interface names (en0, lo0, utun6 observed) instead of Linux-plausible names; idx values are macOS if_nametoindex values.
- **docker:** Present. Header 'Idx<tab>Device    : Count Querier<tab>Group    Users Timer<tab>Reporter', then per-IPv4-iface block with native-endian group hex 010000E0 (=224.0.0.1). Iface names are Linux (lo, eth0).
- **implement:** Format is correct (keep it). Map host interface names to Linux-plausible names: lo0->lo, primary uplink->eth0, and drop Darwin-only pseudo-ifaces (awdl0, llw0, utunN, en0) or rename, so a guest parsing iface names does not see macOS-isms. Same mapping should feed igmp6/dev_mcast/dev.
- **impact:** Go Interface.MulticastAddrs and any code correlating iface NAME between /proc/net/dev (missing) and igmp will mismatch; cosmetic for most, but a guest that does if_nametoindex('en0') will fail since the guest has no en0 device.

### `/proc/net/igmp6` — wrong_value
- **carrick:** PRESENT, correct row format (network-order 128-bit hex, ff02..::1 / ff01..::1). Same host-name leak as igmp: emits awdl0, en0, llw0, lo0.
- **docker:** Present. Rows '<idx> <iface> <128-bit-group-hex> <users> <timer-hex> <flags>' for ff02::1 / ff01::1 per IPv6 iface. Linux iface names.
- **implement:** Keep the format; apply the same host->Linux interface-name mapping as igmp/dev. Drop Darwin pseudo-interfaces.
- **impact:** Same as igmp: name correlation across files breaks; cosmetic to most parsers but wrong for name->index lookups.

### `/proc/<pid>/status (foreign process fields)` — wrong_fields
- **carrick:** Truncated to ~9 lines: Name (often generic 'carrick' when host_proc comm is empty), State, Tgid, Pid, PPid, TracerPid, Uid, Gid, Threads. Uid/Gid show the HOST identity (501/20) not the container's 0/0. Missing the entire Vm* block, FDSize, Groups, SigQ/Sig* masks, Cpus_allowed, NStgid/NSpid quartet. Acceptable as a partial but Uid/Gid 501/20 is a semantic divergence (guest believes it is root:0).
- **docker:** Rich status: Name reflects the real comm (e.g. `sh`), State real (D/S/R/T/Z), Tgid/Pid the ns-pid, PPid the ns parent, plus Uid/Gid/FDSize/Groups/NStgid/NSpid/NSpgid/NSsid/VmPeak/VmSize/... (~50 lines).
- **implement:** For foreign guest pids, report Uid/Gid as the modeled container creds (0/0 in the default rootful container, consistent with /proc/self/status which already prints `Uid: 0`), not the raw Darwin host uid/gid from host_proc::pid_info. Optionally widen the field set (FDSize, VmSize/VmRSS, Threads from a tracked count) to reduce divergence. Self-status is already well-formed; this is the foreign-pid path only.
- **impact:** Monitoring/inspection of sibling guest processes (ps -o user, container tooling reading another pid's Uid) sees the macOS host uid 501 instead of the guest's root, which is inconsistent with that process's own getuid()==0. Low frequency but a clear semantic leak of host identity.

### `/proc top-level static entries (readdir breadth)` — readdir_incomplete
- **carrick:** readdir("/proc") emits only a representative 9: cpuinfo meminfo stat uptime loadavg version cmdline mounts filesystems (+ ., .., self, pids). MANY synthetic_file paths that DO exist when opened by name (config.gz, diskstats, partitions, sys/, net/, self/* etc.) are NOT enumerated. So `ls /proc` under-reports; opening a known-but-unlisted file still works. Missing thread-self and self-as-symlink (covered above).
- **docker:** ~60 entries: buddyinfo bus cgroups cmdline config.gz consoles cpuinfo crypto device-tree devices diskstats driver execdomains filesystems fs interrupts iomem ioports irq kallsyms kcore key-users keys kmsg kpage* loadavg locks meminfo misc modules mounts net pagetypeinfo partitions pressure scsi self softirqs stat swaps sys sysrq-trigger sysvipc thread-self timer_list tty uptime version vmallocinfo vmstat zoneinfo.
- **implement:** Emit in readdir all the top-level synthetic files actually served (config.gz, diskstats, partitions, version is there, plus the `sys`, `net` pseudo-dirs and `thread-self`/`self` symlinks). At minimum add every key in synthetic_file's top-level match arm so `ls /proc` is consistent with what open() will serve. Cite proc(5) top-level table.
- **impact:** Programs that enumerate /proc to feature-detect (e.g. check for config.gz, partitions, sys/, net/) by listing rather than direct open will not find entries that are in fact present. Mostly cosmetic since direct open works; low severity.
