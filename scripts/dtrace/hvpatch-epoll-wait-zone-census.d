/*
 * hvpatch-epoll-wait-zone-census.d -- could these epoll waits stay in the zone?
 *
 * QUESTION: for every guest epoll_pwait the host serves (EL1 forwards them
 * all), which descriptors does the epoll set hold, by type and by backing
 * (an in-zone object -- IPC-pool pipe/eventfd, in-memory AF_UNIX, timerfd,
 * nested epoll -- or a host-backed one: host socket/pipe/file, pidfd, host
 * inotify), what timeout did the guest pass, did the wait block, and how
 * long did a blocked waiter take from the EVFILT_USER producer edge to its
 * vCPU running again?
 *
 * WHAT IT MEASURES
 * - fd type, from the Linux syscall that created the fd (details at the
 *   "fd type map" clauses): single-fd creators by their return value at
 *   syscall-return, pipe2/socketpair by the 8-byte fd pair the service
 *   writes to guest memory, dup/dup3/fcntl(F_DUPFD*) by copying the source.
 *   Backing: eventfd/epoll/timerfd and pipe2 are carrick-owned (IPC pool or
 *   kernel object), socketpair/inet are host sockets, others are "unknown"
 *   unless an out-of-line `event_ring_host_fd` call says so. Fork-inherited
 *   fds resolve through the parent's map (two levels) at lookup time.
 * - epoll sets: epoll-ctl ADD/DEL keeps per (Linux pid, epfd) counts of
 *   in-zone, host-backed and unknown members. Each epoll_pwait is classed at
 *   service-begin as zone-only / host-only / mixed / unknown-member / empty,
 *   by timeout (0, finite, infinite) and by epoll-result kind (0 returned,
 *   1 blocked on the instance kqueue, 2 blocked masked/empty).
 * - wake path, keyed on exact ThreadSerial: hvpatch-lease-settle kind 2
 *   (BlockedContinuation) after an epoll_pwait service on that host thread =
 *   the park; hvpatch-scheduler-wake (kind 0, state Blocked) = the wake;
 *   hvpatch-executor-claim = an executor took the thread; the next
 *   vcpu-run-enter on that host thread = guest running again. The producer
 *   edge is `Kqueue::wake_parked` (pid provider), classified by what the
 *   producing host thread was doing: inside `HostIpc::service_host_wake`
 *   (an EL1-served pipe/eventfd change delivered at a host boundary) or
 *   inside a forwarded write/close service. Producer-to-wake attribution
 *   uses the most recent wake_parked since the park (global, not per
 *   kqueue): with several concurrent waiters it is approximate.
 * - forwarded read/write by fd type (served-in-EL1 calls never reach the
 *   host; pair with CARRICK_EL1_CENSUS for exact served counts).
 *
 * PROVIDER ABI (source-qualified against crates/carrick-observability/src/
 * probes.rs at 313a1ab00; live-qualified on that signed artifact 2026-10-01,
 * see docs/perf-results/2026-10-01-el1-real-workload-ab/node-epoll-wait.md):
 * - hvpatch-syscall-service-begin: arg0 i32 Linux pid, arg1 i32 Linux tid,
 *   arg2 u32 ASID, arg3 u64 syscall number.
 * - hvpatch-syscall-args: arg0 u64 nr, arg1..arg4 guest arg0..arg3; fires
 *   right after service-begin on the same host thread.
 * - hvpatch-guest-lifecycle: arg0 phase (1 fork), arg1 pid, arg2 ppid.
 * - epoll-ctl: arg0 epfd, arg1 op, arg2 fd, arg3 events, arg4 data, arg5 errno.
 * - epoll-result: arg0 epfd, arg1 ready, arg2 wait, arg3 timeout ms, arg4 kind.
 * - hvpatch-executor-claim: arg0 TaskSerial, arg1 ThreadSerial, arg2 executor.
 * - hvpatch-scheduler-wake: arg0 ThreadSerial, arg1 kind (0 wake),
 *   arg2 state found (4 Blocked).
 * - hvpatch-lease-settle: arg0 ThreadSerial, arg1 kind (2 BlockedContinuation).
 * - vcpu-run-enter: arg0 HVF vcpu id.
 * - syscall-return: arg0 nr, arg2 retval. Fires AFTER service-clear on the
 *   same host thread (live-qualified), so it is joined on self->nr.
 * - pid$target::*write_bytes*: (self, guest addr, host ptr, len); the
 *   Aarch64EngineCore GuestMemory::write_bytes_raw carries pipe2/socketpair
 *   output.
 * - pid$target::*event_ring*rec* minus every rec_* sibling (strstr filter on
 *   the demangled probefunc): arg0 kind (10 FDCLOSE), arg1 fd. FDOPEN (9)
 *   is inlined into the install helpers and never fires.
 * - pid$target::*EpollKqueue*wake_parked* (EVFILT_USER trigger),
 *   *HostIpc*service_host_wake*, *el1_delegation*settle_el1_boundary*.
 * - D quirk: carrick trace's libdtrace compile (DTRACE_C_PSPEC) rejects
 *   top-level associative-array declarations; arrays are typed by zero
 *   stores in BEGIN instead.
 * `$target` is the single HVPatch carrier (no guest fork makes a host child).
 * carrick trace compiles with DTRACE_C_ZDEFS: a pid-provider description that
 * matches nothing is silent, so the END block fails closed when the fd-type
 * hooks, the epoll probes or wake_parked never fired.
 *
 * PERTURBATION: HIGH. The event_ring::rec pid probe traps on every ring
 * record (epoll edges included), plus one trap per write_bytes, wake_parked
 * and settle_el1_boundary; the node message-port shard ran 7-40 s traced
 * against ~4-6 s untraced on the same shared host. Aggregations only.
 * Membership and fd-type counts are authoritative; epoll_pwait counts move
 * with timing (timeout=0 polls); latencies and CPU only suggest.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/hvpatch-epoll-wait-zone-census.d \
 *     --trace-out <out> -- run --fs host <image> ...
 * Bound: exits after BOUND_SECONDS (edit inline) or within a second of the
 * guest root process's exit (hvpatch-guest-lifecycle phase 5).
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=16m
#pragma D option dynvarsize=128m
#pragma D option switchrate=10hz

inline int BOUND_SECONDS = 240;

/* fd type codes (fdkind values; 0 = no entry) */
inline int K_EVENTFD = 1;
inline int K_PIPE = 2;
inline int K_UNIXPAIR = 3;
inline int K_UNIX = 4;
inline int K_INET = 5;
inline int K_ACCEPTED = 6;
inline int K_TIMERFD = 7;
inline int K_INOTIFY = 8;
inline int K_EPOLL = 9;
inline int K_FILE = 10;
inline int K_SIGNALFD = 11;
inline int K_PIDFD = 12;
inline int K_OTHER = 13;
inline int K_UNKNOWN = 14;

/*
 * Associative arrays are typed by the zero stores in BEGIN rather than by
 * top-level declarations, which carrick trace's libdtrace compile
 * (DTRACE_C_PSPEC) rejects. fd keys pack (Linux pid << 32 | fd); epoll
 * membership keys pack (pid << 40 | epfd << 20 | fd).
 */

dtrace:::BEGIN
{
    secs = 0;
    exit_seen = 0;
    root_pid = -1;
    fdopens = 0;
    fdcloses = 0;
    ctls = 0;
    results = 0;
    wps = 0;
    last_wp_ts = 0;
    last_wp_src = 0;
    fdkind[(uint64_t)0] = 0;
    fdhost[(uint64_t)0] = 0;
    parent[0] = 0;
    member[(uint64_t)0] = 0;
    zone_n[(uint64_t)0] = 0;
    host_n[(uint64_t)0] = 0;
    unk_n[(uint64_t)0] = 0;
    park_ts[arg0] = 0;
    park_comp[arg0] = "";
    wake_ts[arg0] = 0;
    wake_src[arg0] = "";
    kname[0] = "none";
    kname[1] = "eventfd";
    kname[2] = "pipe";
    kname[3] = "unix-socketpair";
    kname[4] = "unix-socket";
    kname[5] = "inet-socket";
    kname[6] = "accepted-socket";
    kname[7] = "timerfd";
    kname[8] = "inotify";
    kname[9] = "epoll";
    kname[10] = "file";
    kname[11] = "signalfd";
    kname[12] = "pidfd";
    kname[13] = "other";
    kname[14] = "unknown";
    printf("EWZ1|begin|wall=%Y|bound_s=%d\n", walltimestamp, BOUND_SECONDS);
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 1/
{
    parent[(int)arg1] = (int)arg2;
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->lpid = (int)arg0;
    self->ltid = (int)arg1;
    self->nr = arg3;
    self->in_service = 1;
    self->a0 = 0;
    self->a1 = 0;
    self->a3 = 0;
    self->hfd = -1;
    self->hfd_seen = 0;
    self->pair_done = 0;
    @service[arg3] = count();
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && self->in_service && arg0 == self->nr/
{
    self->a0 = arg1;
    self->a1 = arg2;
    self->a3 = arg4;
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && self->in_service/
{
    self->in_service = 0;
}

/* ---- fd type map ---------------------------------------------------- */

/*
 * The creating syscall names the type. The event ring's FDOPEN record is
 * inlined into the install helpers (pid provider cannot see it; FDCLOSE at
 * close_dup is an out-of-line call and does fire), so:
 * - single-fd creators: the Linux return value at syscall-return (which
 *   fires AFTER service-clear on the same host thread, so it is joined on
 *   self->nr, not self->in_service), with the backing from
 *   `event_ring_host_fd`'s return earlier in the same service when that
 *   call is out of line (-1 = in-zone description; it is inlined into the
 *   install helpers in the 313a1ab00 build, so backing is then "unknown"
 *   and is read from the type: eventfd/pipe are IPC-pool objects);
 * - pipe2/socketpair: the 8-byte LinuxFdPair the service writes to guest
 *   memory through GuestMemory::write_bytes* (arg2 host pointer, arg3 len).
 */
pid$target::*fd_helpers*event_ring_host_fd*:return
/self->in_service/
{
    self->hfd = (int)arg1;
    self->hfd_seen = 1;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == self->nr && (int64_t)arg2 >= 0 &&
 (arg0 == 19 || arg0 == 198 || arg0 == 202 || arg0 == 242 || arg0 == 85 ||
  arg0 == 26 || arg0 == 20 || arg0 == 56 || arg0 == 74 || arg0 == 434 ||
  arg0 == 23 || arg0 == 24 || arg0 == 25)/
{
    this->nr = arg0;
    this->k =
        this->nr == 19 ? K_EVENTFD :
        this->nr == 198 ? (self->a0 == 1 ? K_UNIX : K_INET) :
        (this->nr == 202 || this->nr == 242) ? K_ACCEPTED :
        this->nr == 85 ? K_TIMERFD :
        this->nr == 26 ? K_INOTIFY :
        this->nr == 20 ? K_EPOLL :
        this->nr == 56 ? K_FILE :
        this->nr == 74 ? K_SIGNALFD :
        this->nr == 434 ? K_PIDFD : -1;
    /* dup family (and fcntl F_DUPFD*): copy the source fd's type/backing. */
    this->dupe = this->k == -1;
    this->skey = ((uint64_t)(self->lpid) << 32) | (uint32_t)((int)self->a0);
    this->pkey = ((uint64_t)(parent[self->lpid]) << 32) | (uint32_t)((int)self->a0);
    this->sk = fdkind[this->skey] != 0 ? fdkind[this->skey] : fdkind[this->pkey];
    this->sh = fdkind[this->skey] != 0 ? fdhost[this->skey] : fdhost[this->pkey];
    /* fcntl other than F_DUPFD(0)/F_DUPFD_CLOEXEC(1030) returns no fd. */
    this->skip = this->nr == 25 && self->a1 != 0 && self->a1 != 1030;
    this->k = this->dupe ? (this->sk != 0 ? this->sk : K_UNKNOWN) : this->k;
    /* Backing by type when event_ring_host_fd was not observed: eventfd,
       epoll and timerfd descriptions are carrick-owned (eventfd = IPC-pool
       object, fd_table.rs EventFdState); inet/accepted sockets are host. */
    this->typed = (this->k == K_EVENTFD || this->k == K_EPOLL || this->k == K_TIMERFD) ? 1 :
        (this->k == K_INET || this->k == K_ACCEPTED) ? 2 : 0;
    this->h = this->dupe ? this->sh : (self->hfd_seen ? (self->hfd >= 0 ? 2 : 1) : this->typed);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == self->nr && (int64_t)arg2 >= 0 &&
 (arg0 == 19 || arg0 == 198 || arg0 == 202 || arg0 == 242 || arg0 == 85 ||
  arg0 == 26 || arg0 == 20 || arg0 == 56 || arg0 == 74 || arg0 == 434 ||
  arg0 == 23 || arg0 == 24 || arg0 == 25) && !this->skip/
{
    fdopens++;
    this->key = ((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg2);
    fdkind[this->key] = this->k;
    fdhost[this->key] = this->h;
    @fdopen[kname[this->k], this->h == 2 ? "host" : this->h == 1 ? "zone" : "unknown"] = count();
}

pid$target::*write_bytes*:entry
/self->in_service && (self->nr == 59 || self->nr == 199) && arg3 == 8 && !self->pair_done/
{
    self->pair_done = 1;
    this->pair = (int *)copyin(arg2, 8);
    fdopens += 2;
    this->k = self->nr == 59 ? K_PIPE : K_UNIXPAIR;
    /* pipe2 builds IPC-pool PipeReader/PipeWriter (fs/pipe.rs); socketpair
       builds two HostSocket descriptions (net/lifecycle.rs). */
    this->h = self->nr == 59 ? 1 : 2;
    fdkind[((uint64_t)(self->lpid) << 32) | (uint32_t)this->pair[0]] = this->k;
    fdhost[((uint64_t)(self->lpid) << 32) | (uint32_t)this->pair[0]] = this->h;
    fdkind[((uint64_t)(self->lpid) << 32) | (uint32_t)this->pair[1]] = this->k;
    fdhost[((uint64_t)(self->lpid) << 32) | (uint32_t)this->pair[1]] = this->h;
    @fdopen[kname[this->k], this->h == 2 ? "host" : "zone"] = count();
    @fdopen[kname[this->k], this->h == 2 ? "host" : "zone"] = count();
}

pid$target::*event_ring*rec*:entry
/strstr(probefunc, "rec_") == NULL && arg0 == 10 && self->in_service/
{
    fdcloses++;
    fdkind[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg1)] = 0;
    fdhost[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg1)] = 0;
}

/* ---- epoll set composition ------------------------------------------ */

carrick*:::epoll-ctl
/(pid == $target || progenyof($target)) && self->in_service && arg5 == 0/
{
    ctls++;
    this->fd = (int)arg2;
    this->pp = parent[self->lpid];
    this->k = fdkind[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->fd)];
    this->h = fdhost[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->fd)];
    this->k2 = fdkind[((uint64_t)(this->pp) << 32) | (uint32_t)(this->fd)];
    this->h2 = fdhost[((uint64_t)(this->pp) << 32) | (uint32_t)(this->fd)];
    this->k3 = fdkind[((uint64_t)(parent[this->pp]) << 32) | (uint32_t)(this->fd)];
    this->h3 = fdhost[((uint64_t)(parent[this->pp]) << 32) | (uint32_t)(this->fd)];
    this->h = this->k != 0 ? this->h : (this->k2 != 0 ? this->h2 : this->h3);
    this->k = this->k != 0 ? this->k : (this->k2 != 0 ? this->k2 :
        (this->k3 != 0 ? this->k3 : K_UNKNOWN));
    /* member class: 1 zone, 2 host, 3 unknown */
    this->cls = this->k == K_UNKNOWN ? 3 : this->h;
    @ctl[arg1 == 1 ? "add" : arg1 == 2 ? "del" : "mod", kname[this->k],
        this->cls == 1 ? "zone" : this->cls == 2 ? "host" : "unknown"] = count();
}

carrick*:::epoll-ctl
/(pid == $target || progenyof($target)) && self->in_service && arg5 == 0 && arg1 == 1/
{
    member[((uint64_t)(self->lpid) << 40) | ((uint64_t)(uint32_t)((int)arg0) << 20) | (uint32_t)((int)arg2)] = this->cls;
    zone_n[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg0)] += this->cls == 1 ? 1 : 0;
    host_n[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg0)] += this->cls == 2 ? 1 : 0;
    unk_n[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg0)] += this->cls == 3 ? 1 : 0;
}

carrick*:::epoll-ctl
/(pid == $target || progenyof($target)) && self->in_service && arg5 == 0 && arg1 == 2 &&
 member[((uint64_t)(self->lpid) << 40) | ((uint64_t)(uint32_t)((int)arg0) << 20) | (uint32_t)((int)arg2)] != 0/
{
    this->m = member[((uint64_t)(self->lpid) << 40) | ((uint64_t)(uint32_t)((int)arg0) << 20) | (uint32_t)((int)arg2)];
    zone_n[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg0)] -= this->m == 1 ? 1 : 0;
    host_n[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg0)] -= this->m == 2 ? 1 : 0;
    unk_n[((uint64_t)(self->lpid) << 32) | (uint32_t)((int)arg0)] -= this->m == 3 ? 1 : 0;
    member[((uint64_t)(self->lpid) << 40) | ((uint64_t)(uint32_t)((int)arg0) << 20) | (uint32_t)((int)arg2)] = 0;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && self->in_service && arg0 == 22/
{
    this->ep = (int)arg1;
    this->z = zone_n[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->ep)];
    this->hh = host_n[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->ep)];
    this->u = unk_n[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->ep)];
    self->comp =
        (this->z == 0 && this->hh == 0 && this->u == 0) ? "empty-or-untracked" :
        this->u > 0 ? "has-unknown" :
        this->hh == 0 ? "zone-only" :
        this->z == 0 ? "host-only" : "mixed";
    this->to = (int)arg4;
    self->tclass = this->to == 0 ? "timeout=0" : this->to < 0 ? "timeout=inf" : "timeout>0";
    self->ep_pending = 1;
    @pwait[self->comp, self->tclass] = count();
}

carrick*:::epoll-result
/(pid == $target || progenyof($target)) && self->ep_pending/
{
    results++;
    @pwait_result[self->comp, self->tclass,
        arg4 == 0 ? (arg1 > 0 ? "returned-ready" : "returned-empty") :
        arg4 == 1 ? "blocked-kqueue" : "blocked-masked-or-empty"] = count();
    self->ep_blocking = arg4 != 0;
    self->ep_pending = 0;
}

/* ---- forwarded read/write by fd type -------------------------------- */

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && self->in_service && (arg0 == 63 || arg0 == 64)/
{
    this->fd = (int)arg1;
    this->k = fdkind[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->fd)];
    this->h = fdhost[((uint64_t)(self->lpid) << 32) | (uint32_t)(this->fd)];
    this->k2 = fdkind[((uint64_t)(parent[self->lpid]) << 32) | (uint32_t)(this->fd)];
    this->h = this->k != 0 ? this->h : fdhost[((uint64_t)(parent[self->lpid]) << 32) | (uint32_t)(this->fd)];
    this->k = this->k != 0 ? this->k : (this->k2 != 0 ? this->k2 : K_UNKNOWN);
    @fwd_rw[arg0 == 63 ? "read" : "write", kname[this->k],
        this->h == 1 ? "zone" : this->h == 2 ? "host" : "unknown"] = count();
    self->fwd_write_kind = arg0 == 64 ? this->k : 0;
}

/* ---- wake path ------------------------------------------------------- */

carrick*:::hvpatch-executor-claim
/pid == $target || progenyof($target)/
{
    self->claim_serial = arg1;
    self->claim_ts = timestamp;
}

carrick*:::hvpatch-lease-settle
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    @settle_blocked[self->nr == 22 ? "epoll_pwait" : "other"] = count();
}

carrick*:::hvpatch-lease-settle
/(pid == $target || progenyof($target)) && arg1 == 2 && self->nr == 22 && self->ep_blocking/
{
    park_ts[arg0] = timestamp;
    park_comp[arg0] = self->comp;
    self->ep_blocking = 0;
}

pid$target::*HostIpc*service_host_wake*:entry
{
    self->in_host_wake = 1;
    self->hw_vts = vtimestamp;
    @host_wake_calls = count();
}

pid$target::*HostIpc*service_host_wake*:return
/self->hw_vts/
{
    @host_wake_cpu_ns["service_host_wake"] = avg(vtimestamp - self->hw_vts);
    @host_wake_cpu_sum["service_host_wake"] = sum(vtimestamp - self->hw_vts);
    self->in_host_wake = 0;
    self->hw_vts = 0;
}

/* The host side of every EL1 boundary: consume the served/pending flags and
   drain the owed-wake index (el1_delegation.rs settle_el1_boundary). */
pid$target::*el1_delegation*settle_el1_boundary*:entry
/self->sb_vts == 0/
{
    self->sb_vts = vtimestamp;
    self->sb_fn = probefunc;
}

pid$target::*el1_delegation*settle_el1_boundary*:return
/self->sb_vts && probefunc == self->sb_fn/
{
    @host_wake_cpu_ns["settle_el1_boundary"] = avg(vtimestamp - self->sb_vts);
    @host_wake_cpu_sum["settle_el1_boundary"] = sum(vtimestamp - self->sb_vts);
    @settle_calls = count();
    self->sb_vts = 0;
}

pid$target::*Kqueue*wake_parked*:entry
{
    wps++;
    this->src = self->in_host_wake ? 1 :
        (self->in_service && self->nr == 64) ? 2 :
        (self->in_service && self->nr == 57) ? 3 :
        self->in_service ? 4 : 5;
    @wake_parked_src[this->src == 1 ? "el1-owed-ipc-wake" :
        this->src == 2 ? "forwarded-write" :
        this->src == 3 ? "forwarded-close" :
        this->src == 4 ? "other-forwarded-syscall" : "outside-service"] = count();
    last_wp_ts = timestamp;
    last_wp_src = this->src;
}

carrick*:::hvpatch-scheduler-wake
/(pid == $target || progenyof($target)) && arg1 == 0 && arg2 == 4 && park_ts[arg0] != 0/
{
    wake_ts[arg0] = timestamp;
    this->parked = timestamp - park_ts[arg0];
    this->srcname = last_wp_ts > park_ts[arg0] ?
        (last_wp_src == 1 ? "el1-owed-ipc-wake" :
         last_wp_src == 2 ? "forwarded-write" :
         last_wp_src == 3 ? "forwarded-close" :
         last_wp_src == 4 ? "other-forwarded-syscall" : "outside-service") :
        "no-wake-parked-since-park";
    wake_src[arg0] = this->srcname;
    @parked_us[park_comp[arg0]] = quantize(this->parked / 1000);
    @woken_by[park_comp[arg0], this->srcname] = count();
}

carrick*:::hvpatch-scheduler-wake
/(pid == $target || progenyof($target)) && arg1 == 0 && arg2 == 4 && park_ts[arg0] != 0 &&
 last_wp_ts > park_ts[arg0] && timestamp > last_wp_ts/
{
    /* last_wp_ts is a racy global: re-read once and clamp, since another
       CPU may advance it between the predicate and this action. */
    this->wp = last_wp_ts;
    this->d = timestamp > this->wp ? (timestamp - this->wp) / 1000 : 0;
    @producer_to_wake_us[wake_src[arg0]] = quantize(this->d);
    @producer_to_wake_avg[wake_src[arg0]] = avg(this->d);
    park_ts[arg0] = 0;
}

carrick*:::hvpatch-scheduler-wake
/(pid == $target || progenyof($target)) && arg1 == 0 && arg2 == 4 && park_ts[arg0] != 0/
{
    park_ts[arg0] = 0;
}

carrick*:::hvpatch-executor-claim
/(pid == $target || progenyof($target)) && wake_ts[arg1] != 0/
{
    @wake_to_claim_us[wake_src[arg1]] = quantize((timestamp - wake_ts[arg1]) / 1000);
    self->resume_serial = arg1;
    self->resume_wake_ts = wake_ts[arg1];
    wake_ts[arg1] = 0;
}

carrick*:::vcpu-run-enter
/(pid == $target || progenyof($target)) && self->resume_serial != 0/
{
    this->lat = (timestamp - self->resume_wake_ts) / 1000;
    @wake_to_run_us[wake_src[self->resume_serial]] = quantize(this->lat);
    @wake_to_run_avg[wake_src[self->resume_serial]] = avg(this->lat);
    @wake_to_run_n[wake_src[self->resume_serial]] = count();
    self->resume_serial = 0;
}

/* ---- bound and receipts --------------------------------------------- */

/*
 * Terminate on the guest root process's exit (lifecycle phase 0 names it,
 * phase 5 retires it), not on proc:::exit of $target: the traced host
 * process can exit long before the workload is done.
 */
carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 0/
{
    root_pid = (int)arg1;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 5 && (int)arg1 == root_pid/
{
    exit_seen = 1;
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= BOUND_SECONDS || (exit_seen && secs > 0)/
{
    exit(0);
}

dtrace:::END
{
    printf("EWZ1|receipt|secs=%d|fdclose=%d|fdopen=%d|epoll_ctl=%d|epoll_result=%d|wake_parked=%d\n",
        secs, fdcloses, fdopens, ctls, results, wps);
    printf("EWZ1|verdict|%s\n",
        (fdopens > 0 && ctls > 0 && results > 0 && wps > 0) ? "ok" :
        "FAILED: a required probe family never fired (pid-provider symbol missing?)");
    printf("\n== host services by Linux nr ==\n");
    printa("svc nr=%d %@d\n", @service);
    printf("\n== fd installs by type/backing ==\n");
    printa("fdopen %-16s %-5s %@d\n", @fdopen);
    printf("\n== epoll_ctl by op/type/backing ==\n");
    printa("ctl %-4s %-16s %-8s %@d\n", @ctl);
    printf("\n== epoll_pwait by set composition/timeout ==\n");
    printa("pwait %-20s %-12s %@d\n", @pwait);
    printa("pwait-result %-20s %-12s %-24s %@d\n", @pwait_result);
    printf("\n== forwarded read/write by fd type ==\n");
    printa("fwd %-5s %-16s %-8s %@d\n", @fwd_rw);
    printf("\n== blocked-continuation settles ==\n");
    printa("settle-blocked %-12s %@d\n", @settle_blocked);
    printa("service_host_wake calls %@d\n", @host_wake_calls);
    printa("settle_el1_boundary calls %@d\n", @settle_calls);
    printa("cpu ns avg %-22s %@d\n", @host_wake_cpu_ns);
    printa("cpu ns sum %-22s %@d\n", @host_wake_cpu_sum);
    printa("wake_parked src %-24s %@d\n", @wake_parked_src);
    printa("woken %-20s %-26s %@d\n", @woken_by);
    printf("\n== latencies (us) ==\n");
    printa("producer->sched-wake avg %-26s %@d\n", @producer_to_wake_avg);
    printa("sched-wake->vcpu-run avg %-26s %@d\n", @wake_to_run_avg);
    printa("sched-wake->vcpu-run n %-26s %@d\n", @wake_to_run_n);
    printa("parked_us %s%@d\n", @parked_us);
    printa("producer_to_wake_us %s%@d\n", @producer_to_wake_us);
    printa("wake_to_claim_us %s%@d\n", @wake_to_claim_us);
    printa("wake_to_run_us %s%@d\n", @wake_to_run_us);
}
