# Go std-lib conformance — punch list (2026-05-26)

Method: `scripts/go-conformance.sh` — each Go std test binary run under carrick
(`run-elf --raw --fs host`, `-test.short`) AND under a Docker `linux/arm64`
oracle with identical args; a **carrick-only failure** = the oracle PASSes and
carrick does not. Failures that also fail on Docker are environmental and cancel.

Verdict counts and gap clusters below are from this session's runs (logs in
`/tmp/go-conformance/logs/`). Build: signed release at HEAD (ptrace BRK fix +
build-graph A1).

## GREEN — no carrick-only gaps
`sync` (47), `sync/atomic` (95), `context` (38), `time` (0 verdicts; OK),
**`runtime` (341/341)** — newly green after the guest-`BRK`→SIGTRAP fix
(`docs/ptrace-darwin-design.md` Phase 1).

## Remaining carrick-only gaps (prioritized)

### P1a — net: dup'd-fd epoll readiness — ✅ FIXED (2026-05-26)
`File()`/`FileListener` dup a socket so several guest fds share one host fd; the
epoll kqueue is keyed by host fd, so `EPOLL_CTL_DEL` of one dup deafened the
others and readiness reached only the `udata` fd. Fixed in `dispatch/net.rs`
(DEL re-binds the shared filter to a survivor; the drain fans a host-fd event out
to all interested guest fds). Regression test:
`epoll_del_of_one_dup_keeps_readiness_for_the_shared_host_socket`. The TCP
FileListener reducer is now green.

### P1b — net: Unix-domain socket path translation — ✅ FIXED (2026-05-26)
The guest→host unix path hash was one-way: `getsockname`/`getpeername`/`accept`
returned the host node `…/carrick-unix-sockets/<hash>.sock` verbatim, so `ln.Addr()`
reported it and re-dialing double-translated → ENOENT → every unix listen→dial→
accept hung. Fixed in `dispatch/net/support.rs` (host-path→guest-path registry +
reverse translation). `TestUnixConnSpecificMethods`, `TestUnixListenerSpecificMethods`,
`TestConnAndListener/unix` now PASS; the unix reducer is green. Regression test
`getsockname_returns_the_guest_unix_path_not_the_host_translation`.
**Remaining (separate, lower priority):** `unixpacket`/`SOCK_SEQPACKET` over
AF_UNIX is unsupported on macOS (the OS has no AF_UNIX SEQPACKET) — would need
emulation over SOCK_STREAM. `TestFileListener` and `TestConnAndListener` still fail
ONLY on their `unixpacket` iteration.

### P1b (original) — net: Unix-domain sockets broken
Discovered while reducing TestFileListener. A minimal reducer (`net.Listen("unix",…)`
→ Dial → Accept) **hangs** under carrick: the dial fails with
`connect: no such file or directory` on a path under
`…/carrick-unix-sockets/<hash>.sock` — carrick translates the guest's unix socket
path to a host path, but the **listener bind and the dial don't resolve to the
same host path**, so the connection never reaches the listener. Separately,
`unixpacket` (SOCK_SEQPACKET) fails to even listen: `protocol not supported`.
This single root cause explains a large cluster of net carrick-only failures/hangs:
`TestFileListener` (its unix/unixpacket iterations), `TestConnAndListener/unix`
+`/unixpacket`, `TestUnixConnSpecificMethods`, `TestUnixListenerSpecificMethods`,
`TestUnixgramServer`, and others. **Highest-leverage remaining net item.** Start
from the reducer at `/tmp/netrepro` (`plain:unix`); trace `bind`(200)/`connect`(203)
sockaddr path translation in `dispatch/net.rs`.

### P1c — net: remaining netpoll/close-unblock items
`TestPacketConn`, `TestConnAndPacketConn`, `TestFilePacketConn`, `TestFileFdBlocks`,
`TestIPConnRemoteName/SpecificMethods` — re-triage after P1b (some are unix/packet,
some may be independent). Original analysis below.

### P1 (original) — net: netpoll doesn't wake blocked socket ops
One theme explains BOTH the net hangs and most net failures: a blocked socket
operation (Accept / Read / close-notify) never gets its readiness wakeup from
carrick's netpoll for **unix, unixgram/packet, and fd-derived** sockets. Docker
passes all of these.

- **Hangs** (burn the test timeout → panic kills the whole `net.test` binary,
  making every later test look "absent" — this is what made net look wholesale
  broken; see [[project_go_conformance_state]]):
  - `TestFileListener` — `TCPListener.Accept()` on a listener built from a raw
    `*os.File` blocks forever in `runtime_pollWait` (`[IO wait]`).
  - `TestUnixgramServer` — unixgram server; blocks with a cluster of
    close/read-unblock tests live (`TestCloseUnblocksRead`, `TestCloseRead`,
    `TestPacketConnClose`, `TestListenerClose`, `TestCloseWrite`,
    `TestZeroByteRead`) → a close() doesn't unblock a blocked read/accept.
- **Failures** (same subsystem): `TestConnAndListener` (unix/unixpacket),
  `TestConnAndPacketConn`, `TestFileConn`, `TestFilePacketConn`, `TestPacketConn`,
  `TestFileFdBlocks`, `TestIPConnRemoteName`, `TestIPConnSpecificMethods`.
- **Likely root cause:** carrick's epoll/kqueue netpoll registration or
  close-notify for non-TCP-accept paths (unix, packet, fd-imported sockets).
  Relates to [[project_go_bringup]] (epoll readiness=poll(), wait=kqueue) and the
  "netpoller/scheduler race". Highest-leverage net lever — likely one fix clears
  the hangs + ~8 failures.
- **Debug entry point:** `carrick trace` the `TestFileListener` repro
  (smallest), watch `accept`/`epoll_ctl`/`epoll_pwait`/kqueue + the host fd; see
  [[project_shared_file_coherence]] is NOT this. Confirm whether the fd-derived
  listener's fd is ever registered with the netpoll.

### P2 — net: Dialer / ListenConfig Control callbacks — ✅ mostly FIXED (2026-05-26)
Root cause was NOT the Control plumbing but `setsockopt(IPPROTO_IP/IPV6, …)`
passing the Linux option NUMBER straight to macOS (different numbering) →
ENOPROTOOPT. Fixed with a comprehensive Linux→macOS IP/IPV6 sockopt translation
(`dispatch/net/support.rs`). `TestRawConnControl` PASSES; `TestDialerControl`/
`Context`/`TestListenConfigControl` now pass tcp/tcp4/tcp6/unix/udp. The ONLY
remaining failure in these is their `unixpacket` subtest → see the SEQPACKET gap.

### net: interface enumeration — ✅ COMPLETE (2026-05-26)
`getifaddrs(3)` feeds the synthetic rtnetlink (all interfaces, IPv4+IPv6, real
flags/index/prefixlen/hwaddr); `/proc/net/igmp[6]` synthesized for multicast.
TestInterfaces, TestInterfaceAddrs, TestInterfaceUnicastAddrs,
TestInterfaceMulticastAddrs, TestParseProcNet all PASS.

### net: AF_UNIX SOCK_SEQPACKET — ✅ COMPLETE for plumbing (2026-05-26)
macOS lacks AF_UNIX SEQPACKET (EPROTONOSUPPORT); backed with host SOCK_STREAM +
getsockopt(SO_TYPE) reports the guest type. TestFileListener, TestConnAndListener,
TestDialerControl, TestListenConfigControl, TestZeroByteRead PASS on unixpacket.
KNOWN LIMITATION: no message framing (true SEQPACKET boundaries) — no current test
needs it; length-prefix framing is the follow-up.

### net: ABSTRACT + autobind AF_UNIX sockets — ✅ COMPLETE (2026-05-26)
No macOS equivalent (abstract namespace is Linux-only; macOS bind → ENOENT,
autobind → EINVAL). Emulated: abstract names → an `abstract/` host subdir;
Linux-style autobind names (NUL+5hex) generated at bind; getsockname/recvfrom
reverse-translate (incl. unnamed source → AF_UNSPEC/empty, not "@"). All 6 PASS:
TestUnixAndUnixpacketServer, TestUnixgramServer, TestUnixgramAutobind,
TestUnixAutobindClose, TestUnixgramLinuxAbstractLongName,
TestReadUnixgramWithUnnamedSocket.

### net — ✅ FULLY CONFORMANT (2026-05-26)
After /etc/services (EtcServicesVfs), TestProtocolListenError (reject bind to a
trailing-'/' path), and raw sockets via CARRICK_SUDO, the full net suite has ZERO
carrick-only gaps: 238 PASS under `CARRICK_SUDO=1`, empty docker-vs-carrick diff,
no root-regressions. Unprivileged, only the 2 raw-IP tests gap (need root —
macOS has no CAP_NET_RAW; Docker grants it by default).

### cgo — ✅ WORKS (verified 2026-05-26)
Go↔C calls, C→Go callbacks, and C-pthread→Go callbacks (the hard g0/needm path)
all run under carrick matching Docker; the cgo resolver works via /etc/services.
The TestCgo* runtime tests in the SKIP list need a *runtime* C/go toolchain
(compile-on-the-fly), which the bare conformance binary lacks — they cancel on
both sides, so they're not carrick gaps. Recommend adding a cgo smoke fixture
(callbacks + C thread) to the harness for continuous coverage.

### Remaining net carrick-only gaps — fresh full diff 2026-05-26 (historical)
carrick net: **232 PASS / 6 FAIL / no crash / no timeout** (vs ~52-then-truncate
at the start of this session's net work). The 6 docker-PASS-carrick-FAIL:
- `TestCgoLookupPort`(+WithCancel), `TestReadLine` — guest can't open
  **/etc/services** (the --fs host scratch lacks it). FIX: synthesize from the
  macOS host's /etc/services (Darwin-native VFS, like resolvconf). [3 tests]
- `TestIPConnRemoteName`, `TestIPConnSpecificMethods` — **raw IP sockets** →
  EPERM (need root on macOS). Environmental/privileged.
- `TestProtocolListenError` — carrick is too lenient: a unix listen that "should
  fail" succeeded. Small real gap.
Note: `TestCgo*` is already in the harness SKIP; raw-IP needs root — so the
genuinely-actionable remainder is /etc/services (3) + TestProtocolListenError (1).
`TestSplice` no longer appears (the sendfile-family/socket fixes resolved its
path, or it now completes).

### (historical) Biggest remaining net cluster — AF_UNIX SOCK_SEQPACKET (macOS platform gap)
`unixpacket` is unsupported on macOS (no AF_UNIX SEQPACKET). This single gap is
the *sole* remaining failure in `TestFileListener`, `TestConnAndListener`,
`TestDialerControl`, `TestDialerControlContext`, `TestListenConfigControl`,
`TestUnixAndUnixpacketServer`, `TestZeroByteRead/unixpacket`, etc. No native
option; would need SEQPACKET emulation over SOCK_STREAM (message framing) — a
real feature, not a quick fix. Highest test-count cluster but highest effort.

### net: interface enumeration — needs richer rtnetlink (getifaddrs)
`TestInterfaceAddrs`, `TestInterfaceUnicastAddrs`, `TestParseProcNet` — carrick's
synthetic rtnetlink only models a loopback interface. Darwin-native path: feed
macOS `getifaddrs(3)` into the synthetic RTM_GETLINK/RTM_GETADDR responses.

### net: splice (TestSplice) — large socket-write readiness
splice EINVALs all socket↔pipe directions (impl gap) AND the read/write fallback
deadlocks a large (5 MiB) socket write — two goroutines stuck on POLLOUT-write +
EPOLLIN-read. io_wait DOES register EVFILT_WRITE, so it's a subtler large-transfer
readiness/coordination issue. Deeper netpoll investigation.

### P3 — net: interface enumeration
`TestInterfaceAddrs`, `TestInterfaceUnicastAddrs` — `getifaddrs`/`SIOCGIFCONF`
emulation. Verify whether this is a real gap vs environmental (the carrick
guest's view of host interfaces) before investing.

### Container/environment — ✅ richer now (2026-05-26)
The harness (`scripts/go-conformance.sh`) now `provision()`s the std-lib
`testdata/` trees + `/etc/services` and runs BOTH sides with the right CWD —
docker via bind-mount+`-w`, carrick via the new `run-elf -v/-w` (`--fs host` is a
sandboxed scratch, NOT the real host FS, so testdata is bind-mounted in). This
converts ~10 environmental cancels into real signal: `TestLookupStaticHost/Addr`,
`TestDNSReadConfig` now PASS under carrick.

### P4a — net: sendfile — ✅ FIXED (Darwin-native sendfile(2))
All 6 net sendfile tests pass. Root causes: VFS regular files were non-seekable
HostPipe (→ HostFile); 2 GiB buffer alloc (→ capped); userspace copy hung on
socket backpressure (→ macOS sendfile(2), in-kernel, partial-len+EAGAIN → Go
netpoll EPOLLOUT). See `dispatch/fs.rs`.

### P4b — net: splice — TestSplice still hangs
`splice(2)` (pipe↔socket) is a different syscall from sendfile and still hangs —
likely the same backpressure issue the sendfile fast-path solved, but for the
splice path. Apply an analogous Darwin approach (or pipe-buffer + nonblocking
socket write with EPOLLOUT). Next sendfile-family item.

### P4 — os/exec: signal + formatting
- `TestSIGCHLD` — child process exits status **151** (128+23 → killed by signal
  23 = SIGURG on Linux) → a SIGCHLD/async-signal delivery gap in the child.
  Medium; signal subsystem.
- `TestString` — likely `Cmd.String()` formatting; low, needs a quick look.

### Environmental / NOT carrick (do not chase)
- `net` `TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode` — **hangs identically
  on the Docker oracle** (needs reachable real DNS); now in go-conformance.sh
  SKIP. Its panic was truncating net on both sides.
- `net` `TestGoLookupIPCNAMEOrderHostsAliasesFilesOnlyMode`,
  `TestGoLookupIPOrderFallbackToFile` — FAIL on Docker too (cancel).
- `os/signal` `TestDetectNohup` — `--- SKIP` ("cannot find nohup"); environmental,
  not a carrick bug.
- Always-skipped (need infra neither side has): `TestGdb`, `TestLldb`, `TestCgo`,
  `TestTracebackSystem`.

## Suggested order
1. **P1 netpoll** (one fix, biggest payoff: clears 2–3 hangs + ~8 fails, un-hangs
   the net binary so the harness gives a complete net diff).
2. P4 `TestSIGCHLD` (signal subsystem, may relate to other signal work).
3. P2 Control callbacks, P3 interfaces (feature gaps, scope-check first).
