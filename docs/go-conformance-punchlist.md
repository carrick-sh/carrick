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

### P1b — net: Unix-domain sockets broken (NEW — the big remaining net lever)
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

### P2 — net: Dialer / ListenConfig Control callbacks
`TestDialerControl`, `TestDialerControlContext`, `TestListenConfigControl` — the
`Control func(network, address string, c syscall.RawConn) error` hook (raw-fd
setsockopt before bind/connect). A feature gap in `RawConn.Control` plumbing.

### P3 — net: interface enumeration
`TestInterfaceAddrs`, `TestInterfaceUnicastAddrs` — `getifaddrs`/`SIOCGIFCONF`
emulation. Verify whether this is a real gap vs environmental (the carrick
guest's view of host interfaces) before investing.

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
