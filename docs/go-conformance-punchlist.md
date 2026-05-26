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

### P1 — net: netpoll doesn't wake blocked socket ops (the big one)
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
