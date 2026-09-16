# Ecosystem correctness and foundations checkpoint — 2026-09-15

This is an integration checkpoint on local `main`, not completion of the ecosystem goal. No push
was performed; pushing is the owner's decision.

## Landed on main (from `7142d2438`)

Group A, in-zone loopback TCP lifecycle (agy workers, director-verified, all serial MATCH):
- `6b6d94b7d`, `8d18b250e`: IPv4-mapped IPv6 connects resolve to in-zone IPv4 listeners; a `[::1]`-bound
  client connecting to a v4-mapped target gets ENETUNREACH (go-net 449/449).
- `940668bc6`: POLLHUP after drain on a closed in-zone stream (oracle-backed HUP bit).
- `ed1d29e66`: pselect6 samples in-zone descriptions before parking (asyncio TLS handshake abort).
- `28445af8c`: poll/select waits register carrick-owned descriptions host-fd-less so the wait
  service's post-enrollment probe runs (go-net_http 1316/1316).
- `54fde3e88`: in-zone listener waits carry logical interest (cpython-xmlrpc 84/84, wsgiref 36/36).
- `eb0578e11`: a refused nonblocking connect leaves the socket re-connectable (asyncio 2554/2554).
- `d8edf9f0d`, `de60a9a19`: pure INET rebind after AF_UNSPEC disconnect, IPV6_ADDRFORM oracle-backed,
  typed `PureSocketPhase` (LTP connect02 MATCH).
- `0745386ef`: oracle re-bless (438 regression-profile cpython rows + 193 refreshed go/node rows).

Group D, foundations (Claude subagents, Opus plan -> implement, director-verified):
- D2 harness (`feat/sep15-harness-budget`): typed `CarrickDeadline` provenance, `TimeoutKind::Progressing`
  from transcript growth, `Verdict::BudgetKill` (non-gating, bless-blocking), Phase 1b single-shot serial
  confirmation (900 s pool, `=0` hatch), dual-profile oracle fill from one Docker container, default-ON
  probe carrier budget (measured: steady p99.5 5.4 s, budget 60 s) with an escalating wedge capture
  (in-process post-mortem, then a detached `sudo lldb` capture from the runtime), `CARRICK_DEADLOCK_WATCHDOG_MS`
  deleted for a typed `DeadlockWindow`.
- D1 typed wait sources (`feat/sep15-wait-sources`, Tasks 1-5 of 10): one `WaitRegistration` per guest fd
  with a typed `WaitSource` (Host / Description / Dual with latch coverage), `WaitInterest` that cannot be
  empty, one `assemble_wait` behind ppoll and pselect6 with a typed `InvalidFdPolicy` (poll reports
  POLLNVAL per entry; select fails EBADF), and a generated enrollment-gap property test over every
  wait-queue-bearing description kind (red on all ten before the fusion, green after).

## Measured

Post-Group-A ecosystem run on `fea46512a` (635 rows, 8 workers, cached oracle): 629 MATCH, 0 rows
regressed from MATCH. Remaining non-MATCH: go_types/go-net/go-net_http/cpython-tarfile are 2x-oracle
budget kills under load (all MATCH serially; the harness now classifies these as BUDGET_KILL and confirms
serially), cpython-socket 23 SCTP MSG_EOR assertions (open gap), cpython-ssl TestPreHandshakeClose x2
(open, brief A5 written). 

Final run on landed `main` c8d65b9b6 (signed binary sha256 b4d306248b78f238…, entitlement and
`__dof_carrick` verified; receipts `target/conformance/sep15-ecosystem-final/`): 635/635 rows,
628 MATCH, 3 BUDGET_KILL `[progressing]` (go-net_http, cpython-multiprocessing_main_handling,
cpython-tarfile; the 900 s serial-confirmation pool was exhausted before they were confirmed, so they
stay non-gating and bless-blocking; all three MATCH when run serially), 2 DIFF (go-os_signal
TestTerminalSignal and cpython-ssl TestPreHandshakeClose, both baseline-known), 2 REGRESSION:
cpython-socket (the 23 SCTP MSG_EOR assertions) and cpython-int, whose four extra passes are CPython's
timing-gated denial-of-service tests that skip on a fast box and ran under load, a count artifact.
The harness never reported a TIMEOUT `[blocked]` for a progressing suite in this run.

## Open work, in priority order
0. Serial-confirmation pool sizing: 900 s covered 2 of 5 candidates here; raise or make it adaptive to the candidates' declared budgets (D2 follow-up).
1. A5 cpython-ssl pre-handshake close semantics (brief written: target/conformance/sep14-ecosystem/brief-tls-prehandshake-close.md).
2. cpython-socket SCTP MSG_EOR (23 tests).
3. Perf rows: go-net_http TestServerNoWriteTimeout/h2 131 s vs ~3 s; go-net 10x serial.
4. D1 Tasks 6-10: adopt the assembly in every blocking syscall (netlink.rs `raw_one(-1, 0)` is a live
   lost wake, still red-first target), epoll latch proofs, revents normalization parity, delete the
   adapters (`unclassified`), full closure.
5. D2 Task 7 owner-run: armed-budget probe gate and the ignored lldb ladder test from a terminal that is
   not the Claude Code session host (Terminal.app segfaults on an in-session lldb attach).
6. `kernelidentity` probe flake (1/3): child-exit notification to a not-live parent leaks an ERROR line
   into guest stderr (wait_wake.rs `notify_child_exit`).
7. forkstackstorm carrier spin (core in .worktrees/sep14-tcp-dualstack/target/postmortem/), unattributed;
   Group B fork-planning amplification brief.

## Operating lessons recorded in memory
Docker's VM grows to ~15 GB after oracle refreshes (restart it before builds); one workspace build at a
time with CARGO_BUILD_JOBS=4; never attach lldb to a session-descendant process (Terminal.app crashes);
run the session under tmux.
