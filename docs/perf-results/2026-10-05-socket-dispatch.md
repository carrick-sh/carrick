# Deterministic connection notification scope

Contract: `kernel.net.connect-wake-scope`. Starting revision: `51bfe67f4`.
Original failure: `/tmp/inv-pr2-evidence/kernel-semantics.log`, where
`socket_close::tcp_peer_shut_wr_live_peer_handshake` completed its Linux
assertions but dispatched `epoll_pwait` three times instead of two.

## Root cause

This loopback TCP pair is owned in-zone. The host socket reserves the listener
port, but Carrick's connect path publishes a `PureSocketInner` server half via
`InZoneAdmission::enqueue`. Enqueue releases the queue lock and wakes the
listener. The acceptor can now accept the server half, create an epoll, register
RDHUP, drain the ctl wake, check readiness, and return `WaitOnFds`.

The connector formerly called `notify_inmem_epoll` after enqueue. Fork shares
that registry, so the broadcast could include the acceptor's newly created
epoll. The reactor then observed the epoll's user-wake fd as readable and
published `Ready`. Resuming the continuation redispatched `epoll_pwait`, which
drained the wake and found no RDHUP. It parked again. Peer SHUT_WR finally
produced the third dispatch. If connect finished its broadcast before the
acceptor's initial drain, the same test took only two dispatches. Load changes
the available ordering; it is not the correctness criterion.

The driver handshake `await_parked(1, "epoll_pwait")` orders SHUT_WR after
enrollment, but does not order connect's final notification before that
enrollment. Adding a test handshake would hide the unnecessary kernel wake.

## Dispatch-entry audit

- The initial epoll dispatch drains its ctl/user wakes, recomputes readiness,
  and builds a wait when RDHUP is absent. Another publication after this drain
  can make the host poll fd readable.
- Continuation enrollment installs exact file-slot and description-queue
  subscriptions. Those callbacks can publish `Ready`; slot invalidation and
  genuine target changes can legitimately require recomputation. This scenario
  closes neither the epoll nor its watched socket before completion.
- The reactor publishes `Ready` for nonzero fd `revents`. It does not
  distinguish an epoll user-wake from a guest-ready event. The connector's
  unrelated cohort broadcast therefore reaches the normal redispatch path.
- A host `poll` EINTR restarts the reactor, without dispatching the guest.
  A spurious host-thread unpark only repolls the pending future. Neither is
  independently a syscall redispatch.
- The driver wall watchdog reports failure; it does not retry. A guest epoll
  timeout returns zero, contradicting this fixture's `ret(1)` assertion rather
  than adding a successful third dispatch. The child stays live, so SIGCHLD
  cannot explain this wake. An ignored signal does not restart this fixture.
- Peer shutdown publishes write-closed/FIN state before notifying the peer's
  wait queue. Its RDHUP and EOF observations are stable while the control pipe
  retains the live peer. There is no socket EAGAIN loop in the empty-data FIN
  completion.

## Correction and witness

Fresh connect and reconnect now notify only the connecting description's epoll
owners. Listener enqueue retains its targeted readiness notification. No guest
timeout, driver count, retry policy, or expected dispatch budget changes.

`connect_publication_does_not_wake_a_newly_accepted_rdhup_wait` holds connect
synchronously inside its listener wake callback. A distinct forked kernel task
accepts, registers RDHUP and builds its wait before the callback releases
connect's final notification. The witness uses neither sleeps nor load. On
the pre-fix path its exact zero poll-readiness assertion fails with `1 != 0`
(exit 101): the unnecessary notification would cause the extra dispatch. It
also checks that a pre-connect client epoll becomes writable and that SHUT_WR
reports RDHUP, registered event data and EOF with the peer still live.

`just test-loom` includes bounded kernel models with two actors and at most two
preemptions. The model covers listener publication racing accepted-owner
enrollment, description-scoped notification, and FIN state preceding wake
delivery. A cohort-broadcast negative control must find the bad ordering. This
is an abstract protocol model; the held-listener witness binds it to real
dispatch and multiplexer behavior. It does not model fd reuse, user-wake
coalescing, or the entire reactor.

Local receipts: `/tmp/socket-dispatch-evidence/`. Signed HVF execution and
native arm64 Docker differential remain director-owned and unrun here. These
portable results do not close migration or release acceptance.

The first semantics run also exposed a stale futex replay source binding:
the starting tree's source hash was `30277d14358e70de81d22c8c6c3abd049e15c9a9a995b10cde47b1b0dda4ba4e`,
while the retained receipt pinned `2630c677f11520bbf5a88c5bed136ea891568fc4e6b039645352a2d59e2d910f`.
The director confirmed this failure already exists on main and is fixed by
reviewed PR #46, scheduled for the next batch. The historical receipt and
replay test remain unchanged in this PR. Full kernel-semantics and kernel
recipes therefore stop at this pre-existing source mismatch; the final socket
suite and held-listener witness are run directly as well. No source, replay,
semantic or work assertion was relaxed.

## Verification receipts

All commands ran in the foreground on the Linux worker, with output redirected
under `/tmp/socket-dispatch-evidence/`.

| Check | Exit | Log |
| --- | --- | --- |
| Held-listener witness before the fix | 101 (`1 != 0`) | `witness-red.log` |
| Final witness and kernel loom models | 0 (4 tests) | `witness-green.log` |
| Original socket-close suite | 0 (8 tests) | `socket-close.log` |
| `just test-loom` | 0 (2 fd-core and 3 kernel models) | `loom.log` |
| `just test-kernel-semantics` | 101 (pre-existing futex receipt) | `kernel-semantics.log` |
| `just test-kernel` | 101 (same receipt, kernel lib tests pass) | `kernel.log` |
| `just clippy` | 0 | `clippy.log` |
| Scoped kernel/example clippy, all targets with kernel loom | 0 | `clippy-scoped.log` |
| `just fmt-check` | 0 | `fmt-check.log` |
| `just lint-domains` | 2 (live host-call position drift only) | `lint-domains.log` |

The live Linux domain census detects five moved host-call spans in
`lifecycle.rs`: four AF_UNIX backing-path calls and one netlink PID call.
Their operations and classifications are unchanged; their locations move by
24 lines and 886 bytes. The director requested that the reviewed inventory
remain at main's recorded positions for reconciliation in the landing batch.
Changing these shared positions locally would invalidate the macOS capture;
no capture was fabricated and no per-PR remote recapture was run. The final
`just lint-domains` result is exit 2 at this live position comparison, after
the source/static gates pass; its receipt is `lint-domains.log`.
