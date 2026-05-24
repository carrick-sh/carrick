# epoll-on-kqueue: persistent kqueue per epoll instance (FreeBSD model)

## Why
`epoll_pwait` snapshots the in-memory `interest` map at entry and parks on a
**separate per-thread** `io_wait` kqueue with just that snapshot's host fds. An
fd `epoll_ctl(ADD)`-ed by another thread while a netpoller thread is already
blocked in `epoll_wait` is never monitored by that in-flight wait → lost
wakeup. Confirmed root cause of the Go HTTP fixture's ~5/6 hang (server's
accepted conn fd7 added while the netpoller blocks on fd3/fd6; fd7's readiness
has no observer). See `project_go_bringup` memory + `golang-bringup-handoff.md`.

## Prior art
FreeBSD `sys/compat/linux/linux_event.c`: the epoll fd **is** a kqueue.
`epoll_ctl`→`EV_ADD`/`EV_DELETE`, `epoll_wait`→`kevent`. A concurrently-added fd
is seen by the already-blocked `kevent`. EPOLLET→`EV_CLEAR`,
EPOLLONESHOT→`EV_DISPATCH`, level=plain `EV_ADD`. jiixyj/epoll-shim adds per-fd
`eof_state` to keep level HUP/RDHUP/ERR persistent and a re-probe pass.

## Design (fits carrick's existing WaitOnFds + ThreadWaiter machinery)
A **kqueue fd is itself pollable** (readable when it has pending events). So the
epoll instance owns a persistent kqueue, and the per-thread waiter blocks on
*that kqueue's fd* becoming readable — no new wait primitive needed.

1. `OpenDescription::Epoll` gains `kqueue: Arc<Kqueue>` (Arc so a dup'd epoll fd
   shares the instance, matching Linux). Keep `interest` map as metadata
   (data, requested mask, EEXIST/ENOENT, in-memory readiness).
2. `epoll_create1`: create the kqueue.
3. `epoll_ctl`:
   - ADD/MOD: update interest map; then on the instance kqueue:
     - host-backed fd (`host_fd_for_poll` = Some): `EV_ADD` `EVFILT_READ` if
       EPOLLIN, `EVFILT_WRITE` if EPOLLOUT; `EV_CLEAR` iff EPOLLET; `udata` =
       guest fd. MOD = delete both filters then re-add.
     - in-memory (eventfd/pipe/timerfd, `host_fd_for_poll` = None): `EV_ADD`
       `EVFILT_USER` ident=guest fd, `udata`=guest fd; register the instance
       (kq fd, ident) on the object so its readiness-increasing ops
       `NOTE_TRIGGER` it.
   - DEL: remove from map; `EV_DELETE` the filters / EVFILT_USER; deregister.
4. `epoll_pwait`:
   - Non-blocking `kevent()` drain of the instance kqueue → for each event map
     `udata`→guest fd and (filter,flags,fflags)→epoll events (`kevent_to_epoll`:
     READ→EPOLLIN, WRITE→EPOLLOUT, EV_EOF on read→+EPOLLRDHUP, both halves→
     +EPOLLHUP, EV_ERROR/EV_EOF+fflags→EPOLLERR). For EVFILT_USER idents,
     recompute the in-memory object's readiness (existing `epoll_ready_events`).
   - Mask to `requested | EPOLLHUP | EPOLLERR`. Collect up to maxevents.
   - If any ready → write + return count.
   - Else if `timeout != 0` → `WaitOnFds { fds: [(instance_kq_fd, POLLIN)],
     timeout, on_timeout: 0 }`. The thread waiter wakes when the instance kqueue
     gets any event (incl. an fd ADDed by another thread → race fixed).

## Wrinkles
- **fork**: a kqueue isn't inherited. Guest fork with an open epoll fd is an edge
  case (Go doesn't fork); rebuild lazily / document. Track as follow-up.
- **maxevents < ready (edge)**: EV_CLEAR events drained but not delivered would
  be lost. Drain into a bounded buffer ≤ maxevents; level events re-report next
  call. Acceptable; refine if a probe shows it.
- **in-memory readiness without a write hook**: a level-ready in-memory fd that
  never gets a new trigger still re-reports because epoll_pwait recomputes it on
  every call; the EVFILT_USER only needs to *wake* a blocked wait.

## Verification (TDD)
- Oracle 1: `conformance_go_fixture` (Go HTTP) — baseline 5/30, target ~30/30.
- Oracle 2: a new conformance probe deterministically reproducing
  "register fd in epoll from thread B while thread A blocks in epoll_wait, then
  make it ready" (the ADD-during-wait race), MATCHing Docker.
- LTP epoll_* (epoll_ctl0*, epoll_wait0*, epoll_pwait0*) stay MATCH.
- `cargo test --release --lib` stays green.
