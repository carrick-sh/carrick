# Zone the workloads: the in-guest kernel for everything that stays in Linux

Status: plan, 2026-09-24. Builds on
[`2026-09-24-el1-born-in-zone.md`](2026-09-24-el1-born-in-zone.md) (phases 1
and the inode/open-file split of phase 2 are on main at 4c92a8ab8).

## What the EL1 work showed

| Finding | Evidence |
|---|---|
| A syscall served in-guest is cheap | ~0.5 µs per add_watch+write+lseek+rm_watch iteration vs ~9.7 µs with `CARRICK_EL1=0`; LTP inotify09 2.7 s vs 37.4 s off vs ~5.9 s Docker |
| Ownership, not code speed, decided the result | every delegate/recall protocol shipped defects; "born in the zone, one owner, one implementation" removed whole classes |
| Focused contracts are not enough | the first full probe gate found 7 EL1 defects that passed focused tests; LTP found 2 more; phase 2 exposed a pre-existing O_TRUNC/truncate(path) data loss |
| Tests lie when they do not prove their path | a fork silently made writes host-served; a perl literal made a script die; a green run proved nothing until counters were asserted |
| Removing a mechanism removes what it covered | a "cleanup" (9e6ef15ab) deleted the signal pump's wake-debt retry; lost SIGALRM, found by bisect |
| We have measured one workload | EL1 has never been run against go build, cpython or node. A trapping syscall costs ~12x native and ~70% of per-op cost was our own host work (2026-09-20); the cold go build is ~10x Docker |

## Goal

Every object that never leaves the Linux compat zone is served by the in-guest
kernel, chosen by what real workloads spend, under the project's bar: within 2x
of native-arm64 Docker per ecosystem row, with `CARRICK_EL1=0` as the bisect
switch.

## Stages

### Stage 0: measure (first)

- A census that attributes every guest syscall to served-in-guest or forwarded,
  per syscall class, with host dispatch time per forwarded class, for one run.
  It is exact (per-carrier counters and host timing, no sampling) and emitted
  as machine-readable JSON by the CLI, so the ecosystem harness can collect it.
- Paired runs, EL1 on and off, of the ecosystem rows (cpython, go, node), a
  cold `go build`, and the LTP file/inotify set.
- Deliverable: `docs/perf-results/<date>-el1-census.md`, a ranked table per
  workload of forwarded host time by syscall class. It orders stages 2 and 3.

### Stage 1: finish the file zone

1. Files enter the zone only at open. Delete delegate-at-first-forward and
   the backoff machinery.
2. Split description access into a non-recalling inspect and a recalling I/O
   guard; migrate the ~80 kind-probe sites so recall-on-inspect cannot be
   expressed (a type, not a comment).
3. Demotion is the only exit, with one test per trigger (mmap, record locks,
   O_APPEND, fallocate/FICLONE/copy_file_range into, fanotify, seccomp,
   interceptors, capacity).
4. ABI layout hash in the EL1 image header, checked at boot.
5. A paged in-zone page cache replacing the fixed 128 x 256 KiB slots: per-page
   residency, eviction of clean pages, no whole-file copy at open. The largest
   item; real builds overflow the current cache immediately.

### Stage 2: name resolution in the zone (expected top of the census)

An in-guest dentry/stat cache so `openat`, `newfstatat`, `faccessat` and
`readlink` on cached paths are served without a trap, invalidated by every host
mutation path. Contracts: a stat storm and an import storm, with structural
budgets.

### Stage 3: next objects, in census order

Candidates: pipes and AF_UNIX between guest processes (already carrick-owned),
poll/epoll readiness over in-zone objects, a futex fast path, the root-thread
gettid stamp gap (2026-09-20), clocks.

### Stage 4: promotion

The ecosystem ratio ledger with EL1 on, per row, against the 2x bar; no
regression against the EL1-off ledger.

## Process rules, from stage 0

- One gate recipe for every EL1 landing on one recorded artifact: signed EL1
  embed tests, `just conformance-probes`, the LTP file/inotify set, and the
  inotify09 screen.
- Every EL1 contract asserts served counters, so a green run proves the zone
  path ran.
- Removing a mechanism names what it covered and adds a test for each case.
- One command reconciles the line-pinned inventories, abort sites, global
  state and K1 taxonomy for the mechanical cases; review stays manual.
- Contracts are added red-first at the cheapest capable layer for every stage.

## Risks

- The zone grows guest-reachable state with no adversarial security review; a
  guest is not a hardened trust boundary, and this plan does not change that.
- EL1 is HVF-only. The shared implementation (`carrick-el1` run by EL1 and the
  host) keeps other lanes on the same semantics through the host path.
- The 64 MiB aperture bounds the page cache and tables until the paged cache
  lands.
