# N2 readiness: creation path born at EL1

SUMMARY: No complete vertical-slice row is DONE. Current main has useful N2
A/B/C/D preparation and Phase B thread serving; work/n1 adds owner Fork,
UserTransfer and an owned file cursor, but does not close N1. Five file-disjoint
leaf packages can prepare witnesses and shared-core work now. Their production
bindings require accepted N1, a refreshed main stack and driver-owned shared
integration. This is a planning audit, not implementation or runtime acceptance.

**Scope and evidence convention.** This mirrors the summary, row inventory,
acceptance limits, parallel split and start decision in
`/Volumes/carrick/dev/n1-audit-report.md`. That report froze `4f459db98e` against
older main `6a33e26b2`; its verdicts and log receipts do not transfer here.
This audit fetched and inspected these committed snapshots on cloudmac:

| Citation key | Ref and exact commit |
| --- | --- |
| M | `github/main`, `b1167c6e19811c5b3a601d979cedca844656454f` (this worktree's base) |
| N | `github/work/n1`, `050b3aea2156023bfe45c0353f7a797db3737d1f` |
| P1 | PR #14 / `pr14`, `09cf6a56b5b99734bf7829cad370285ddedd840e` |
| P2 | PR #11 / `pr11`, `41fe977bc3c2c3020bd95dc070266180a33d36aa` |
| P3 | PR #16 / `pr16`, `3db84db7c37e78dbaeddffa791565de0276eb987` |
| P4 | PR #21 / `pr21`, `a0ead6ea56da24eb68d7e7e97af99a08a7534418` |
| PS | PR #19 / `pr19`, `146d5dd25ab5f34d49254ff7af62ce0f8413c090` |

`M:path:line` and `N:path:line` are source anchors in those exact revisions,
read with `git show`/`git grep`, not line claims about a future merge. P1–P4
line numbers refer to their respective
`docs/superpowers/plans/2026-10-04-n1-p1-handoff.md`, `n1-p2-handoff.md`,
`n1-p3-handoff.md`, `n1-p4-handoff.md` (all with the same date prefix).
PS refers to `docs/superpowers/specs/2026-10-04-personality-core-split.md`.
The PR branches are separate inputs, not assumed merged into N.

Path prefixes: `E` = `crates/carrick-el1/src/`; `ABI` =
`crates/carrick-el1-abi/src/`; `K` = `crates/carrick-kernel/src/`;
`R` = `crates/carrick-runtime/src/`; `H` =
`crates/carrick-vmm-hvf/src/trap/`; `S` = `crates/carrick-sched-core/src/`;
`EX` = `crates/carrick-kernel-example/`; `FD` = `crates/carrick-fd-core/`;
`PIPE` = `crates/carrick-pipe-core/`; `SIG` = `crates/carrick-signal-core/`;
`MEM` = `crates/carrick-mem/src/`. Braces in ownership lists expand to exact
files; they are not directory-wide permissions.

`DONE` requires the entire specified admitted operation and its implementation
witness, not merely an existing host implementation. `PARTIAL` credits an
implemented subset or reusable core with missing owner integration.
`NOT STARTED` means the requested EL1 conversion is absent in the inspected
routes. Signed acceptance is independently UNKNOWN unless tied to a receipt;
source status is not inferred from generic host CI, and no guest was run
by this document audit.

**Controlling scope.** Native-ownership section 4 at M:254–336 and N2 at
M:352 require one composed task/fd/pipe/wait/signal/exec ownership cutover,
including all section-2 MM consumers used by creation. This readiness document
partitions the existing [N2 execution plan](2026-10-04-el1-n2-creation.md),
not a second migration. Its B/C/D preparation is already on M: do not re-create
`install_pair`, readiness revisions, signal policy, or task transaction tests.
N1 must supply MM ownership; N2 must not implement a competing MM owner.

## Per-row status

The two source columns deliberately do not imply that N contains current main.
Rows 1–10 follow the native-ownership section-4 table; the remaining rows retain
its exec paragraph and the N2 milestone obligations.

| Row / required venue | M | N | File:line evidence and remaining work |
| --- | --- | --- | --- |
| 1. `clone`: process fork, thread clone, CLONE_VM/vfork; one task/identity graph | PARTIAL | PARTIAL | M:`E/personality/lifecycle.rs:7,20,386` serves a thread-flag subset using stocked identity and later host settlement; traced/seccomp/full-pool paths forward. N:`E/personality/lifecycle.rs:409` has the same thread-only boundary. N:`E/personality/mm_portal/fork.rs:409,502` provides owner memory prepare/publication, not EL1 process birth. M:`K/kernel/operations.rs:555,805` and `EX/tests/n2_task_transactions.rs:185,386,629` provide real graph rollback/vfork groundwork. Compose MM/fd/sighand/uid/TID outputs before runnable publication; move host graph mutation once. |
| 2. `exit` / `exit_group`: robust death, final thread, cleanup, zombie/SIGCHLD | PARTIAL | PARTIAL | M:`E/personality/lifecycle.rs:514,544`; N:same file `:537,567`: EL1 nonleader/nonlast exit, nonempty robust list declines. M:`EX/tests/n2_task_lifecycle.rs:231,343` covers host group semantics and explicit ignored zero-budget reds. No EL1 group teardown/robust walker/zombie closure is demonstrated. |
| 3. `wait4`: child queues, rusage, WNOHANG/ECHILD, reparent/autoreap/ptrace stops | NOT STARTED | NOT STARTED | M:`K/dispatch/proc.rs:3214`, `K/kernel/operations/wait.rs:157`; M:`EX/tests/n2_task_lifecycle.rs:118,273,350`: real host child waits and budget-red scaffolding. N:`crates/carrick-el1/tests/n2_creation_baseline.rs:19` counts forward for 260; inspected dispatcher/lifecycle has no wait4 owner arm. Move the existing child authority, not a second queue. |
| 4. `set_tid_address`, `set_robust_list`, `gettid` | PARTIAL | PARTIAL | M:`E/personality/lifecycle.rs:150,165`, `E/personality/thread_setup.rs:123`, `E/personality/common_entry.rs:35`: gettid and shared canonical robust registration exist. N:`E/personality/lifecycle.rs:136,340` has the earlier registration body. M:`K/dispatch/proc.rs:1786` still owns set_tid_address; N baseline `:19` forwards 96. Live-owner copy/robust exit and clear-tid under unmap/reuse remain; storing a robust pointer is not walking it. |
| 5. `sched_setaffinity`: Linux permission/mask checks, exact remote tid, eligible guest CPUs | PARTIAL | PARTIAL | M:`S/lib.rs:718,3015,3023` already carries eligibility and unhome primitives. M:`K/dispatch/proc.rs:2046` performs host Linux decoding; only `SelfProc` updates affinity in that inspected arm. N baseline `:19` forwards 122. Need EL1 policy and remote/vanished/recycled tid tests; generic eligibility alone does not implement this syscall. |
| 6. `mmap`, `munmap`, `mprotect`, `brk`: all mappings used by creation | PARTIAL | PARTIAL | M:`E/personality/dispatch.rs:27` reservation route is groundwork. N:`E/personality/dispatch.rs:375,428` routes admitted anonymous work but retains other venues; N:`E/personality/native_ownership_tests.rs:222` explicitly retains nonfork host semantic authority. P1:`76–86` leaves all-shape policy, VA-free Capacity and HostBacking integration open. N1 rows 1–7, 12–23, 28–30 close this prerequisite; N2 only consumes it. |
| 7. `futex`: private/shared keys, enroll/value order, robust/clear-tid lifetime | PARTIAL | PARTIAL | M and N:`E/personality/sched.rs:16,32` serve selected private WAIT/WAKE variants. N baseline `:92` distinguishes shared WAIT and waitv outside that route. M:`E/sched/object_wait.rs:43,77,180` supplies owned object waits/wakes. Shared key generations, all required operations, robust death and retirement composition remain. |
| 8. `ppoll`: all-zone/mixed readiness, temporary masks, EINTR/timeouts | PARTIAL | PARTIAL | M:`K/dispatch/net.rs:3187` remains host ppoll. M/N:`E/personality/ipc.rs:61,70` exposes shared IPC venue and epoll/read/write serving, not ppoll. M:`SIG/src/wait.rs:56`, `SIG/src/policy.rs:324,334` provide interruption and mask reducers; N baseline `:19` forwards 73. Need one EL1 enrollment for the full set, physical host completion input, no pipe readiness proxy or periodic scan. |
| 9. `pipe2`, `close`, `write`: one table across every backing kind, complete pipe lifetime | PARTIAL | PARTIAL | M:`FD/src/lib.rs:753` has atomic `install_pair`; M:`PIPE/src/tests.rs:670,716,868` has readiness/partial-progress/signal-decision witnesses. M/N:`E/personality/ipc.rs:61,70,95` serves shared IPC using host-published table identities. M:`K/dispatch/fs/pipe.rs:943` still creates pairs on host; N baseline `:19` forwards 57/59. EL1 pair copyout/rollback, final close, all-backing fd publication and driver cursor integration remain. |
| 10. `rt_sigaction` plus full delivery/restart/frame/sigreturn owner | PARTIAL | PARTIAL | M:`SIG/src/policy.rs:154,197,375,472` supplies policy; M:`K/dispatch/signal.rs:2042` remains host sigaction. N dispatcher lacks 134 serving; P4:`69–99,145–215` extracts one codec/handler transition but explicitly leaves owner transport and activation open. N1 row 27 is necessary, not sufficient: N2 moves Sighand/pending/delivery policy together, including CLONE_SIGHAND and exec reset. |
| 11. `execve` / `execveat` and dynamic-loader scaffolding | NOT STARTED | NOT STARTED | M:`K/dispatch/proc.rs:3356,3374`, `R/vcpu_loop/exec.rs:1464`, `MEM/elf.rs:381,389` are existing host entry/parser work. N:`H/execve_rebuild.rs:1472` still constructs legacy authority; P2:`86–140` explicitly requires owner Exec and routing. No EL1 prepared-image/loader orchestration found. Reuse parser/contained source service; include PT_INTERP, argv/env/auxv/stack/TLS/vDSO, credentials, CLOEXEC, sibling cancellation and failure/no-return boundary. |
| 12. Numeric 103 `setitimer` (retained census obligation) | PARTIAL | NOT STARTED | M:`SIG/src/timer.rs:62,95,135` provides exact-key interval policy; M:`K/dispatch/time.rs:391,422,453` still uses host proc/pump state. N baseline `:19` forwards 103; the M timer preparation is absent from N. The existing N2 plan M:`201–219` corrects 103's old label; 99 remains robust-list coverage. Do not drop the 21 observed 103 events. |
| 13. Composed zero-forward/work census and hostile lifecycle schedules | PARTIAL | PARTIAL | M/N:`crates/carrick-el1/tests/n2_creation_owner.rs:10,30,150,265` has 21-ID nonadmitted characterization and a served thread witness, not process/exec closure. M:`EX/tests/n2_creation.rs:14,286,300` explicitly lacks runtime pool exhaustion. N:`conformance-contracts/contracts/el1-creation-native-path.toml:10–22` still declares unresolved bindings and zero slope. TRACECLONE, seccomp, mapping/clone storms, production parked contexts and default-pool composition remain unaccepted. |

No full row is DONE: eleven PARTIAL and two NOT STARTED on M; ten PARTIAL and
three NOT STARTED on N. These counts describe source readiness, not test verdicts.
N's registered `kernel.el1.creation-native-path` is absent from M's contracts
directory; driver must reconcile it rather than add a new competing contract.

## N1 prerequisites and hard stops

The helper documents deliberately carry active reds. Read them as requirements
on N1 integration, not permission for N2 to accept a fallback. Public names
such as `PreparedEl1Exec` below remain proposed where the handoff says so.

| Dependency / section-2 rows | Evidence at frozen inputs | N2 consumer and release condition |
| --- | --- | --- |
| Sealed bootstrap/exec lifetime, rows 1/2/21–23/28–29 | P2:`38–84` active owner-plus-host-manager constructor red; `86–119` absent owner Exec/automatic permit drain; N:`E/personality/native_ownership_tests.rs:222`. | All production leaves require an owner-only admitted representation. Task/exec must compose a closed successor and exact rollback; no host editor retained through attach/detach/vfork. Keep occupancy/ForkClosing/ASID proofs while deleting PT editor fences. |
| UserTransfer, admission and retained accesses, rows 3–7/12–15 | P1:`88–176` retained HostWrites crosses owner admission despite physical pins. P1:`78–86` lists grant-pool generation, Capacity, EOF and policy obligations. | Task TID/status copies, fd pair rollback, signal frames and loader reads cannot complete until exact-generation permits and retained-read/write drain work. No guessed errno for an owner wait. |
| Owner Fork and all-shape MM, rows 10–19 | N:`E/personality/mm_portal/fork.rs:409,502` is real owner work; P1:`79–86` lists remaining COW, file, growdown, advice and grants. | Task leaf can prepare graph rules now; production process fork needs accepted child publication/abort. Loader needs file/stack/fixed mappings, exact EOF/SIGBUS policy, extent-bounded supply and compound return. |
| Owned service under exhaustion, rows 8/9/20/24/30 | P3:`115–178` borrowed engine service is insufficient; `61–70` explicitly says its 256 service slots are not runtime default executor leases. P3:`180–223` requires ordinary-read fallback fencing and simultaneous observer leases. | Wait leaf and all suspended copy consumers need service without running stopped EL0 or borrowing another exhausted worker. Observer/native revoke-on-exec belongs to N1; N2 retains TRACECLONE/stop/exec composition. |
| Owned OFD cursor and source consumption | N:`K/dispatch/host_io.rs:91,197,232,295` now implements `FileCursorAdmission`, `OwnedHostFileCursor`, staged read and copied-prefix commit. This updates the older N2 plan's “not in fetched branch” note. | FD and exec consume this same OFD authority across dup/fork/SCM_RIGHTS. Source presence is not accepted cancellation/copyout integration. Preserve prepare-before-consume, staged read and exact prefix/offset; do not introduce a per-fd cursor or hold locks across I/O. |
| Snapshot/SignalFrame, rows 26/27 | P4:`31–67` active snapshot identity and six-legacy-hook signal reds; `101–143` requires frozen exact MM/thread manifest; `145–215` requires explicit intent, multi-chunk frame custody and successful-return state commit. | Signal production binding waits for N1 frame service; task/signed capture requires exact parked registers. P4 says parked save-area reading already exists: do not report it wholly absent. Snapshot formats and CPU contexts must be separated. |
| Whole-N1 acceptance | P1:`178–249`, P2:`217–267`, P3:`314–400`, P4:`217–241` record checkpoint passes and unclosed host/owner/signed gates. | Driver must obtain the actual accepted N1 commit and receipts, refresh main/helper integration and rebuild. None of these documents supplies a current whole-N1 pass. |

**Start rule:** all five leaves can start their new, disjoint tests and bounded
extractions before N1 lands. None may activate an admitted production path or
claim a row closed before its prerequisites. Exec's owner publication and
signal's frame cutover cannot start as production wiring yet. The task graph
can be extracted against today's public transactions; it cannot invent the
missing owner Exec API. MM/service files remain N1-owned until explicit handoff.

## Five file-disjoint leaf packages

These are work packages within existing N2 landings B–E. Landing A accounting,
common exports, ABI changes and production route activation belong to the
driver. The file lists below are pairwise disjoint. New files are explicitly
marked; their names are proposed deliverables, not existing APIs or tests.
All other files are out of fence until the driver updates this manifest.
The 38 expanded leaf paths were checked against N1 branch-only changes and
each helper PR diff: no intersection remains. `E/substrate/ipc.rs` does
intersect N1 and is therefore driver-reserved, even though it is an IPC entry
point. This check is frozen-source evidence, not a lock on advancing branches.

Before dispatching implementation, the driver rebases accepted N1 onto current
main, retains M's preparation and freezes one shared API/header commit. The
driver registers any new module in existing `lib.rs`/`mod.rs`/Cargo files so
leaf production code is actually compiled. Helpers may first add auto-discovered
integration tests using current public APIs; an unregistered module is not a
verified extraction. Cross-leaf type requests return to the driver, never two
independent public protocols. Move existing algorithms and switch their callers
in the same integration; do not leave a second host implementation beside EL1.

### L1 — task graph, birth/retirement and Linux child policy (landing D)

**Exclusive existing files:** `K/kernel/operations.rs`,
`K/kernel/operations/{thread,exit,wait}.rs`, `K/kernel/clone_plan.rs`,
`K/kernel/thread_ledger.rs`, `K/kernel/objects/{task,thread}.rs`.
**New files:** `S/task_lifecycle.rs`, `E/personality/task.rs`,
`EX/tests/n2_readiness_task.rs`.

**Entry points:** extract from `PreparedFork`/`KernelContext::reserve_fork`
(M:`K/kernel/operations.rs:555,805`), `ClonePlan::from_flags` (`:56`),
`wait_child` (M:`K/kernel/operations/wait.rs:157`) and existing exit/thread
transactions. Consume N1 `MmPortal::prepare_fork`/`publish_fork`; driver wires
existing `personality/lifecycle.rs` and kernel proc dispatch. Cover process and
thread birth, uid credits, parent/child TID publication, vfork release,
robust/clear-tid requests, exit_group, wait statuses and reparenting.

**Cheapest red first:** extend the existing public-graph scenarios, keeping two
live parents at 1/8/32. Proposed `n2_readiness_task` exercises failed MM/fd/TID
publication, exact rollback, child never runnable before all edges commit,
clone versus exec close, stale/recycled task notifications and robust death.
Use existing `EX/tests/n2_task_transactions.rs` as the positive control; reuse
`n2_task_lifecycle` zero-work reds explicitly. Those host scripts prove policy
and their measured host-dispatch deficit, not EL1 hardware routing. New
owner-binding tests must invoke the extracted production core and retain the
same observations after cutover, rather than substituting a fake zero counter.

**Exact commands (after adding the proposed test):**

```sh
source /Volumes/carrick/dev/env.sh
CARRICK_RUN_ID=n2-l1-red cargo test -p carrick-kernel-example --test n2_task_lifecycle -- --ignored --nocapture
CARRICK_RUN_ID=n2-l1 cargo test -p carrick-kernel-example --test n2_readiness_task --test n2_task_transactions -- --nocapture
```

The first command is an existing expected-red diagnostic, not a passing gate.
Driver removes the preparatory ignore only when connecting the real owner
binding; no new ignored test, expected-panic inversion or weakened budget.

### L2 — descriptor and pipe creation/lifetime (landing B resource half)

**Exclusive existing files:** `FD/src/{lib,tests}.rs`,
`PIPE/src/{lib,tests}.rs`, `E/personality/ipc.rs`.
**New file:** `crates/carrick-el1/tests/n2_readiness_fd_pipe.rs`.

**Entry points:** existing fd `Authority`/transaction `install_pair`
(M:`FD/src/lib.rs:753`), pipe `retain`/`release`/`write_with`
(M:`PIPE/src/lib.rs:469,482,708`), `IpcVenue`/`serve_ipc` and
`substrate::ipc::transfer`. Extend the one table to all backing kinds including
stdio; fork copies slots and shares OFDs, CLONE_FILES shares the table, exec
unshares before CLOEXEC. Do not replace the landed B-prep pair/revision code.
Driver owns ABI object storage, host description adapters and N1 cursor glue.

**Cheapest red first:** production IPC/region fixture with two live task/MM
identities, atomic two-fd copyout refusal, retained endpoint/OFD pins through
close/reuse, fork and CLOEXEC, three-page write interrupted after a prefix,
resumed exact remaining bytes, final EOF/EPIPE/SIGPIPE. Use 1/8/64 objects and
existing B-prep deterministic work bounds; no bytes copied twice and one final
release per endpoint. The new test must demand EL1 pair/close ownership on the
real dispatcher fixture; existing pair-core greens alone cannot supply red.
Actual default-pool progress belongs to L3/driver composition.

```sh
source /Volumes/carrick/dev/env.sh
CARRICK_RUN_ID=n2-l2-core cargo test -p carrick-fd-core -p carrick-pipe-core --lib
CARRICK_RUN_ID=n2-l2 cargo test -p carrick-el1 --test n2_readiness_fd_pipe -- --nocapture
```

### L3 — owned wait sets, futex and CPU eligibility (landing B wait half)

**Exclusive existing file:** `E/personality/sched.rs`.
**New files:** `S/creation_wait.rs`, `E/personality/poll.rs`,
`E/personality/affinity.rs`, `EX/tests/n2_readiness_wait.rs`,
`crates/carrick-el1/tests/n2_readiness_wait_owner.rs`.

**Entry points:** extend Linux `is_served_futex_op`/`Sched::serve_futex`
(M:`E/personality/sched.rs:16,32`) over existing exact word/object waits;
consume `observe_object`/`park_object`/`notify_object`
(M:`E/sched/object_wait.rs:43,77,180`) and sched eligibility (`S/lib.rs:718`).
Extract ppoll decode from `K/dispatch/net.rs:3187` and affinity policy from
`K/dispatch/proc.rs:2046` through driver-owned caller edits. Linux masks,
permissions and result lowering stay in these personality modules; the shared
wait operation owns a set of exact keys and typed completions, not an fd or
negative errno. Reuse L4's temporary-mask/interruption reducer.

**Cheapest red first:** bounded seeded schedules using M:`EX/src/schedule.rs:116`
(`Schedule::explore`), capture/replay/shrink the first failing receipt. Include
readiness just before/after enrollment, all-zone/mixed sets, timeout versus
signal restore, shared futex after unmap/reuse and remote affinity after tid
reuse. Assert one enrollment/park per blocking episode, no redispatch while
parked, exact wake count and affected-waiter work, not a population scan.
Run 1/8/32 and retain both live processes throughout the race.

```sh
source /Volumes/carrick/dev/env.sh
CARRICK_RUN_ID=n2-l3-schedule cargo test -p carrick-kernel-example --test n2_readiness_wait -- --nocapture
CARRICK_RUN_ID=n2-l3-owner cargo test -p carrick-el1 --test n2_readiness_wait_owner -- --nocapture
```

Use a fixed small seed list in that proposed test, record chosen seeds in its
receipt, and keep failures replayable; no fuzz flood. The scripted backend
uses host threads per actor (M:`EX/tests/n2_creation.rs:14`), so it **cannot**
prove default runtime lease exhaustion. Driver must add a VM-free fixture on
the real bounded executor/continuation code, fill its unchanged default pool
with 32 partial writers and a runnable reader, and prove waiters release
capacity. If that binding is unavailable, report UnsupportedLayer, then add it;
256 occupied EL1 service slots or more host threads are not substitutes.

### L4 — Linux signal/timer owner (landing C)

**Exclusive existing files:** `SIG/src/{lib,policy,timer,wait,fasync}.rs`,
`SIG/tests/policy_contract.rs`.
**New files:** `E/personality/signal.rs`, `E/personality/timer.rs`,
`crates/carrick-el1/tests/n2_readiness_signal.rs`.

**Entry points:** use existing `ActionTable::{install,for_exec,for_clone}`,
`PendingSignals`, `take_pending`, `MaskState::{begin_temporary,end_temporary}`,
`IntervalTimer::{set,expire,cancel}`, `interrupted_wait` (status table anchors).
Consume P4's single codec through N1's eventual owner SignalFrame operation;
HAL cannot simply become a no_std EL1 dependency. Driver moves the codec once
and switches kernel object/dispatch/runtime callers together. This leaf does
not edit N1 P4's active files before handoff.

**Cheapest red first:** production personality fixture at 1/8/32 exact targets,
two live processes, immediate post-birth tgkill, blocked SIGCHLD, shared versus
copied actions, exec reset, duplicate/stale timer expiry, SIGPIPE after partial
write, temporary-mask readiness race and SA_RESTART. Assert zero host signal
selection/semantic forwarding. Preserve existing policy-core tests as controls;
new route test must fail on today's missing owner even if reducers pass. Frame
cross-page fault, invalid sigreturn and handler activation require N1 production
binding, then signed execution; a transport spy alone cannot close them.

```sh
source /Volumes/carrick/dev/env.sh
CARRICK_RUN_ID=n2-l4-policy cargo test -p carrick-signal-core
CARRICK_RUN_ID=n2-l4-owner cargo test -p carrick-el1 --test n2_readiness_signal -- --nocapture
```

### L5 — Linux image preparation and exec transaction (landing E)

**Exclusive existing files:** `MEM/elf.rs`, `K/kernel/exec.rs`,
`K/dispatch/executable_authority.rs`, `R/runtime/exec.rs`.
**New files:** `E/personality/exec.rs`, `EX/tests/n2_readiness_exec.rs`.

**Entry points:** extract the one `plan_elf_load_bytes_for` parser
(M:`MEM/elf.rs:389`), contained executable authority and `load_execve_image`
from runtime byte/format work; compose `PreparedExec`/`prepare_exec`
(M:`K/kernel/exec.rs:100,236`) with N1's **not-yet-available** owner Exec
prepare/commit/abort. Driver arranges shared parser module/dependency exports
and removes the old policy body, rather than linking host memory machinery
into EL1. Host supplies retained byte/source identities only. Core consumes a
format-neutral prepared image; ELF/PT_INTERP/auxv/vDSO/stack decisions are Linux.

**Cheapest red first:** public task transaction and parser fixtures: two live
same-VA MMs; invalid ELF, missing interpreter, non-UTF8 arguments; every
precommit failure leaves exact old MM/fds/signal state; delayed old completion
cannot publish successor; failed vfork exec does not wake parent; successful
exec/exit wakes it once. A concurrent dup/fork reader consumes N1's actual
staged OFD cursor once, including short copy/cancel. Demand no host ELF semantic
selection at production entry. The parser tests alone cannot prove venue;
owner-API absence is a dependency, not a fabricated compiling-red result.

```sh
source /Volumes/carrick/dev/env.sh
CARRICK_RUN_ID=n2-l5 cargo test -p carrick-kernel-example --test n2_readiness_exec -- --nocapture
```

## Driver-reserved shared integration files

Only the N2 driver edits these integration points after the relevant N1 owner
releases them. Helpers send narrow interface requests/diffs, not concurrent
changes. This reservation is intentionally distinct from the exclusive leaf
algorithm files above.

| Integration surface | Exact reserved files / reason |
| --- | --- |
| Routing and exports | `E/personality/{dispatch,mod,lifecycle,thread_setup,common_entry}.rs`, `E/lib.rs`, `E/substrate/{mod,ipc}.rs`, `S/lib.rs`, `MEM/lib.rs`; `Cargo.toml`, `Cargo.lock`, `crates/carrick-el1/Cargo.toml`, `crates/carrick-sched-core/Cargo.toml`, `crates/carrick-mem/Cargo.toml`. Register and compile leaf modules, preserve the main-only canonical robust setup/x86 adapter seam. Other package manifests require the same single-driver coordination. |
| Shared records and wait/placement | `ABI/{lib,thread_lifecycle,ipc,ipc_tables,mm_portal}.rs`, `S/{object_wait,completion_queue,spaces}.rs`, `S/object_wait/delegated.rs`, `S/spaces/notification.rs`, `E/sched.rs`, `E/sched/object_wait.rs`. Exact generations, Linux payload separation, persistent pipe revision and layout hash/version are one publication change. |
| Task/fd/cursor and host dispatch adapters | `K/kernel/{objects,registry,scheduler,continuation}.rs`, `K/kernel/objects/{signal,process,ipc}.rs`, `K/kernel/continuation/{ipc,readiness,wait_service}.rs`, `K/dispatch/{proc,signal,time,net,fd_table,fd_wait,io_pipe,host_io}.rs`, `K/dispatch/fs/{pipe,fd_helpers,rw}.rs`. Shared edge publication, one cursor, old caller removal and owned completion binding. |
| N1 owner attachment and service | `crates/carrick-aarch64/src/{engine,stage1_authority,user_transfer,vmm}.rs`, `H/{foreign_mm,user_transfer,execve_rebuild,process_plan,host_writes}.rs`, `crates/carrick-guest-mem/src/{lib,prepared}.rs`, `E/personality/mm_portal/{mod,production,fork,edit_wait}.rs`, `MEM/memory.rs`. Consume accepted N1; helpers may not change MM policy here. Remaining N1 MM/custody/observer files are out of N2 scope, not free leaves. |
| Runtime composition | `R/runtime.rs`, `R/vcpu_loop/{mod,binding,lifecycle,quiesce,zone,exec,signal,crash}.rs`, `crates/carrick-hal/src/sigframe.rs`. One task/MM/fd/signal commit, default-executor progress, parked-context and codec integration. |
| Evidence and gates | `EX/src/{lib,driver,schedule,scripted}.rs`, `EX/tests/{n2_creation,n2_task_lifecycle,n2_task_transactions}.rs`, `crates/carrick-el1/tests/{n2_creation_baseline,n2_creation_owner}.rs`, `crates/carrick-embed/tests/el1_sched.rs`, `conformance-contracts/contracts/{el1-creation-native-path,el1-mm-exclusive-owner,el1-fork-cow,el1-signal-delivery-owner}.toml`, `crates/carrick-observability/src/probes.rs`, `crates/carrick-cli/src/trace_profile.rs`, `justfile`. Contract/binding registries, conformance-next registration and line-pinned/authority inventories are also single-driver changes, reconciled on a clean integrated tree. |

This is an integration fence, not a claim that all named changes are necessary.
The older N2 plan names `scripts/dtrace/fork-cow-exit-attribution.d`, but
that file is absent from both M and N. Driver must recover the attributed
script from its original branch or identify the current registered profile;
this audit does not invent an existing tracing file. No leaf may add another
API/transport to avoid a reserved file. The driver must
check each pathname on the actual N1 landing before assigning edits; a changed
name or moved module is an explicit manifest update, not license for a glob.

## Personality-neutral landing rules

PS:`304–333` is an extraction requirement at N1/N2 landing, not a request to
implement NT now. Preserve the current common library/package sequencing.

| Owner | Required boundary |
| --- | --- |
| L1 / driver records | Core owns exact identity, birth claims, resource edges, retirement and generic completion. Split `BornRecord.clone_flags` (M:`ABI/thread_lifecycle.rs:339`) and blocked masks/altstack/robust pointers from neutral records. Linux owns clone rules, zombie/rusage/SIGCHLD, robust death and clear_child_tid; do not name a neutral process completion “SIGCHLD.” |
| L2 / L3 | Core pins, byte queues, wait sets and CPU eligibility are reusable. Linux fd allocation/CLONE_FILES/CLOEXEC, readiness masks, futex rules, temporary masks, EPIPE/SIGPIPE and errno lowering stay personality policy. A generic completion must support multiple objects and typed results, not only one fd plus negative errno. |
| L4 | The entire signal owner is Linux policy. IRQ/preemption and async-notification scheduling are core. Keeping a Linux-specific signal-core crate is compatible with this split; calling its state neutral is not. |
| L5 / N1 | Prepared image publication and saved contexts are format/ISA-neutral. Linux ELF/auxv/vDSO and Linux core-file serialization remain clients. Do not require `Aarch64CoreRegisters` for every core snapshot or require an ELF object to publish an MM. |

## Verification, risks and unknowns

**Required proof ladder.** Use `kernel.el1.creation-native-path`,
`kernel.el1.mm-exclusive-owner`, existing fork-COW/thread/IPC/signal contracts
and their Linux semantic authorities. Proposed tests above are not commands
run for this audit. First retain an actual compiling semantic/work red on the
prechange implementation; a missing symbol or zero selected tests is not red
proof. Then run the focused leaf command, relevant shared-core suites and
`just test-kernel`. Register missing bindings with the driver, not an invented
counter or standalone alternate model.

After accepted N1 and composed VM-free greens, driver runs signed existing
`just test-embed el1_ --nocapture` (including `el1_ipc_`), `just accept`,
`just el1-gate` and applicable conformance-next bindings on the exact rebuilt
artifact. Preserve all original creation workloads and libc scaffolding,
TRACECLONE/seccomp, robust death, partial writes, fork/exec during clone/mapping
storms, and two live MMs. Promote the same identified CLI through the mandated
probe/smoke/full sequence on an authorized gate host; cloudmac must not run
Docker. Native-arm64 Docker semantics/timing are a separate director-run phase
on a capable host, never concurrent with Carrick. No new CLI subprocess probes.

N3 still closes 20×16 total exits <=144 and syscall exits <=64, 16/64/256 scales,
per-added-page slope <0.125 and <=2x uninstrumented native-arm64 Docker per-op.
N2 must supply zero semantic-forward slope for the 18 numeric IDs plus 99 and
execve/execveat, zero host COW resolution, descriptor edits and page-table
pauses, with loader/Capacity/HostBacking physical work separately attributed,
fixed startup retained and no unknown/dropped events. A low exit
count cannot waive a semantic or structural failure. Record HEAD, executable
hash/CDHash/LC_UUID/entitlement/DOF, fixture/image/operation identities and scoped
`scripts/sudo/kill.sh <run-id>` cleanup for each actual signed artifact.

| Named failure class / risk | Required witness or disposition |
| --- | --- |
| Default-pool exhaustion | 32 partial writers and runnable reader on the actual unchanged default executor pool; every guest wait releases capacity. No larger pool, spare-worker assumption, parked host worker, polling, retry or deadline increase. P3 service-slot fixture is insufficient. |
| Partial I/O continuation | Own endpoint/OFD pin, source/cursor, exact MM generation, token, copied offset and completion authority across suspend/cancel. Never replay from byte zero or turn suspension into short success. Include close/reuse and signal after prefix; prepare after readiness before consumption. |
| Two-live-process scope | Keep both live at identical VAs, not sequentially reused setup. Test shared versus private fd/sighand/MM edges, independent pending signals/timers, cross-owner wake and stale completion after exec/reuse. Host pid/process timer/registry must not decide guest identity. |
| Task graph migration / std dependency | Existing host graph is not a no_std EL1 owner. Extract its real state/transaction algorithm once, compile it at both venues, and delete displaced host mutation; a second Born mirror is not closure. |
| Admission is irreversible | Full pool, seccomp, trace, unsupported mapping and copy fault cannot demote admitted tasks to host Linux policy. Genuine external operations remain physical effects. Retain exact pre-admission bisection rules only as the governing plan permits. |
| Exec rollback versus no-return | Fault every boundary, preserve old image and vfork block before commit, terminal policy after no-return. Drain old permits/native activations without waiting in Drop. Frame/handler state commits only after successful owner completion. |
| False-green preparations | M contains ignored task budget reds and green forwarding characterizations. Run reds explicitly; do not report ordinary suite success as zero-forward acceptance. Leaf policy tests, physical stubs and source fences do not establish trap routing or hardware TLBI/I-cache. |
| Branch skew and inventories | N lacks some main-only core/witness/canonical-entry work. Use merge-base diffs as well as endpoint diffs; helper PRs are not implicitly included. Reconcile shared inventories after integration on a clean tree; never take another branch's positions/receipt as current. |

**UNKNOWN, with searches performed.**

- Current whole-N1 acceptance: searched frozen N's owner/dispatch source and
  all four fetched handoffs; the supplied audit and handoffs expose open reds.
  No current accepted-artifact packet was supplied or established. Refresh
  actual N1 landing and receipts; do not infer acceptance from PR status.
- A production VM-free runtime default-pool binding for this composed workload:
  searched `n2_creation*`, task suites, `E/sched/object_wait.rs` and P3 handoff.
  Existing EX fixture explicitly excludes it. Driver must identify or implement
  the real bounded-executor binding before claiming that layer green.
- Owner Exec / complete SignalFrame / neutral prepared-image API: searched
  N's `mm_portal`, `execve_rebuild`, signal/lifecycle dispatcher and P2/P4
  handoffs. Required names in those documents are proposals. No settled public
  signature or current production completion is assumed by these leaf fences.
- Numeric 103's original trace interpretation: searched the existing N2 plan
  and 21-ID fixture; preserved the documented correction. Raw signed census
  was not rerun. Both 99 and 103 remain in scope until driver attribution.
- Exact Linux TID-copyout fault ordering and partial SignalFrame failure policy:
  current graph tests and P2/P4 receipts do not qualify every failure ordering.
  Preserve their uncertainty; request the retained oracle or add a clean-room
  conformance-next witness on the authorized oracle host, never guess errno.
- Signed/performance results of this combined future tree: no combined
  main/N1 build, guest execution, Docker or workload timing was attempted. All such claims
  remain open, including historical frozen admission reds whose N1 attribution
  was never established.

**Start decision:** release all five leaves for preparation against refreshed
main, with the exact fences above and the driver header/API queue. Release
production integration only after the N1 dependencies close. The critical path
is sealed MM/service/Exec plus driver task/fd/signal publication, not another
round of standalone core implementations.

**Documentation verification and exemption.** Only this file changes; it has
no guest-visible semantic or work effect. Required local verification:

```sh
source /Volumes/carrick/dev/env.sh
export CARRICK_RUN_ID=n2-audit-doc
test -s docs/superpowers/plans/2026-10-04-n2-readiness.md && just fmt-check
```

The requested nonempty-document/format check passed. A read-only manifest
check validated 38 leaf paths, no pairwise or driver overlap, existing paths
on M/N, and no overlap with the frozen N1/helper diffs. `git diff --check`
also passed. The initial rulebook `just ci` stopped at missing `cargo-deny`
(`/tmp/n2-audit-ci.log`). After the director installed it, the complete recipe
was attempted again on documentation commit `fab4a0b96`:
`CARRICK_RUN_ID=n2-audit-ci-final just ci`, log
`/tmp/n2-audit-ci-final.log`. Formatting, Clippy, domain/authority, dependency,
matrix, layering, portable-kernel and workspace build checks passed. Rustdoc
then exited 101 on inherited `carrick-mmu-core/src/aarch64.rs:299,826,889,949,1831`
unresolved `[5:0]`, `publish_existing_invalid_private_pages` and `AP[1]`
links, and `carrick-el1-abi/src/ipc/epoll.rs:11`'s private
`EpollState::host_items` link. Both files are unchanged from M; the inspected
[PR #3](https://github.com/carrick-sh/carrick/pull/3) contains their fixes.
Host-test and integration-test stages after rustdoc were not reached. This
records a blocked full CI attempt, not a green acceptance receipt; fixing
those source files is outside this planning-only task.

Product acceptance commands in this plan are future obligations. This audit
must not be reported as N1, N2 or N3 acceptance.
