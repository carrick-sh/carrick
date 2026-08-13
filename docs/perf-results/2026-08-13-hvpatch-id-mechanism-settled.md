# The guest-pid mechanism, settled by the kernel's own graph

**Recorded 2026-08-13.** Two earlier passes at this reasoned from code and got
part of it wrong. This one reads the answer out of the running kernel with
`carrick debug hvpatch-kernel`, which takes one coherent snapshot of the live
object graph over the run's authenticated debug socket.

## Method

A guest that forks a child and holds both alive:

```sh
carrick run --exec-backend hvpatch -e CARRICK_RUN_ID=$ID <image> \
  /bin/sh -c 'echo INIT_PID=$$; /bin/sh -c "echo CHILD_PID=\$\$; sleep 25" & sleep 25'
carrick debug hvpatch-kernel --run-id $ID --table task,thread
```

## What the guest reported

```text
INIT_PID=1
CHILD_PID=70829
```

## What the kernel's own graph says, at the same moment

```json
{ "key": { "id": 70828, "serial": 6 }, "diagnostic_name": "hvpatch-root",
  "parent": null, "process_group": 70828, "session": 70828,
  "children": [ { "id": 70829 }, { "id": 70830 } ] }

{ "key": { "id": 70829, "serial": 53 }, "diagnostic_name": "hvpatch-child-of-70828",
  "parent": { "id": 70828 }, "process_group": 70828, "session": 70828 }
```

## The mechanism, now settled

1. **The root task id IS the host pid.** 70828, named `hvpatch-root`. That
   confirms the seed at `hvpatch/mod.rs:626` (`pid = std::process::id()`), fed
   to `RootBootstrap` and then to `IdRegistry::with_root`. The
   registry-seeding hypothesis was **right**.
2. **Children are allocated from `root + 1`.** 70829, 70830, then 70831 for the
   grandchild — the `with_root` cursor (`registry.rs:31`) walking upward.
3. **A child's `getpid()` is EXACTLY its kernel task id.** The guest said
   70829; the graph says 70829. There is ONE authority for a child and it is
   the task id. The "two competing authorities" worry from the previous pass
   was **unfounded for children** — the number is wrong because the *id* is
   wrong, not because two sources disagree.
4. **The root is the exception, and that is the inconsistency.** Its
   guest-visible pid is 1 while its task id is 70828. The init alone is mapped
   to 1; its children are not, so a parent and its child answer from different
   schemes.
5. **`process_group` and `session` are 70828 for every task**, and the guest
   sees it. `/proc/self/stat` from a forked child:

   | field | carrick | Docker |
   | --- | ---: | ---: |
   | pid | 70954 | 7 |
   | ppid | 70952 | 1 |
   | pgrp | **70954** | **1** |
   | sid | **70954** | **1** |

   So this is not only a `getpid` bug: process-group and session identity are
   host-magnitude for the whole guest session, which is what `waitpgid`,
   `setpgidparentgroup` and the job-control probes are failing on.

## What this does to the refuted design

The **FATAL** objection to reseeding was that native and vmm run two id
allocators whose agreement depends on the host-pid coincidence. The
measurement makes that objection **inapplicable to a lane-scoped reseed**:
`initialize_root_process` opens with

```rust
if dispatcher.execution_backend() != ExecutionBackend::HvPatch { return Ok(None); }
```

(`hvpatch/mod.rs:619-621`), so changing the seed *there* cannot reach the
reference lanes at all — they bootstrap through `bootstrap_one_task_binding`
instead. That is exactly the lane-scoped design, and it now has measurement
behind it rather than an argument.

The two MAJOR objections **survive unchanged** and are still the work:

- **`LINUX_BOOTSTRAP_PID` (1) is an unconditional self-alias** in six live
  comparators. It is dead today only because no task holds id 1 — the graph
  proves it: the root is 70828. Seed the root at 1 and the alias goes live.
- **The host-call fall-throughs** are the `launchd` hazard, and they are why
  the comparators close first. Three of four liveness probes are already routed
  (`f6bf85701`); the `libc::kill` fall-through, `cred_ipc::read_target`, and the
  process-group probe remain.

## The fix, now precisely located

Seed the kernel lane's root at 1 in `initialize_root_process`
(`hvpatch/mod.rs:626`) instead of `std::process::id()`. Three things follow for
free, and the graph shows why each is currently wrong:

- the root's task id becomes 1, agreeing with the guest pid it already
  reports — removing the parent/child scheme split;
- children become 2, 3, 4 from the same cursor;
- `process_group` and `session` are copied verbatim from the root task id
  (`ids.rs:124-132`) and follow it to 1, which is what Docker reports.

**Order is unchanged and still binding:** comparators first, seed second.

## What is still NOT established

- Where the root's guest-visible `1` comes from, given its task id is 70828.
  Something maps the init specifically. Worth naming before the reseed, because
  after it the two agree and the mapping may become dead code that outlives its
  reason.
- Whether anything outside `kernel/` persists a task id across a boundary where
  a low number could collide with a host pid. The comparator audit covers the
  reads; this is about writes.
