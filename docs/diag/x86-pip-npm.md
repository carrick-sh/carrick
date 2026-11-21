# x86 KVM pip and npm rows: root causes (2026-11-21)

This is a read-only diagnosis with no product change. Both rows fail because
a **run-root** syscall that the ARM root forwards to the host has **no x86
venue**. The shared dispatch then answers it in ring with a counted ENOSYS.
Each refusing site was measured, not inferred from reading (see "How the site
was proven").

| Row | Refused syscall | x86 nr | canonical nr | Caller | Count (one run) | Refusing site (main `a522eae5e`) | Owner |
|---|---|---:|---:|---|---:|---|---|
| pip | `clock_gettime` | 228 | 113 | root | 743 unrouted ENOSYS, 0 forwarded | crossing-table refusal in `finish()`, `crates/carrick-personality-linux/src/dispatch.rs:1698-1712`, because `ClockGettime` is not x86-allowed at `crates/carrick-personality-linux/src/crossing.rs:294` | open draft PR #2618 (issue #2028) |
| npm | `execve` | 59 | 221 | root | 6 unrouted ENOSYS (also counted 6 "forwarded") | `settle_unwired_native_service`, `crates/carrick-el1-linux/src/dispatch.rs:1289-1307`, reached from the `CompletionRoute::NativeService` arm at `crates/carrick-x86-cpl0/src/linux_personality.rs:1626-1640` | issue #2142, blocked per #2188; no open PR |

Both are one-lane gaps: the ARM root serves both calls today, and x86 does
not. Each is therefore P0-relevant for whichever PR claims the row.

## Row 1: x86 pip (`rc 1`, `OSError: [Errno 38]`)

**Symptom.** `carrick run python:3.12-slim pip install requests==2.32.3`
fails before pip parses its arguments. `import logging` runs
`_startTime = time.time()` (`logging/__init__.py:59`) and gets
`OSError: [Errno 38] Function not implemented`. `python3 -c 'import time;
print(time.time())'` fails the same way, with no fork involved.

**Refused call.** Census `--refusals`: `clock_gettime`, x86 nr 228, canonical
113, caller `root`, **743** unrouted ENOSYS, 0 carrier-refused, not
allowlisted. The per-syscall census shows 0 served and 0 forwarded.

**Why.**
1. x86 publishes no vDSO. `crates/carrick-kernel/src/vdso_policy.rs:88`
   omits `AT_SYSINFO_EHDR` for x86_64 ("no x86_64 no-fastpaths vDSO image
   yet"), so glibc issues a raw `syscall(228)` for every clock read. That is
   why one Python start makes 743 of them.
2. Canonical 113 has no ring family. It is absent from `route_aarch64` and
   `route_x86` (`crates/carrick-personality-linux/src/dispatch.rs:722`,
   `:891`), so it is `Family::Unported`. `service_owner`
   (`dispatch.rs:1530-1541`) makes it a `ServiceOwner::Crossing`, a
   Permanent host crossing.
3. The family declines with Forward. `finish()` takes the x86 branch
   (`dispatch.rs:1677-1684`) and calls
   `evaluate_host_crossing(HostCrossingSet::X86, strict, 113, …)`
   (`dispatch.rs:1698`). The crossing table declares
   `ClockGettime = nr::CLOCK_GETTIME, false, Permanent;`
   (`crossing.rs:294`): the `false` means "not allowed on x86". So the call
   is `Refused`, ENOSYS is installed, and the refusal is recorded at
   `dispatch.rs:1706-1710` under bucket 228, origin Initial.

**ARM.** The same `service_owner` and `finish()` path evaluate
`HostCrossingSet::Aarch64`, which allows `ClockGettime`. ARM's
`resolve_arm_process_route` maps `Forward` to `Action::Forward`
(`crates/carrick-el1-linux/src/dispatch.rs:2620-2626`), and the host serves
it through `carrick-kernel/src/dispatch/time.rs:358` under the root's
container clock policy (`docs/design/arm-ring-first-flip.tsv:115`,
`Forward-Allowlist`). So ARM serves the root and x86 refuses it.
**Single-lane gap.**

**Fix shape (shared neutral layer).** Serve `clock_gettime`, `clock_getres`
and `gettimeofday` in ring for the root and native children on both ISAs,
from one neutral time handler (`carrick-personality-linux/src/time.rs` plus
`carrick-sched-core` clock state). Then publish the x86 vDSO with a
calibrated TSC so glibc stops making 743 syscalls. Do **not** flip the x86
crossing bit at `crossing.rs:294`: that adds a Forward and is director-owned.
Open draft **PR #2618** (`fix/2420-ring-clock-owner`, "Part of #2028") is
exactly this shape. It covers REALTIME, which is the clock `time.time()`
reads. So this row's owner is #2618 and **no new PR should start**.

**Minimal red witness (production entry, both ISAs).**
- x86: a KVM `cpl0_initial_mm.rs` test where the run root issues raw
  `syscall(228, CLOCK_REALTIME, &ts)` and `syscall(228, CLOCK_MONOTONIC, &ts)`
  with no vDSO, and gets 0 and a plausible timespec. Red on main is
  `-38`. #2618 carries
  `crates/carrick-vmm-kvm/tests/cpl0_initial_mm.rs::serial_host_native_root_and_child_monotonic_clock_gettime`.
  Its REALTIME raw-syscall root case should be explicit, since that is what
  pip hits; #2618's realtime witnesses are vDSO-bracketed.
- ARM: `crates/carrick-el1-linux/src/aarch64_process_tests.rs::native_fork_child_realtime_clocks_reach_time_handler`
  (on #2618). The ARM root is already served by the host forward.
- Row demo: `carrick run python:3.12-slim python3 -c 'import time;
  print(time.time())'` prints a float.

**Next refusals this row will hit** (same census, root, non-fatal today):
`ioctl` (x86 16) ×6, `mremap` (25) ×4, `mmap` (9) ×1, `rseq` (334) ×1 (glibc
tolerates ENOSYS), and one call in the overflow bucket 512, which the
census cannot name. After the clock fix the row reaches `socket()` and DNS,
which is #2418's own list.

## Row 2: x86 npm (`rc 126`, `exec: …: Function not implemented`)

**Symptom.** `node:22-slim`'s `docker-entrypoint.sh` ends in `exec "$@"`
(line 11). On x86 KVM that `execve` returns ENOSYS, and dash reports
`exec: npm: Function not implemented` and exits 126. The director's row
text says `exec: sh`; it is the same call with a different first argument.
`/bin/sh -c 'exec /bin/echo ROOT_EXEC_OK'` fails the same way, so this is
any **root** exec. A fork child's exec is served: the entrypoint's
`$(command -v npm)` subshell forks, runs and is reaped (census: `clone` 1,
`wait4` 2, `exit_group` 2).

**Refused call.** Census `--refusals`: `execve`, x86 nr 59, canonical 221,
caller `root`, **6** unrouted ENOSYS (dash tries each `PATH` entry), 0
carrier-refused, not allowlisted. The per-syscall census shows 6
forwarded and 6 refused. It is first counted as a NativeService forward,
then refused.

**Why.**
1. `route_x86` sends 221 and 281 to `Family::NativeService` (`dispatch.rs`,
   `221 | 281 => Family::NativeService`, witnessed by
   `native_exec_routes_to_the_native_service_on_both_isas`). `finish()`
   records it as forwarded and returns `CompletionRoute::NativeService`.
2. x86 CPL0 hands an exec to the native exec service only when
   `native_exec_claimed(|| process.thread_group_owner())` holds
   (`crates/carrick-x86-cpl0/src/linux_personality.rs:1426-1428`).
   `native_exec_claimed` is `owner == ForkChild`
   (`crates/carrick-el1-linux/src/dispatch.rs:540-544`), and the run root is
   `NativeThreadGroupOwner::Root`
   (`native_process_runtime.rs:5549-5555`).
3. The route stays `NativeService` and falls to the arm at
   `linux_personality.rs:1626-1640`, which calls
   `settle_unwired_native_service`
   (`crates/carrick-el1-linux/src/dispatch.rs:1289-1307`). That records a
   Ring refusal with origin Initial and returns ENOSYS.
4. Even a claimed root exec has no host consumer yet:
   `crates/carrick-x86-cpl0-host/src/cpl0_exec.rs:1572-1576` returns
   "root exec settlement has no custody consumer" for
   `ExecSettlement::Root` (#2142).

**ARM.** On ARM a root exec's `NativeService` route becomes
`Action::Forward` (`crates/carrick-el1-linux/src/dispatch.rs:597`,
`:2620`; `arm_process_call_claimed` at `:547-565` leaves 221 and 281 to the
host for a root). The HVPatch host serves it through the neutral
`carrick_kernel::kernel::exec_transaction::drive_root_exec`
(`crates/carrick-kernel/src/kernel/exec_transaction.rs:327`), called at
`crates/carrick-runtime/src/vcpu_loop/exec.rs:1549`, with
`HvpatchExecVenue: RootExecVenue` (`exec.rs:1794`). So ARM serves root exec
and x86 refuses it. **Single-lane gap.**

**Fix shape (shared neutral layer).** No crossing flip. Give x86 a
`RootExecVenue` and drive the same `drive_root_exec`. Build the successor
with the shared `build_x86_successor` from the same entry a fork child's
exec uses, not a root-only copy. Then give the CPL0 host's
`ExecSettlement::Root` a custody consumer (`cpl0_exec.rs:1574`). Finally,
route the root's 221 and 281 through that owner instead of
`settle_unwired_native_service`. The sequencing is recorded in #2188 (S4c
b→c→d, then #2142 slice 2) and in the director's rulings on #2142 (adopt
crossing owns the Kernel exec; extend the carrier handback, no second
forward form).

**Minimal red witness (production entry, both ISAs).**
- x86: un-ignore the three existing witnesses on main
  (`crates/carrick-vmm-kvm/tests/cpl0_initial_mm.rs:893-926`, each
  `#[ignore = "#2142 root exec: not served by #2273"]`):
  `production_root_exec_replaces_image_and_runs_static_successor`,
  `production_root_exec_of_a_missing_path_is_enoent` and
  `production_root_exec_of_a_non_elf_file_is_enoexec`. Today they return
  `(38, [])`.
- ARM: the root exec already runs through `drive_root_exec`. Pair it with a
  root-exec witness on the HVPatch entry for the same three cases (success,
  ENOENT and ENOEXEC before the seal), so both ISAs prove the same contract.
- Row demo: `carrick run node:22-slim node -e 'console.log(process.version)'`
  prints the version.

**Ownership.** #2142 is open, and no open PR names it: #2343 and #2146 are
closed and #2273 is merged. Its blockers are #2188 and #1093. This is the
next x86 single-lane landable for every node and npm row and for `sh` → `go`.

## How the site was proven

1. **Census.** PR #2650 (`work/2646-refusal-census-zonedump` @ `9ea213339`,
   based on main `63f240a1a`), `just build`, binary SHA-256
   `92ef1e7aae00a0a9eeee15d9d7d6eb6a974cb9a3637cc6cfe83df83b5d9a4d05`.
   - `CARRICK_RUN_ID=diag-pip-1 CARRICK_EL1_CENSUS=… carrick run python:3.12-slim pip install requests==2.32.3` → rc 1
   - `CARRICK_RUN_ID=diag-npm-1 CARRICK_EL1_CENSUS=… carrick run node:22-slim npm install lodash` → rc 126
   - `carrick debug el1-census --refusals <dir>` gave the tables below.
2. **Site discrimination on current main** (`a522eae5e`). A throwaway local
   build made each candidate refusal site return a distinct errno: 80 in
   `settle_unwired_native_service`, 51 in the `finish()` crossing refusal,
   52 in the unadmitted crossing refusal at `dispatch.rs:1846`, and 53 in
   the preflight refusal. Binary SHA-256 `97d34abd…6c40dc4`. It was never
   committed or pushed.
   - `python3 -c 'import time; print(time.time())'` → `OSError: [Errno 51]` = **`finish()` crossing refusal**
   - `npm --version` → `exec: npm: Accessing a corrupted shared library` (errno 80) = **`settle_unwired_native_service`**
   - `/bin/sh -c 'exec /bin/echo ROOT_EXEC_OK'` → errno 80, rc 126

<details><summary>Census refusal tables</summary>

```text
# pip (diag-pip-1)
| rank | syscall | isa | native nr | canonical nr | caller | unrouted ENOSYS | carrier refused | total | allowlisted |
| 1 | clock_gettime | x86_64 | 228 | 113 | root | 743 | 0 | 743 | no |
| 2 | ioctl | x86_64 | 16 | 29 | root | 6 | 0 | 6 | no |
| 3 | mremap | x86_64 | 25 | 216 | root | 4 | 0 | 4 | no |
| 4 | mmap | x86_64 | 9 | 222 | root | 1 | 0 | 1 | no |
| 5 | rseq | x86_64 | 334 | 293 | root | 1 | 0 | 1 | no |
| 6 | overflow | x86_64 | 512 | - | root | 1 | 0 | 1 | no |

# npm (diag-npm-1)
| 1 | execve | x86_64 | 59 | 221 | root | 6 | 0 | 6 | no |
| 2 | rseq | x86_64 | 334 | 293 | root | 1 | 0 | 1 | no |
# per-syscall: execve EL1 forwarded 6, refused 6; clone 1, wait4 2, exit_group 2 served
```

</details>
