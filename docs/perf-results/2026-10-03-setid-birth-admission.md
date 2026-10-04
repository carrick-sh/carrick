# Credential broadcast during thread births

## Attribution and reproduction

The isolated `setidthreadchurn` GNU probe passed 20/20 on main `fda4e0350`
on this gate Mac. Its full generic shard and the complete three-shard signed
generic gate also passed. This does not explain the earlier failures reported
on main: their cause remains unproven on this box.

The director identified the failing gate artifact as Phase B `b5f739d5d`.
The same isolated probe failed 6/20 on that exact signed artifact, with guest
exit 134, 86 traps and empty stdout in every failure. Failures were runs
1, 3, 5, 11, 15 and 18. The musl variant passed every run. The director
approved rebasing `work/setid-churn` onto Phase B to fix this attributable
regression.

Each repetition was foreground, untraced, and stamped with its own
`CARRICK_RUN_ID`, followed by `scripts/sudo/kill.sh <run-id>`. No Docker or
load generator was used. This is a reproduction count, not a controlled
performance measurement on the shared host.

Artifacts:

| Artifact | SHA-256 |
| --- | --- |
| main signed shard 0 | `6a501ad52589df232c39dca849a4d7c7b38d9eda84df936277c42575e08a2047` |
| Phase B signed shard 0 | `fb9216676f6abe64d738fd2fe68506a166ab0d8580e92639f04d815d170b3e0b` |
| Phase B CLI used for trace | `862e3f4de2302f7923743a9fb9b08d9daa1ceed75a498eec18b3a08dea20d259` |
| GNU guest probe | `0e07e1d0a784524d3bd27a6c3b89ff781b010b335b1ccc41e9a39580fea3eea6` |
| musl guest probe | `458ce6ae8280e5806d4fa9f9c2fd6effdedb6f67955c0fe8db484db6ce9e430b` |

Main shard CDHash was `97f1d9ebb1cfdd373fc6c85986b53921ad110021`, UUID
`C0F6B428-FA4A-3470-9D91-4E1A17408E0F`, with the hypervisor entitlement and
`__dof_carrick`. Detailed signatures, logs and scoped cleanup evidence live
under `target/setid-evidence/`; subsequent signing changes identity.
Phase B shard CDHash was `fe7a04095219ad0591070cbef58122cd4f53fbbb`, UUID
`DFE87ABA-2D2B-38F7-A1ED-60536AA2A7B5`, with the same entitlement and DOF.

## Positive trace and debugger evidence

`carrick trace -s scripts/dtrace/setid-thread-broadcast.d` ran the Phase B
CLI externally, mounting the prebuilt GNU probe at `/tmp/p` and musl
`probeinit` at `/tmp/carrick-init` in `ubuntu:24.04`. Run ID:
`setid-pb-trace`. The completed stream recorded 136 entries, 99 returns and
42 signal deliveries. It captured the following events:

- Sibling calls to `setresgid(21, 0, 201)` returned 0.
- Linux tid 12's same call returned -11, errno 11.
- That tid issued `tgkill(7, 12, 6)` and received SIGABRT.
- The parent exited 134; scoped cleanup left zero survivors.

This is evidence of inconsistent raw setxid results, not a missing signal
acknowledgement diagnosis. Per-event tracing perturbs scheduling. The embed
test executable installs signal hooks without the compat return hook, so its
empty syscall-return stream cannot answer this question; the durable D script
documents that live qualification.

A private copy of the Phase B CLI was signed with debug entitlements and
run through `carrick debug lldb-run --stop-on-signal 6`. Run
`setid-pb-lldb-2` captured a real modified-memory core and all host stacks;
`assemble_run_result` showed guest exit code 134. The stopped-process kernel
debug request timed out, so no coherent kernel census is claimed. The core,
manifest and transcript remain under `target/setid-evidence/lldb/`. The
director's original executable was not modified.

## Architectural correction and red-first witness

[setresuid(2)](https://man7.org/linux/man-pages/man2/setresuid.2.html) and
[nptl(7)](https://man7.org/linux/man-pages/man7/nptl.7.html) distinguish
per-thread kernel credentials from libc's signal-based synchronization.
Phase B added `BirthAdmissionGuard::acquire` to `Kernel::update_credentials`.
That process-wide close refuses a claimed sibling birth or a concurrent
credential close; the credential dispatcher translates refusal to EAGAIN.
NPTL can therefore observe different results across its broadcast and abort.

Remove that close from credential publication. Keep the settled registry
write transaction, exact caller resource validation, and CAS revocation of
unused identity credits. A sibling's birth uses its own caller's credentials.
A caller cannot execute clone and set*id simultaneously; its completed Born
is settled before its own credential COW. No polling, retry, timeout change,
continuation, or worker serialization is added.

The VM-free `setid_birth_admission` dispatcher witness failed before the
implementation change with `Errno { errno: LinuxErrno(11) }` instead of
`Returned { value: 0 }`, while one sibling birth remained claimed. It covers
1/8/32 pairs of uid/gid transitions and asserts one dispatcher invocation per
transition, unchanged sibling credentials, and preservation of the claim.
Ledger witnesses cover actual ABI Born publication after a sibling credential
change, completed own-caller birth settlement before COW, and exact uid-wide
`RLIMIT_NPROC` refusal/release across two live processes.

Contract: `kernel.credentials.birth-admission`. The committed generic oracle
remains the Linux output authority. No refreshed Docker differential or
runtime-ratio acceptance is claimed for this task.

## Fixed isolated signed result

After the correction, the untraced GNU probe passed 20/20 with zero DIFFs;
musl also passed 20/20. Run IDs were `setid-fixed-measure-1` through `-20`,
with zero survivors after every scoped cleanup. The preserved signed shard
is `target/setid-evidence/fixed-probes-shard-0`, SHA-256
`97b78024fab9ed81a682bac01c3e16e9cc3302ab52f68018fb0331cb23afaa3b`, CDHash
`eef49fbb2effa3c3a3deb30d15dbd00081f898d5`, UUID
`2A7B9C4B-8A8C-36D4-BF9E-5DA68AE5CD71`, with the hypervisor entitlement and
`__dof_carrick`. It was built from the Phase B base plus this correction and
witnesses; it precedes the final committed-tree acceptance artifact. The
signed harness's unentitled negative control also passed.

`just test-kernel-semantics` (including the new dispatcher witness) and
`just clippy` passed. The first `just test-kernel` stopped at
`authenticated_exec_returns_an_opaque_same_carrier_capability`: the carrier
control server reported host errno 35 and the client reported unexpected EOF;
2387 kernel tests passed, including both new ledger witnesses. That control
source is unchanged between main, Phase B and this correction, but no
pre-change binary reproduction of this separate failure is claimed. The
original failed log remains in `target/setid-evidence/test-kernel.log`.
Committed-tree host and signed acceptance is recorded separately by
`just accept` under `target/el1-gate/<commit>/receipt.json`; the isolated
passes above do not confer full acceptance.
