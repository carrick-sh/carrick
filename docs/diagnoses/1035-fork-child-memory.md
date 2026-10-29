# Fork-child memory failures (#1035)

The five signed failures do **not** establish one wrong-child-MM edit.
The source separates a poll/copyout group, an unimplemented native discard
operation, and a permission/signal failure. No runtime repair is included.
The director requested this diagnosis-only stop and an ignored red witness,
because the copyout owner repair is already underway for #898 on
`work/fix-898-copyout`.

References below describe GitHub main `1fd381832b2377fd2b79e8f392a7c8c9f738159b`.
The signed observations are the director's [#1035](https://github.com/carrick-sh/carrick/issues/1035)
table and the detailed [#898 triage](https://github.com/carrick-sh/carrick/issues/898#issuecomment-6485988205).
This Linux host cannot execute HVF or supply fresh signed attribution.

## What the fixtures actually execute

| Test / mode | Trigger and observed boundary | Dependency / remaining work |
|---|---|---|
| `el1_anonymous_permission_transitions_stay_in_guest` / `permission-transitions` | `main.rs:2599` never forks. It installs an SA_SIGINFO handler (`:2640`), maps and initializes private memory, protects it read-only (`:2665`), deliberately writes (`:2688`), then protects it NONE and deliberately reads (`:2693`, `:2705`). The handler restores RW with mprotect (`:2390`). SIGSEGV with no report is not evidence of a child MM. | Separate permission/signal attribution. Retained signal-frame owner copyout may be relevant, but the pipe witness does not prove it. Run this independently after #898; do not declare it fixed by that repair. |
| `el1_anonymous_discard_and_exit_return_frames` / `anonymous-discard-and-exit` | Fork at `main.rs:2938`; child checks inherited bytes, calls MADV_DONTNEED (`:2965`), checks zeros, reports and waits on a pipe. `child discard failed` (`:3010`) folds child semantics, handshake and wait status into one Boolean. | Native discard needs its own in-ring implementation. The handshakes also depend on poll/IPC copyout; #898 alone cannot supply MADV_DONTNEED semantics. |
| `el1_delegated_root_concurrent_vma_ops` / `delegated-root-vma` | Fork at `delegated_root.rs:577`. Child writes readiness then polls/reads the parent reply (`:584`); the failure at `:589` precedes `vma_worker` (`:595`). Parent VMA checks passing do not validate the child's rendezvous copyout. | Depends on copyout repair, including native poll output and IPC retry into inherited COW memory. The failing observation does not implicate child mmap/mprotect yet. |
| `el1_delegated_root_map_fixed_over_cow_pages` / `delegated-root-fixed-cow` | Fork at `delegated_root.rs:890`. Child COW writes, fixed replacements, zero checks and untouched-range checks (`:810`–`:819`) all precede `child-signal-f` (`:821`). Parent's `parent-signal-p` (`:859`) likewise names a handshake. `base_in_16k=0x2000` is context printed for **every** failure, not proof of a bad memory word. A real word mismatch includes page/word/got/want (`:711`–`:722`); the signed lines have none. | Depends on poll/IPC copyout repair first. Re-run the existing byte assertions afterward; no replacement or compound-offset correction is justified by these signed failure names. |
| `el1_delegated_root_kick_then_first_read_publications` / `kick-first-read` | Child poll writes `pollfd.revents` to its stack (`delegated_root.rs:976`), then reads a byte (`:979`). The detailed signed log says `polled=-1 read=1`. Parent's map/touch/unmap kick finishes. | Poll output copyout is the first suspect; the read already succeeded in that observation. Depends on extending #898's owner-memory handling to this ring path, not merely its host readv adapter. Numeric poll errno is still required on HVF. |

## The owner paths and their refusal points

### Delegated anonymous operations preserve the selected MM in the model

`dispatch.rs:2429` calls `serve_delegated_mapping`; `memory.rs:1124`
selects the admitted root from `CurrentTask.mm.key`, not host PID.
`serve_delegated_anonymous` (`memory.rs:922`) locks that root, proposes the
reservation edit, obtains that MM's grant/editor (`:967`), probes backing
(`:979`), and performs protection or retirement before completing the root
transaction (`:1041`, `:1064`). The hardware probe/protect/retire use the fixed
current-MM alias (`memory.rs:736`, `:392`, `:434`) with the supplied root's
physical base. That is an assumption worth testing, **not a demonstrated
mismatch**: production fork explicitly remaps the child's alias in
`carrick-core/src/mm/fork.rs:933`, and initial root relocation remaps it in
`carrick-aarch64/src/stage1_authority.rs:1000`.

The newer fault/portal path uses `service_target_table_window`
(`carrick-el1-abi/src/service_copy.rs:23`) and the target grant, rather than
assuming identity between guest VA and IPA. The two-live-MM witness below
uses real fork publication and confirms distinct roots, separate admitted
identities, inherited read translations and recoverable COW in both MMs.
It finds no wrong-root edit in that component.

### Poll and pipe output lose the memory-preparation obligation

`poll_read_byte` (`fixtures/embed-el1-sched/src/main.rs:1787`) first calls
poll and only reads if poll succeeds. In ring, `dispatch.rs:1933` stages
pollfds and reads their input. It copies the output through `ValidatedCopy`
at `:1988` or `:2023`. Failure immediately becomes EFAULT **14** (`:2002`,
`:2030`), without an owner-memory continuation. Pending poll output similarly
uses the completed-output adapter, so both immediate and resumed output need
coverage. `ValidatedCopy::copy_out` (`carrick-el1/src/file.rs:320`) rejects
an EL0-unwritable destination before copying. Hardware validation uses AT
S1E0W (`:239`); a valid inherited COW page is readable but not yet writable.
That refusal is not an invalid Linux buffer.

For pipe read, IPC's first failed transfer becomes `FaultFirst` and forwards
without consuming bytes (`ipc.rs:761`). Native host-file staging resolves the
descriptor as in-zone and returns `HostFileStage::InRing`
(`carrick-personality-linux/src/native_host_file.rs:767`), bypassing the
output preparation performed for host-backed reads (`:584`). The ARM service
adapter interprets that as an unsupported in-zone call and returns ENOSYS
**38** (`dispatch.rs:1103`–`:1111`). No target root is edited at this point;
the missing step is owner preparation before retrying the retained pipe op.

A staging-only change to return `Fault` would still be insufficient:
after local fault resolution the adapter's loop continues (`dispatch.rs:1137`),
re-stages the same in-zone read and reaches `InRing`/ENOSYS again. After host
supply, the existing `RetrySyscall` path does replay the syscall. The repair
must retain operation/progress and use the existing owner wait/supply route
for both outcomes, releasing object/editor custody before suspension. It
must not forward the in-zone pipe to a host syscall or erase partial progress.

This is a production component counterexample, not proof that every signed
handshake took the pipe-read branch: poll occurs first and is already known
to fail in `kick-first-read`.

### Native MADV_DONTNEED has no ring owner yet

`memory.rs:1137` admits only brk, mmap, munmap and mprotect to the delegated
anonymous route. The personality's temporary madvise crossing is declared in
`carrick-personality-linux/src/crossing.rs:244`. On a native child, unserved
SVCs become `ServiceOperation::Crossing` (`dispatch.rs:753`). Carrier service
supply without a typed backing/COW selection calls `refuse`
(`carrick-vmm-hvf/src/metadata_grant/native_service.rs:682`), and native
completion maps `Crossing + Refused` to ENOSYS **38**
(`native_process_runtime/service.rs:1557`). The host dispatcher's private-anon
discard implementation (`carrick-kernel/src/dispatch/mem/madvise.rs:735`)
is not a native child's syscall fallback.

The separate repair belongs in the shared ring reservation/descriptor and
physical-retirement owner: decommit/zero-on-next-touch, exact MM/generation,
retained backing, rollback-capable publication and the parent's preserved
bytes. It must not add a host fallback or reuse a guest VA as an IPA.
The signed fixture does not print the madvise errno, so **38 is the traced
source outcome**, not a newly measured guest errno.

### Permission transitions need a separate signal witness

The explicit mprotect follows the delegated path above. Its deliberate
protection fault reaches `dispatch_classified_fault`
(`carrick-el1/src/fault.rs:1289`), where a genuinely denied access is not a
COW write to restore. Native refusal forces SIGSEGV with ACCERR or MAPERR
(`native_process_runtime/service.rs:1591`); host-born execution also retains
its legacy host signal route. The root fixture therefore needs its exact
execution-owner state recorded before attributing one of those branches.

Native delivery builds a public frame and calls `process.copy_signal_frame`
(`signal_delivery.rs:183`). That uses the exact process MM
(`native_process_runtime.rs:4307`), through `copy_signal_bytes`
(`aarch64_process.rs:2198`) and `write_user_bytes` (`:2248`). Owner errors
become a failed copy; frame setup failure calls `force_delivery_fault`
(`signal_delivery.rs:190`). If the original signal was SIGSEGV, that path
terminates with SIGSEGV (`:243`). This is a concrete possible explanation
for exit 139, **not a reproduced attribution**. Frame copy wait retention,
handler registration/selection, fault address/code and handler mprotect all
need an independent witness or a signed capture. No loop is proven here.

## Red witness and limits

`carrick-core::mm::publication::tests::fork_child_pipe_copyout_selects_owner_preparation_with_two_live_mms`
uses production reservation admission, `census_fork`, `prepare_fork`,
`publish_fork`, and commit. Both MMs remain admitted and live. Real ARM
descriptor walks prove that the same VA reads the inherited IPA and denies
EL0 stores in each; the shipping COW classifier proves those are recoverable
COW leaves. The child's native pipe-read staging then returns `Some(InRing)`
instead of selecting writable owner preparation. No fake MM, byte-address
identity, or manually constructed child reservation stands in for fork.
The fixture retains descriptor storage and models physical source custody;
it does not claim stage-2 installation, scheduler execution or a host service.

Run the explicit red counterexample:

```sh
cargo test -p carrick-core --lib fork_child_pipe_copyout_selects_owner_preparation_with_two_live_mms -- --ignored --nocapture
```

The observed failure is:

```text
child COW copyout must select owner preparation before IPC retry; native ARM lowers Some(InRing) to ENOSYS (38)
```

The test is ignored with an explicit #1035 reason at the director's request.
It remains a red diagnostic, not an enabled acceptance binding or passing
conformance claim. Existing contracts `kernel.el1.fork-cow` and
`kernel.copyout.owner-refusal` state the required semantics; the future repair
must enable a complete operation witness and retain their work budgets.

## Sequencing and #840

1. Complete #898's retained owner-memory copyout repair. Its
   `from_owner_memory_error` / `CopyoutRedispatch` host mechanisms are relevant
   reuse points, but do not automatically fix direct ring `ValidatedCopy`.
   Include native immediate/resumed poll output and retained pipe reads.
2. Re-run concurrent-VMA, fixed-COW and kick-first-read on the director Mac,
   recording numeric poll/read errnos. These three depend on that integration;
   their present failure lines do not prove wrong-MM VMA publication.
3. Implement native MADV_DONTNEED separately, then re-run discard with both
   madvise errno and handshake results visible.
4. Attribute permission/signal failure separately; no fork is present.

#840's `fork-cow` also uses pipe handshakes (`main.rs:2056`, `:2076`) and may
benefit from copyout repair. Its supplied failure is SIGSEGV with COW
`unreachable` declines, not this counterexample's ENOSYS. **A shared root
cause is unproven**; this witness cannot close #840 or its historical hang.
Keep its signed run and a fault/owner witness separate.

Acceptance remains the original five tests passing 10/10 signed runs, plus
attribution of #840. Nothing in this diagnosis changes budgets, timeouts,
concurrency, routing allowlists, or publication transactions.
