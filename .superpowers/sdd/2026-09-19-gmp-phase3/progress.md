# SDD ledger — plan: docs/superpowers/plans/2026-09-19-gmp-phase3.md

Direct implementation resumed in existing codex/gmp-phase3 worktree. No tasks
are fully complete; the tracked plan contains the prior receipts and full scope.

Pre-flight: scheduler token is consumed by runtime submission, selected syscall
dispatch, MM admission and captured-file authority. Diagnostics and signed/embed
bindings consume those same ownership transitions; foundation tests cannot close
those downstream interfaces.

Task 2: Ruling: owned flush operations consume the remainder of their captured
file-table scope rather than reacquiring a functional lease while waiting for P.
The endpoint is already pinned and handlers perform no later table lookup.
Reacquiring early would recreate the retirement cycle; an accidental subsequent
lookup fails closed. Other I/O paths must be audited before using this boundary.

Task 2: retirement red evidence: core
`/private/tmp/gmp-phase3-retirement-92463.core` showed original executor waiting
for P while replacement blocked in FileTableFunctionalGate::retire on the
original dispatch's functional lease. Captured before scoped test termination.
No retries, larger budget, or shared-file-table substitution used as closure.

Task 2: public injected sync regressions now pass (2/2): replacement MM mutation
and private-file-table thread retirement. Retired return is HostWaitRetired,
not guest errno or a restored MM admission.

Task 2: production terminal routing regression red exit 101 (treated retirement
as error), then green 1/1: finishes ThreadDone without engine/register writes or
process-wide terminal work. Focused routing proof, not signed execution proof.

Task 2: additional MM retirement/unwind fixture initially failed because it tried
exit_thread on the last thread; added a surviving sibling. This fixture failure
is not runtime red evidence. Retest passed 2/2: normal return/unwind restore
MM+P; retired return/unwind restore P but retain zero MM participants.

Pending: full host gates, source-local inventory completion, other host waits,
pre-park race, diagnostics and structural budgets, policy/embed/backend bindings,
same-artifact signed acceptance and default-sizing proof. No completion claim.

VM-free gate after retirement correction: `RUSTC_WRAPPER= just test-kernel`
exit 0, log `/private/tmp/gmp-phase3-test-kernel.log`. Parallel kernel 2064
passed/1 ignored, serial kernel 1 passed, semantics including 12 handoff cases
passed. Later diagnostic additions require a new gate receipt.

Task 3: actual runtime debug provider red exit 101 (host_wait field Null),
then green: exact enter/resume counters at scales 1,8,32 and retained claimant
identity/CPU/slot ownership. Census uses try_lock and returns None on contention.
Counter overflow fails closed. Wire-invariant tests pending.

Task 3: wire-invariant regression red exit 101 (resume count beyond enters
accepted), then full kernel gate green. Validation now rejects count mismatch,
duplicate slot/owner/waiter identity and an owner also waiting. Contention test
proves the abort/debug reader returns unavailable without waiting on the ledger.
Sibling handoff integration checks the replacement's exact slot ownership.

Broader host receipts before final unwind-audit tightening: full test-kernel
exit 0 (2066 parallel kernel tests, 1 existing ignored; serial and semantics
including 12 handoff tests green). Runtime lib serialized: 578 passed, 1 existing
ignored. Targeted all-target clippy for kernel/example/runtime/embed exit 0 after
fixing one fixture-only intentional-panic allowance. No lint relaxations in
production. Final unwind audit now mirrors existing MM helper fail-closed rules
instead of allowing an audit error to suppress a panic; final rerun pending.

Final checkpoint rerun: exit 0 for chained test-kernel, serialized runtime lib,
targeted all-target clippy (kernel/example/runtime/embed), and fmt-check. Logs:
`/private/tmp/gmp-phase3-test-kernel-final.log` (2066 parallel kernel passed,
1 ignored; serial/semantics green), `/private/tmp/gmp-phase3-test-runtime-final.log`
(578 passed, 1 ignored), `/private/tmp/gmp-phase3-clippy-final.log`, and
`/private/tmp/gmp-phase3-fmt-final.log`. Diff whitespace check clean. These are
host-only receipts, not signed guest or whole-workspace CI acceptance.

Fanout checkpoint: added public-API `host_wait_cancellation` peer-exec test.
Focused run passed 1/1: exec graph replacement progresses while actual injected
sync is blocked, exact spare owns the slot, and original dispatch terminates as
HostWaitRetired with balanced enter/resume. No bound production ThreadRunner or
direct predecessor MM census is tested; production runner drain remains open.
Static remaining-seam audit is in `host-wait-seam-audit.md`.

Scalar stdio experiment: two injected writer tests were red on the unchanged
path (replacement cannot progress during blocked writer). Owned bytes, pinned
inherited endpoint, and writer locking inside handoff compiled/linted, but the
normal-return regression aborted. LLDB identified execution.rs post-I/O
epoll_rearm_after_io reaching CapturedResources::files after the consuming
boundary. This is not safe to solve by skipping epoll or reacquiring a frozen
table lease with P held. The unaccepted experiment (including its red fixtures)
is preserved separately in `stdio-handoff-experiment.patch` and withdrawn from
compiled source. Next: capture exact target/epoll owner/registration generation
before handoff, then table-free completion against still-matching live slots,
including BSD rebind dependencies and concurrent MOD/DEL/close/reuse tests.
Scalar stdio, vector I/O, contract bindings, policy composition and signed
acceptance remain incomplete. No defaults changed or completion claimed.

Retained-source verification after withdrawing stdio draft: scheduler_handoff
12/12 and host_wait_cancellation 1/1 passed together. Diff whitespace clean.
Debugger-launched processes 10920 and 10955 confirmed absent. Earlier full
checkpoint receipts remain distinct from these new focused results.

Scalar stdio resumed: reproduced saved fatal (SIGABRT) before epoll correction.
Ruling: stage scalar-write epoll receipts in threaded dispatch before executing
the handler, then complete from exact description/owner/generation identities —
post-return numeric lookups are both consumed-authority and fd-ABA hazards.
No table functional lease or description mutex spans host wait. BSD rebind
recomputes current interests using exact descriptions, preserving MOD/DEL.
Cost if wrong: edge delivery can be lost or delivered to a replacement; focused
consumed-scope, outcome, MOD, DEL/ADD and epoll-fd reuse tests passed 5/5.
Removing generation validation made DEL/ADD regression fail (old completion
cleared the new latch and incremented its io_gen); restored before full gate.

Audit correction: current epoll_ctl requires target_file from open_file;
production ADD cannot create target=None. Old bare-stdio comments are stale.
Bare writes therefore have a deliberately empty owned receipt, while duped
stdio has an exact HostPipe description. Arbitrary bare-stdio epoll support
is not newly implemented or claimed here.

Initial scalar stdio/MM and retirement regressions now green: 14/14 handoff
tests. Additional redirected-stdio and short-write/error tests added; full
test-kernel pending. Inherit pins a duplicate before handoff, Captured stays
in-memory, and Piped acquires its writer mutex only inside the host operation.
Vector/transfer paths still use their old helper and remain inventoried work.

Policy lane: actual embed AdversarialPolicy and RecordReplay composed with
public Scheduler at 1/8/32 tasks, pinned P1, exact completion/census and zero
replay fallback. Focused 2/2 passed; not signed guest proof. Initial fixture
assumptions about lazy spare acquisition and active-slot census were corrected;
those failures are not runtime red evidence. One stranded fixture process was
terminated by exact PID 14808, not broad cleanup.

Superseding epoll ruling after source audit: the first receipt design captured
too early (before the handler independently selected its target), and freezing
registration generations missed a watch added while I/O was pending. The
DEL/ADD mutation above proves a comparator, not the correct completion contract;
its expected semantic result is superseded. Two corrected regressions were red
against frozen receipts (new watch latch remained OUT) before correction.
Handler now stages its actual selected target into owned dispatch-scope state;
completion enumerates current owners/registrations of that exact description.
No target fd or epoll fd is re-resolved, and MOD mask/data remain current.
Six focused rearm cases passed, including reused writer number remaining
untouched and new watches of the original description receiving consumption.
Cost if wrong remains missing or misdirected edges; signed/Linux proof is open.

First broader stdio test-kernel run passed before that audit correction (log
`/private/tmp/gmp-phase3-stdio-kernel.log`); it is not acceptance of the newer
source. Current redirected/error/unwind and full host reruns pending.

Current focused handoff/cancellation gate passed 19+1 tests, including bare and
redirected injected writers, short-write suffix/error behavior, normal unwind,
and retired unwind. Exact one enter/resume asserted. Targeted all-target clippy
(kernel/example/runtime/embed) exit 0; log
`/private/tmp/gmp-phase3-stdio-clippy.log`. Fresh full kernel, serialized runtime,
policy and format chain now running; no signed guest or default-sizing claim.

Wrap-up requested; user also requested rebase on main. Pre-rebase final host
chain exited 0: 2072 kernel parallel passed/1 existing ignored, serial and
semantics passed; runtime 578 passed/1 ignored; policy 2 passed; fmt passed.

Rebased codex/gmp-phase3 onto local main a58a89c219574b9aaad382db67fcf7206dd300f5.
All work remains uncommitted. Recovery stash
bb93803fdb9ec55a386858a04e2b2ac09ef97224 retained, already applied once; do not
reapply it. No conflicts; embed lib reexport auto-merged. Tracked patch ID
2c9ac50f95307245778415f7a9c95f474f49dbd0 identical pre/post; all 12 original
untracked file hashes matched. Main checkout untouched; no push.

Standalone resume document:
docs/superpowers/plans/2026-09-19-gmp-phase3-handoff.md.
All subagents stopped; contention fixture not started/no partial file. Fresh
post-rebase host gates running, results recorded in the handoff before stopping.

Post-rebase results: kernel gate passed (2072 parallel passed, 1 ignored, plus
serial and semantics); runtime 578 passed/1 ignored; policy 2 passed. Clippy
stopped the chain with four needless_borrow errors in inotify.rs (1226, 1248,
1265, 1266), a file verified unchanged from incoming main. No unrelated fix
made. Full acceptance remains incomplete; detailed receipts are in the handoff.

User requested logical commits and fast-forward to main if ready. Saved the
implementation and internal tests as 4f36777b9 and public regression suites as
58313ffeb, with separate debugging documentation and handoff commits. Fresh
checkpoint host chain exited 0: kernel 2072 parallel plus serial/semantics,
runtime 578, embed policy 2, format clean. Existing ignored tests unchanged.
Logs: /private/tmp/gmp-phase3-checkpoint-{kernel,runtime,policy,fmt}.log.
Integration condition is not met: signed acceptance, contract binding and
broader gates remain open; incoming-main clippy failure unresolved. Main left
unchanged, including its three unrelated untracked plans. Resume the committed
codex/gmp-phase3 branch using the standalone handoff.

Subsequent explicit user direction supersedes the integration deferral above:
fast-forwarded local main to f3c8685f2 and made the handoff checkout-independent.
No push; unrelated checkout changes preserved. Post-merge just test-kernel
exited 101: 2072 parallel kernel tests passed/1 ignored, but semantics had
78 pass and futex_contention::futex_pi_lock_unlock_deadlock_detection fail
with "continuation build failed: failed to pin an exact fd description".
No retry or attribution claim. Log /private/tmp/gmp-phase3-main-kernel.log.
Concurrent inotify.rs edits appeared during validation and were left untouched.
The standalone handoff records this new blocker for the next session.
