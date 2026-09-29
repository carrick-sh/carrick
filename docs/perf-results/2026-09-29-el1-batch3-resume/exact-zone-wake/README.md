# Exact deferred zone handback wakes

Base `55cb799a3`. Task A remains open. The prior signed gate at `8916e1fe2`
precedes this scheduler change and cannot certify the changed source.

## Red reduction

The witness extracts the existing post-thread-key-capture body of
publish_zone_handback into a private method, without changing its behavior.
It captures the original key and record, exits and reaps the child through
the kernel, then invokes that delivery phase. The recording auditor sees a
Reaped rejection, the class the production fatal auditor rejects. No sleep,
poll, added debug hook or weakened auditor is involved. The retained patch
applies to the base source and includes the unchanged-body extraction.

The first command used a short name with --exact and selected zero tests;
zero-selected.log is not red evidence. The fully qualified test ran once and
failed at the intended rejection assertion, preserved in red.log. This is a
deterministic zone-producer reduction, not historical otmp crash attribution.

## Correction

Both publication and direct adoption use wake_exact. Thread execution state
and a matching registered continuation's ID are captured under the same
execution lock as readiness publication. A mismatched registered zone record
returns no target. A thread still running or switching out before enrollment
gets a generation-bound target so its owner can settle. A task already gone
at lookup returns; one reaped after target capture is handled by wake_exact.
The ordinary untyped wake and fatal auditors are unchanged.

Controls cover matching continuation delivery, mismatched incarnation refusal,
and pre-registration handback with one kick and zero added queue rows.
These are VM-free producer/admission checks. They do not prove exclusive
service-record lifetime, complete context restore safety, or all generation
and continuation transitions. Fresh signed execution and full task-A gates
remain required; neither historical blocker is attributed by this witness.

## VM-free validation

All three focused controls passed. Kernel/semantics passed 2,461 tests in
21 binaries (one existing ignore); the later-added pre-registration control
is verified by the focused three-test run, not included in that broad count.
Serial kernel passed 109 (four nested child executions); runtime passed 630
(eight existing ignores and one nested child execution). Affected all-target
Clippy with warnings denied passed, and registry validation passed all 68
contracts. Fresh signed proof remains outstanding for this scheduler change.
