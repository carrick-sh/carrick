# Guest wake publication preparation

Base `26874b0b2`. The host-placement callback's immediate consumer saw a
runnable waiter with one futex queue entry still attached (expected zero).
`guest_wake_publication_has_no_remaining_futex_entry` is red before the fix;
with cleanup inside the destination queue publication boundary it passes
at populations 1, 8 and 32. `red.log` preserves the original failure.

Both the EL1 own/remote-slot wake and host-to-guest wake now remove the old
futex entry under the already-held bucket and destination queue locks,
before releasing the queue lock. They add no lock or scan. EL1 misplaced
classification is computed before publishing the runnable record too, so
it does not read a record the destination may already have retired/reused.
Host wake fallback is deliberately still listed as an open controller red;
this is step 1 of `2026-09-29-el1-handback-publication.md`, not acceptance.

Validation: 54 scheduler-core tests, 74 EL1 host tests, 2,459 kernel/semantics
tests (one existing ignore, 21 binaries) passed. Scheduler-core/EL1 all-target
Clippy with warnings denied passed. Kernel command exited 0. No signed
execution claim is made for this changed source: the prior 49-execution
receipt at 40a707ba0 is historical. Signed promotion and full batch gates
remain required after completing the transfer protocol.

Implementation commit: `a9da3196d`; clean provenance refresh: `68a25b09d`.
All 595 authority rows and positions were unchanged. `just lint-domains`
exited 0 at the refreshed source; its compiler authority result explicitly
covers the macOS subset, with Linux/FreeBSD/NetBSD profiles still pending.
Exact contract-change coverage from `26874b0b2` passed.
