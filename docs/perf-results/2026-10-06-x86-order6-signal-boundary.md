# Order 6 signal boundary correction

Base: director-rebased and macOS-recaptured `6bb08a88d` on order 5
`926ccbd46`. The exact CI scanner is red before this correction: nine
`PendingSignals` findings in signal-core. This is an order-6 gate regression.
The prior archived-source comparison used a newer auditor against older
sources and was invalid for baseline attribution; those reports now mark it
non-authoritative and preserve the historical outputs.

## Ownership and unchanged behavior

Linux pending queues, enqueue coalescing, realtime FIFO, lowest-number
selection, thread-first ties and exact-generation inbox admission now live
in `carrick-personality-linux::signal`. All implementation bodies are
identical to the base. The 18 existing Linux policy contracts move to the
personality with one additional import; no assertions, populations, budgets
or policy branches change. Generic signal storage remains in signal-core.
There is no reverse dependency or compatibility re-export.
The surface registry follows the existing lifecycle body after deletion of
`pending_lifecycle.rs` and names the relocated signal implementation and
contracts; contract requirements and checker behavior are unchanged.

Locked all-feature metadata confirms core/core-ABI have no normal/build
signal-core edge, before or after this correction. Neutral lifecycle state
already lives in core/core-ABI and needs no additional signal type. The
order-6 auditor added `PendingSignals` to its forbidden-symbol list; the
checker itself and its allowlist are untouched by this correction.

The standalone ARM scheduler fixture lock records the new personality-to-
signal-storage dependency; its locked offline metadata succeeds.
ARM implementation files and CurrentTask's physical ABI are untouched.
The correction contributes zero ARM production-line delta. Order 6's
previously measured reduction versus `7b6d15813` remains 1,705 production
lines (33,658 to 31,953 across EL1, EL1-ABI and AArch64). The six original
order-6 red dispositions remain as documented in the rebase ledger; this
change touches none of those implementations or assertions.

## Verification

The sibling JSON records exact commands and output tails. The exact scanner
now reports **9 substrate crate(s) clean**. Shared core/core-ABI/personality
contracts pass, including all 18 relocated signal contracts; all 228 EL1
library tests and the 12 signal-core storage tests pass. The CPL0 release
build, KVM X5, entry and progress tests pass. X5 retains 16/64/256 births per
MM, matching 96/384/1536 completions and zero host forwards. All-target
Clippy passes with `-D warnings`; its existing Linux configuration warning
about the macOS-only `libc::proc_listallpids` catalog remains.

Clean-tree inventory reconciliation exits zero with zero moved positions or
fingerprints and all 661 rows preserved. It executes Linux capture profiles
and leaves the macOS capture untouched. **Full `just ci` exits zero**,
including source/static Mac/live Linux authority lint, dependency policy,
portability, build, documentation, host and integration tests.

An initial CI run exposed the stale lifecycle surface entry, now corrected.
A later run inherited the login shell's umask `0002` rather than the required
`022`, making tempfile's default directory group-writable and correctly
refused by the observability artifact test. Every requested focused command
and full CI were rerun with explicit `022` and exited zero. No fixture or
production security check was changed. The JSON preserves both diagnostics.
The final reconciliation also ran on the clean tree under explicit `022`.
The qualified CPL0 image hash remains unchanged after full CI; no load
generators or KVM test processes remain.
Docker and signed HVF are unavailable on this host. No acceptance command
was run. Production executor-pool exhaustion, adopted-job retirement and
ARM signed bindings remain director-owned qualifications.
