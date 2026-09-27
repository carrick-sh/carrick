# Bounded attribution of retained GNU observations

The public run on `863e81757` reported `ppollwaitset` wake bucket `lt100`
versus cached Linux `lt1`, and `sigprofvdso` timer text sampling `1` versus
cached Linux `0`. No probe or oracle was changed for this investigation.

Run two predetermined samples per probe on frozen predecessor `aa5d55dd6`,
two on corrected `863e81757`, then two on native arm64 Docker. The original
base64/stdin shell transport is preserved. Carrick phases finish before Docker;
no compiler/test job overlaps. Docker is pinned to Carrick's cached April
Ubuntu image with rootfs digest checked. This compares the shared-exec fix,
not the entire EL1 campaign against its starting revision.

All twelve samples exit zero and scoped cleanup is empty. Both Carrick
artifacts and native Linux return `wake_after_ms_bucket=lt1` twice and
`timer_pc_in_text=1` twice. Exact commands, fixture hashes, observations and
cleanup are in `receipt.json`; both raw streams and the runner are retained.

The public-run latency observation did not reproduce in this isolated screen.
The timer sampling value is also produced by fresh native Linux, despite the
committed oracle recording `0`. These results do not establish a regression
from the shared-exec change. They support investigating unstable observational
fields or stale oracle expectations before changing runtime behavior. They do
not prove either issue harmless or repair the original public-run receipt.
Do not re-bless, suppress, widen thresholds, or rerun until green. Deterministic
probe contracts and strict final acceptance remain open; no performance ratio
is inferred from this comparison.

## CI source-position reconciliation

Full CI on `863e81757` stopped at host-authority inventory drift: three existing
`libc::getpid` sites in `trap.rs` moved down three lines. The compiler refresh is
explicitly partial to macOS; six non-macOS profiles remain pending. Position
reconciliation updates those three spans and matching rationale prefixes,
preserving all 588 reviewed classifications and rationale bodies. The capture
hash and source identity are refreshed. Full CI must rerun on the reconciled
clean tree; this metadata correction does not change product behavior.
