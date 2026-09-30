# Deterministic signed delayed-parent notification

Final fixture/source: `2e6e3794abb60c2fa4016742f1c5fd5140118b4a`.
This proves the delayed runtime notification producer against a real guest
reap. It does not attribute the historical otmpfileforkexec failure or accept
the whole batch.

The guest creates root -> parent -> child. The parent's marked sched_yield
waits through the existing interceptor until the child's notification has
captured the exact parent's signal snapshot. A typed lifecycle auditor event
then holds that delivery until root reaps parent. The signed assertion requires
exact ordering captured/reaped/released, one marker, no rendezvous timeout,
successful guest waits/exit, and zero reaped-target wake rejections. Both
rendezvous waits are bounded at 5 seconds; no timing jitter or retry is used.

## Discrimination and provenance

The initial ordering-only fixture passed with both implementations. Those
non-discriminating initial-green and oldwake-nondiscriminating logs/manifests
are retained. They are not acceptance proof. The final fixture adds an explicit
reaped-wake rejection count; the default auditor's Continue disposition alone
could not make the old method fail this embed test.

Controlled red: base `2e6e3794a` plus pre-fix-control.patch replaces only the
HvpatchRuntimeEndpoint method body with `932a33568^`'s untyped wake. It retains
the current fixture and capture event. `red.log` fails the intended assertion:
one reaped-target rejection versus zero, after the ordering/guest assertions.
The script exited 1, its entitlement negative control passed, and both scoped
process counts were zero. Because failed runs do not publish a success manifest,
red-artifact.json was captured directly from the tested executable before the
next build. It includes SHA-256, CDHash, UUID, entitlement digest and DOF. Read
its base revision together with the exact patch and modified-file SHA; the
runner's base HEAD alone does not describe the controlled dirty source.

Matching green: restored the exact wake source byte-for-byte (Git diff empty),
then rebuilt/signed and ran the same final test once. `green.log` passes the
ordering and zero-rejection assertions. The runner exited 0; entitlement
negative control and scoped cleanup passed. green-artifacts.jsonl names the
source and exact executable. Its SHA-256 was independently recomputed and
matched after execution. This is one selected execution, not the full EL1 suite.

Compile check, the existing VM-free notification regression, affected
all-target Clippy, registry and contract coverage passed during fixture
development. check2.log covers the final rejection-count addition. Broader regression results below cover the final auditor event; clean
compiler inventory/domain gates are recorded below. Other deferred-record signed interleavings,
structural notification observations, historical attribution and full batch
acceptance remain open.

## Final broader regression

On `b1f5290b5` (the signed source plus receipt/controller changes), kernel and
semantics passed 2,462 tests in 21 binaries with one existing ignore. The
separate serialized kernel lane passed 110 tests; runtime passed 630 tests
with eight existing ignores. Affected kernel/runtime/embed all-target Clippy
passed. Logs are final-kernel, final-serial, final-runtime and final-clippy.
The contract registry also passed (final-registry). These are source regressions;
they do not enlarge the signed fixture's one-test execution population.

Clean compiler reconciliation on `3fb63f608` retained all 595 rows and their
positions; only the source stamp changed (commit `852fedd48`). Final
`just lint-domains` and contract coverage `257de53e0..852fedd48` passed.
Logs are final-reconcile, final-lint and final-coverage. The compiler census
is the macOS subset only; Linux/FreeBSD/NetBSD profiles remain unqualified.
