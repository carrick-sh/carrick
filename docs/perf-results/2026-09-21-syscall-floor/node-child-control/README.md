# Minimal child control and coarse lifecycle diagnosis

Frozen discard-retirement binary, same pinned Node image as node-phases.
Four independent timed samples per variant after one warm sample; balanced
orders, Carrick then Linux. All 40 runs completed with the expected marker.
File preparation is outside whole-process bash timing (millisecond precision).
No builds or tracing during timing. All raw samples and source variants retained.
The standalone control includes its completion marker and is contextual; do not
subtract it as an exact startup component from the other variants.

| Variant | Carrick median ms | Linux median ms |
| --- | ---: | ---: |
| No child or worker | 95.5 | 21 |
| /bin/echo child, no worker | 162 | 23 |
| Node child, no worker | 187.5 | 34 |
| Standalone minimal Node | 82 | 14 |

Adding echo costs 66.5 versus 2 ms (differences of medians). Replacing echo with
Node costs another 25.5 versus 11 ms. These are work-substitution diagnostics,
not product improvements or confidence intervals. Do not replace original
fixture acceptance with these /tmp variants.

## Coarse traces

Separate bounded captures run five successful echo variants or base variants.
All return and cleanup codes zero; root exited, no errors, markers complete.
Service capture counts close exactly: echo 5,607 and base 4,361
begin/argument/end events. The service sums overlap and are perturbed: they
cannot be subtracted from wall time or read as removable latency.

Across five echo runs, ten fork-total records sum to 7.532 ms and ten outer
exec engine-replacement records sum to 31.259 ms. This includes shell launches;
these are not child-only timing claims. The process-spec ledger has five rows
per phase. Current M:N fork path emits phases 0,1,2,3,8,9, not retired phases
4..7. Spec total11 also encloses appended phases12 (COW range projection) and
13 (parent COW publication), in addition to 0..10. No nested-ledger sum is used.
The script header's initial shorthand 0..10 is incomplete; source enum and
raw rows qualify these appended phases. Exec rows lack guest task identity.

Summed madvise service is 267.542 ms for echo versus 28.377 ms for base across
five iterations. munmap is 42.003 versus 17.989 ms. Expensive madvise rows occur
in parent Node task threads. This directs the next bounded experiment to
post-fork discard/zeroing and its shared/unaligned backing eligibility, rather
than optimizing the already short fork setup ledger.

Next capture advice, requested alignment/length, and actual scrub/retirement
outcomes for those requests; then use a red-first contract and original-fixture
paired intervention if the expensive fallback is avoidable. Merely reducing
trace totals or skipping required discard semantics is not acceptance.
