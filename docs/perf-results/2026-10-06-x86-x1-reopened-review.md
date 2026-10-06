# X1 increment 1 reopened-review witnesses

These are scoped Linux x86_64 KVM/VM-free results. They do not close X1's
protect/unmap/remap and cross-MM hardware transfer increments, whole N1,
OCI carrier execution, or the signed ARM regression gate. No Docker ran.

The five fixes have distinct production-path negative controls:

| Finding | Witness | Restored-code failure |
| --- | --- | --- |
| Full grant capacity | Core `x1_full_size_owner_grant`; KVM `x1_shared_mm_owner` now includes 512 pages | Core journal-capacity refusal; CPL0 halting allocator at the spill boundary |
| Parked-executor wake | KVM `x1_shared_mm_owner`: actual MM editor release after `serve_grant` | Remote executor remains at STI/HLT until the existing five-second fixture deadline |
| Guest/host wake address | KVM `host_mm_release_uses_carrier_retained_wake_bindings`: actual MM root unlock with the carrier-published guest address | Host process dies with SIGSEGV instead of dereferencing a retained host alias |
| Unsafe grant facade | `serve_cpl0_grant` compile-fail doctest | Old safe facade makes the unqualified call compile, failing the doctest |
| Personality errno | KVM `x1_shared_mm_owner`: valid submission for the wrong carrier reaches core Stale refusal | Old adapter returns 403; Linux personality requires ESRCH 3 |

The wake witness executes both existing native vCPUs. The waiter is enrolled
on the real MM editor notification, then its executor enters shared idle
admission and native STI/HLT. The owner calls linked `serve_grant` in CPL0;
its editor release publishes the shared queue and sends the existing xAPIC
wake. The waiter acknowledges the native interrupt, takes the same shared
queue claim, reauthenticates its retained context and completes an ordinary
robust-list syscall before returning a user observation. No callback called
by the test supplies the completion or wake. The two-vCPU native fixture is
not evidence for the full production executor-pool population gate.

The same production MM release transfers a host continuation to the existing
completion chain. Its native return boundary drains that chain into the
carrier's exact-record consumer. The witness checks the record incarnation,
Host claim and saved operation, and proves there is no duplicate consumption
or placement. Removing that boundary consumer leaves the expected record
absent. A refused transport in the actual host root-unlock witness leaves the
remote destination bit in the retained owner binding; removing retention
makes that bit zero instead of two. Busy native delivery is never polled.

Host callbacks borrow qualified host aliases and their execution transport
for the guard lifetime. CPL0 callbacks accept only the fixed slot-qualified
supervisor binding interval. Context sidecars occupy their own retained
region rather than overlapping the residency authority. Planning and apply
share one bounded 518-entry retained plan for the production 2 MiB ceiling;
there is no private x86 heap and no larger syscall stack.

Focused verification: CPL0 image build; core x86_acceleration (15), MMU core
(121), sched core (230), EL1 ABI (134), EL1 lib (239), personality-boundary
contracts (48), x86 lib (57), unsafe-entry doctest (1), KVM carrier_memory
(8) and cpl0_entry (5); Clippy with -D warnings; fmt-check; five locked signed
fixture manifests. Host lint inventory positions are reconciled on a clean
snapshot. Raw commands and outputs are in `target/x1-review/finding*-*.log`
on carrick-vm. The director owns signed artifact and ARM regression evidence.

## Rebase onto the signed comparison baseline

The director requested exact base `56bf8c0caefe39fcc2260345d0a54772a74bffad`.
It contains the order-4 shared wait/lifecycle changes and exit revision custody
absent from the original `229194ae6` base. No complete X1 commit was dropped.
The range audit below names the original commits; rebased subjects are unchanged.

| Original commit | Disposition |
| --- | --- |
| d7476ac73 | Ported: initial boot retained; redundant fixture-lock hunk already in the new base omitted |
| ab6a98ab9 | Kept: explicit revert of the preliminary boot |
| 21020bff4 | Kept: production shared admission |
| 902dbec28 | Kept: in-place zone and one-shot admission |
| d6afab125 | Kept: admission witness and dependency cleanup |
| 2d0d03758 | Kept: distinct COW-owed refusal |
| ee62006e1 | Kept: linked core grant owner in CPL0 |
| 57412e832 | Kept: removal of unsupported protect/retire claims |
| c004739c1 | Kept: qualified table-word interval |
| a3add1a4e | Kept: missing-carrier refusal |
| f07965c07 | Kept: Linux errno conversion |
| 80dbaf9ea | Kept: bounded overlay lookup |
| 22f61858d | Kept: bounded journal, subsequently strengthened to the full ceiling |
| df605a239 | Kept: effects publication, subsequently strengthened to real native wake |
| 0d98f6ef9 | Kept: one shared anonymous owner body, ARM switched |
| 97690b0d9 | Kept: one shared transfer admission body, ARM switched |
| 41ca025b6 | Kept: full 512-page grant and retained in-place execution |
| 2e4b2b84f | Kept: unsafe qualified facade |
| a971a9d60 | Kept: actual core-refusal errno witness |
| 9bda63605 | Ported: borrowed retained delivery through the new shared order-4 wait helper |
| f4ae120e2 | Ported: native wake/consumer; retained sidecar TLS/XSAVE and boot-qualified zone accessor |

The order-4 wait/lifecycle bodies and exit revision custody from the new base
remain intact. ARM venue callers borrow their existing callback without changing
its behavior. The unused public x86 portal alias was removed and the guest
venue made private: safe host guard construction must use retained host
bindings. The safe carrier zone accessor now refuses ordinary boot's absent
metadata instead of creating an out-of-bounds reference.

Red controls were re-executed after rebase, not inherited from old-SHA results:
`target/x1-review/rebase-reds.log` and `rebase-red-*.log`. They restore historical
259-entry planning/journal, safe facade, 403 adapter mapping, flag-only wake,
guest-pointer host delivery, missing handback consumer, and dropped failed-wake
retention. Every control reaches its named failing production-path assertion.
Missing-carrier fallback and linear overlay were also restored and fail their
production refusal/work-budget assertions. Each hardware control rebuilds and
retains its own ELF and SHA-256 (`rebase-*-image.elf`); none shares a stale image.
The older direct-errno and flag-only tests were replaced by these stronger
production witnesses. Removal of unsupported edit claims has no runtime body
to restore and is audited as a scope correction.

Fresh green evidence is `target/x1-review/rebase-final-gates.log`, with clean
host census in `rebase-final-lint.log`. Signed/HVF evidence remains pending on
the director's macOS lane; Linux results do not confer signed acceptance.

Order-4b resident-line audit (the plan lists symbols rather than a numeric
line forecast): anonymous move `memory.rs` 2144 -> 2043, net -101;
transfer transport `production.rs` 506 -> 498, net -8. No other
`carrick-el1`, `carrick-el1-abi` or `carrick-aarch64` file changes in those
commits: their combined aarch64-resident reduction is 109 lines. Both are
body moves, not seams around retained implementations. Later moves must
report the same resident-line comparison.
