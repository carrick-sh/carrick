# Carrier-wide descriptor ceiling: proposed change, not implemented

## Problem and evidence

Current ca2dcc810 signed artifact7055c9d3 passes public probes but smoke is22/23: subprocess exceeds44s. Fresh pinned native arm64 Docker completes341tests/44skips (297passes) in20.3s. The historical instrumented case comparison attributes27.833s of excess to five descriptor scans (28.387s total excess among62 observed cases). Current sampling ranks83% of retained samples in the opaque guest/HVF execution path, not fstat service. Existing mailbox transport reaches174passing assertions but still exceeds44s. These are diagnostic facts, not a promised speedup.

## Alternatives and decision

1. Continue tuning host-side fstat dispatch: simplest but little profile support; not selected.
2. Exact per-FileTable ceiling: precise but adds cross-MM sharing and per-thread rebinding machinery; not selected.
3. Carrier-wide monotonic ceiling: recommended. A conservative superset avoids thread-table rebinding while preserving every guest descriptor and limit. One unusually high descriptor reduces effectiveness permanently for that carrier; it never creates a false EBADF.

## Contract

A carrier owns one ceiling C, initially at least2, that is never below any descriptor ever made visible in any participating FileTable. Before either insertion seam publishes a valid descriptor N, it raises C to max(C,N) with release ordering. Closing, fork, exec, unshare, failed allocations and cleanup never lower C. No process-global static; ownership and lifetime are explicit per carrier.

Only AArch64 fstat is eligible initially. EL1 may return EBADF for a correctly decoded fd greater than C only while the carrier mapping and policy gate are valid. Every in-range, disabled or uncertain case takes ordinary host dispatch with all syscall arguments preserved. Do not change RLIMIT_NOFILE, SC_OPEN_MAX, test source, oracle flags, timeout, transport default or other syscalls to obtain a pass.

## Ownership and wiring

Add a small kernel-domain descriptor-ceiling authority shared by FileTables. A backend-neutral publisher connects it to an owned carrier-global atomic backing. Both FileTable::install and FileTableWriteGuard::insert publish before map insertion. Fork/exec constructors inherit that authority; imported tables must join and publish their existing maximum before guest entry. Empty constructors cover implicit stdio. No mutable map escape is introduced.

The backing joins PersistentCarrierMappings and the persistent executor mapping specification, is read-only to EL1 and inaccessible to EL0, and is the same backing in every root/MM. All mapping replay, exec rebuild and teardown paths retain that ownership. The guest-entry gate remains closed until authority registration, initial population and all required mappings are complete. Mapping failure or absent authority falls back to ordinary dispatch, never to an assumed low ceiling. A copied snapshot of C is insufficient.

The EL1 sequence must preserve x0..x5 and every existing scratch-register contract. It uses an acquire load paired with release publication. The current identity guard cannot be copied directly because it clobbers x0. Keep the optimization separately disableable for comparison and fallback; enabling it must not implicitly select mailbox transport.

## Policy and accounting

Eligibility must explicitly cover fstat in container policy, interceptors, seccomp, ptrace/audit observers and CPU accounting. Any policy requiring a host boundary disables this path before publication. Pending signals must remain deliverable under continuous fast-path calls, and CPU limits must still fire without subsequent host syscalls. Reuse identity-path lifecycle machinery only after tests establish these obligations for argument-bearing fstat. Unsupported policy combinations use host dispatch. Do not infer fstat eligibility from getpid eligibility.

## Policy review correction from current source

Do not assume existing identity shutdown is an atomic EL1 policy gate. In dispatch/proc.rs, successful seccomp installation calls disable_identity_syscall_shim afterward; that helper discards guest-memory write errors. seccomp.rs separately closes a host atomic before filter publication, but that is not proof that the EL1-mapped word observes the same ordering. The new path must use an authoritative gate whose successful close precedes policy visibility, or remain disabled for the affected execution topology. It must not copy the ignored-write-error pattern.

ContainerPolicy::wants_fast_path_visibility currently checks only IDENTITY_FAST_PATH_SYSCALLS, which excludes fstat80. Add explicit fstat eligibility rather than assuming the current Blind result permits this new operation. Tests must install a policy that rejects fstat and prove it remains observable even for a descriptor above the ceiling. Also test policy installation while a sibling executes the fast path and fault-injected gate publication failure. This review identifies requirements for the proposal; it does not by itself prove an exploitable existing runtime failure.

## Red-first proof and acceptance

Before enabling runtime behavior, add deterministic tests exposing a deliberately missing/late publication, including install, guard insert, concurrent readers, fork, exec, clone-files sharing across MMs, and close-range unshare within one MM. Exercise inherited/imported high descriptors, signed-width FD decoding, high duplicate followed by close (ceiling does not fall), failed insertion, carrier isolation, mapping replay, startup gate and teardown.

Signed guest probes must compare Linux outcomes for valid and invalid high descriptors, nonzero arguments on forced fallback, seccomp interception, observer visibility, signal delivery and CPU limits during repeated fstat. Demonstrate red on a broken variant and green on the candidate. Performance proof separately checks that invalid-above-ceiling calls avoid host exits while valid/in-range/policy calls retain host dispatch; traced counts are not timing acceptance.

Use same-image same-host ABBA for the raw reducer and the unmodified five descriptor tests. Then run appropriate host checks and freeze a clean signed artifact with complete provenance. Public probes -> smoke -> full2127 rows must all pass, with scoped cleanup after each rung. A failed rung blocks promotion. No retries-until-green, new gaps, deadline changes, push, or performance-only closure.

## Review status

Source-reviewed with Sol. Feasible, but requires the new publication/mapping bridge and argument-preserving policy-aware handler. No implementation or default change has been made. User approved implementation on 2026-09-14.
