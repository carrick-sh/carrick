# Native x86 xstate transfer strategy

**Status:** Phases 0–3 implemented and exact-workload gated; full pinned-LTP artifact gate active
**Target:** FreeBSD/amd64 native DSR
**Risk:** high — gateway assembly, dynamically patched control flow, signal exits, and Linux task snapshots share the contract

## Evidence

A clean kernel-only profile of the pinned LTP source build recorded 4,888 samples in five seconds. The DSR gateway accounted for 2,993 samples (61.2%), primarily around full xstate transfer. Repeated gateway context copies were already eliminated: `memcpy` callers were 68 samples (1.39%).

The conservative runtime switches xstate for `has_edges || uses_fpu`. The original target-only chain-gating experiment failed because its local state classifier omitted opmask-only K-register instructions:

- a mixed integer-to-cached-FPU reducer expected `37` and observed `-121634175`;
- focused XMM tests passed, so they were not a sufficient oracle;
- exact Kaniko apt/GnuTLS failed with ASN.1 parser and `apt-key` errors;
- restoring the conservative policy restored the workload.

Phase 0 then made that mechanism exact. With every direct edge held cold, apt-key descendants repeatedly faulted at libc `vmovdqa64 1(%r11),%zmm6`. The immediately preceding block was `mov %rsi,%r11; kortestq %k3,%k3; jne ...`; `kortestq` was classified neutral, so host `%k3` set the wrong flags and fell through with an invalid pointer. Adding K/TMM/BND register classes made the red-first opmask regression and the exact Kaniko apt/GnuTLS build green (RC 0, 184.65s).

Phase 1 keeps conservative guest ownership but seeds the persistent host image with full XSAVE and uses full-mask XSAVEOPT thereafter. A deterministic FreeBSD test alternates affinity between two CPUs around blocking `nanosleep(2)` and compares semantic XMM/YMM/ZMM/opmask/x87/MXCSR/PKRU state; it passes without stale components. On the exact cc1 profile, the host-save hotspot fell from 492 to 202 samples and total gateway share from about 55% to 51.9%. Two 20-output timings were 202.70s and 202.85s versus 205.53s before the change.

Phase 2 adds the explicit `neutral-domains` policy. Locally proven neutral blocks preserve whichever physical owner entered; state-using/unknown targets remain cold, and nonzero virtual guest PKRU forces guest residency. An early implementation accidentally executed CPUID on every entry while locating PKRU in the XSAVE image; a fail-closed profile exposed 3,559/4,965 samples there. Component geometry was first cached, and PKRU is now a scalar virtual field that needs no geometry lookup. The corrected cc1 run completed in 137.78s, 32.0% below Phase 1, and gateway share fell from 51.9% to 15.1%. The full runtime integration gate and exact Kaniko apt/GnuTLS build pass under the policy. Conservative remains the default rollback.

Phase 3 adds one gateway-owned monomorphic cache for `ret`/`ret imm16`. Emitted code captures the live stack target with flag-neutral moves; the gateway snapshots GPR/RFLAGS, validates the one-based site and expected guest VA, and resumes translated code before xstate transfer only while guest state is resident. Cold, mismatched, or host-resident sites still use the authoritative Rust control-flow resolver. Generation changes, JIT recycling, fork, and exec clear the table. A synchronous stack fault reverse-maps the RCX spill, while the asynchronous kick handler repairs the same spill in the saved host ucontext before redirecting. The exact GnuTLS gate passes, and the comparable 20-output cc1 run was 135.82s; the modest 1.4% additional wall reduction is not overstated because stable hotspot sampling was unavailable for the short-lived compiler children.

## Ownership model

Three distinct states must never be conflated:

- **H:** complete host xstate, including every XCR0-enabled component and PKRU;
- **G:** authoritative guest xstate in `X86UcontextSnapshot`;
- **P:** physical CPU xstate.

At every Rust boundary, `P` is host-owned and G is materialized. A guest-resident interval starts by saving P to H and restoring G to P. It may traverse directly chained JIT blocks without another switch because no Rust/libc executes. Every syscall, sensitive operation, uncached indirect, cold chain, signal, fault, or kick exit that returns to Rust must materialize G, restore H, clear DF, and only then cross the host ABI. A validated return-cache hit may pass through the assembly gateway's GPR/RFLAGS snapshot and resume the same guest-resident interval before any xstate or FS-base transfer; Rust/libc never executes on that path.

An integer block may execute with host-resident P only when every instruction reachable before the next gateway exit is proven independent of xstate and PKRU. Local `uses_fpu` is not that proof.

## Falsifiable root-cause hypotheses

The failed target-only experiment proves that its implementation did not enforce the ownership invariant; it does **not** yet prove why. A correctly enforced barrier on every edge into a known state user would interrupt `integer A -> integer B -> FPU C` before C, so transitivity alone is not an explanation.

Phase 0 distinguishes these candidates rather than choosing one speculatively:

1. a state-using or state-dependent instruction is locally misclassified;
2. a pending-edge, self-edge, cache-hit, or recycled-cache patch bypasses the target check;
3. entry-scoped `save_fpu` metadata survives into a chained block whose effective classification differs from the cache metadata;
4. an implicit dependency such as PKRU affects an otherwise integer-looking block;
5. a signal, kick, fault, or cold exit materializes G under the wrong residency decision.

The edge probes therefore record both patch lifecycle and source/target classification. The selected cold-edge barrier is the causal test: only a barrier that restores the expected result identifies an ownership transition worth optimizing around.

## Blast radius

Primary implementation files:

- `crates/carrick-dsr-x86/src/gateway_x86_64.S`
- `crates/carrick-dsr-x86/src/gateway.rs`
- `crates/carrick-dsr-x86/src/block.rs`
- `crates/carrick-dsr-x86/src/decode.rs`
- `crates/carrick-dsr-x86/src/emit.rs`
- `crates/carrick-runtime/src/native_freebsd.rs`

Direct test surfaces:

- `crates/carrick-dsr-x86/tests/native_execution.rs`
- `crates/carrick-dsr-x86/tests/native_static_elf.rs`
- gateway unit tests in `gateway.rs`
- FreeBSD runtime integrations in `crates/carrick-runtime/tests/native_freebsd_x86.rs`

Indirect contracts include synchronous fault redirection, asynchronous kick exits, clone snapshot copying, fork/vfork context ownership, exec reset, CPUID exposure, JIT cache recycling, code-generation invalidation, and profiler layout offsets. The risk remains high even though direct fan-in is limited because one incorrect transition silently corrupts cryptographic/parser state long before failure.

## Phased implementation

### Phase 0 — capture the first divergent edge

Add opt-in, guest-PC-filtered diagnostics. Extend the existing native-x86 PC/resolve seams rather than adding unconditional logging. For selected transitions record:

- source and target guest PCs;
- JIT entry PC, cache hit, cold edge, and pending-patch state;
- decoded local state-use class;
- proposed ownership/save decision and exit kind;
- XSTATE_BV, MXCSR, FCW, PKRU;
- bounded hashes for legacy, YMM, opmask/ZMM, and other enabled component ranges.

Add an edge-barrier diagnostic mode that forces a gateway boundary after selected direct edges. First reproduce the existing mixed-chain failure with target translated before the source, after a pending patch, and after cache recycling. Then select/bisect the exact GnuTLS transition. No transfer policy changes until one captured transition explains both failures.

### Phase 1 — optimize persistent host saves

Keep the conservative guest policy. Initialize the stable host buffer with full XSAVE, then evaluate full-mask XSAVEOPT for subsequent host saves into the same aligned buffer. Always restore the complete host image. Compare architectural components, not reserved XSAVE padding.

Rollback on any host XMM/YMM/ZMM/opmask/x87/MXCSR/PKRU mismatch, signal/fault/kick regression, CPU-migration failure, or negligible measured reduction.

### Phase 2 — mode-separated neutral domains

The first correctness form does not duplicate emitted bytes: residency is carried by the persistent context's entry decision. Neutral edges may target only locally proven neutral blocks; every edge to an unknown or state-using target remains cold and re-enters with guest state. This is sufficient because neutral code preserves either incoming physical-state owner, while `save_fpu` remains the entry interval's exit/materialization decision. Mode-specific translated versions are required only to let a guest-resident interval bypass barriers that a host-resident interval must retain; that optimization belongs to Phase 3.

The state-user classifier fails closed for vector, x87/MMX, opmask K, AMX TMM/tile configuration, BND, MXCSR, XSAVE-family, and implicit decoded state users. RDPKRU/WRPKRU are sensitive-emulated: the virtual value stays outside the hardware XSAVE payload because applying guest key-0 rights in this user-mode gateway would revoke access to its context and host stack. Nonzero virtual PKRU conservatively forces guest residency, but Carrick does not yet enforce protection-key rights on guest memory. CPUID and XGETBV therefore hide PKU/OSPKE and component 9; XRSTOR-family instructions fail closed until safe component-9 virtualization is implemented. `neutral-domains` is experimental and conservative remains the default rollback.

### Phase 3 — extend guest-resident intervals

The first correctness slice caches only `ret` and `ret imm16`. Each translated return owns one generation-scoped monomorphic data entry. The emitted probe reads `[rsp]` without changing guest flags, records its site id, and enters the common gateway. After the gateway has captured every GPR and RFLAGS—but before it transfers xstate—the hit path validates the expected guest target, advances the saved RSP by `8 + imm16`, reloads the snapshot, and jumps to the cached translated target. It never executes Rust or host libc.

A hit requires `save_fpu != 0`; this is an ownership test, not a target-class heuristic. Cold and polymorphic misses leave RSP/RFLAGS unchanged and resolve from the target captured once inside the JIT fault region. Cache vectors are thread-local and mutate only at gateway boundaries. A Rust-observed code-generation change, JIT recycling, fork-child reset, and exec clear them with the block cache. Return-stack faults retain the return VA and restore the temporary RCX spill. The kick shim repairs an interrupted spill directly in the signal ucontext before the ordinary kick exit captures guest state.

Indirect calls and jumps remain cold. Extending the cache to instructions with memory writes or call-stack side effects requires the same precise fault and asynchronous-observation proof; it is not implied by the return result. Component-aware save masks are also deferred. Host saves and restores remain complete.

### Open review blockers

The second independent architecture review closed the RET double-read and raw
PKRU hazards but did not pass the overall gate:

- Task 46 is complete: Linux signal frames now carry a validated, dynamically
  sized standard XSAVE image plus separately virtualized PKRU. Mutation-proven
  async, synchronous-fault, and nested fixtures cover x87/MXCSR/YMM/K/ZMM0-31;
  malformed state is rejected before mutation. Host mapping transitions are
  serialized against signal-frame copies, so read-only/unmapped stack races
  become guest faults rather than Rust-side host faults. Dual hostile review
  passed after the mapping/alias race fixes.
- Cross-thread executable mutation and exec takeover do not yet synchronously
  force resident direct-chain/RET intervals to acknowledge a generation stop
  before old mappings or translations retire. Task 43 owns the unified epoch,
  kick, quiescence, and exact-PC recovery design.

The review also found registerless x87 environment/control instructions. The
classifier now uses iced's complete FPU/MMX CPUID-family metadata plus explicit
WAIT/FEMMS handling; 55 DSR units include an exhaustive catalog regression.
Until Task 43 passes a fresh dual review, Phase 3 is experimental and must not
be committed or described as architecturally complete.

## Verification gates

Each behavior follows red-first validation. Do not overlap heavy compilation with the running Kaniko acceptance build.

1. Direct and transitive integer-to-FPU chains, cycles, middle entry, patch-order variants, and cache recycling.
2. XMM, YMM, ZMM, opmask, x87, MXCSR, PKRU, init-state, and repeated host-clobber tests.
3. Synchronous fault, asynchronous kick, signal delivery, clone, fork/vfork, and exec boundaries.
4. Serial DSR unit/integration suites and FreeBSD native runtime integrations.
5. Exact previously failing Kaniko apt/GnuTLS command with identical inputs.
6. Full pinned LTP source image and packaged native gate (**pass**); same-artifact native Linux/amd64 oracle comparison (**pending**).
7. Only after correctness: compare gateway count, instruction samples, wall time, CPU time, and artifact manifest against the conservative policy.

## Execution order

The measured performance phases were executed serially:

1. Task 38 — divergent-edge diagnostics;
2. Task 39 — persistent host XSAVEOPT;
3. Task 40 — neutral chain domains;
4. Task 41 — longer guest-resident intervals.

Task 35's jobs=8 pinned-LTP build, packaged 25-case gate, and Task 46 signal-frame XSAVE ownership now pass. The active correctness successor is Task 43 (synchronized executable epochs), followed by fresh dual review and the same-archive native Linux/amd64 oracle. Until those gates pass, `neutral-domains` remains explicit rather than the production default.
