# carrick-embed — the standing directive

Paste this to resume or finish the program. It is written to be self-contained.

---

Finish the `carrick-embed` program.

**Authority.** The goal is the ORIGINAL source plan,
`docs/superpowers/plans/2026-08-23-carrick-embed-source-implementation-plan.md` —
its purposes and its spirit. The approved design is
`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`; the task-level
plan is `docs/superpowers/plans/2026-08-25-carrick-embed-phase-a-c-plan.md` plus its
phase-a/b/c task files. The two 2026-08-23 review documents are NOT authority — they
were static reviews that ran nothing; mine them for concerns, never for permission.

**Where the work is.** Branch `feat/carrick-embed` in `.worktrees/carrick-embed`.
Rebase on `main` before each work session and re-run the gate afterwards — a rebase
that reports "Successfully rebased" is not evidence that the result compiles.

**What done means.** Not "it compiles" and not a green unit suite. A phase is done
when, on ONE exact signed artifact (record source HEAD, binary SHA-256, CDHash,
hypervisor entitlement, `__dof_carrick`): `just ci` is green, the phase's guest
probes MATCH the native-arm64 Docker oracle, the disabled path has an ABBA receipt
showing no added cost, and a dated evidence report exists under `docs/perf-results/`.
Carrick and Docker phases never overlap.

**How to execute.** Delegate code to agy workers via the `agy-director:antigravity-agents`
skill — one git worktree per worker, file-disjoint tasks, and these rules in every
brief: run verification in the FOREGROUND (never background/poll/end a turn to wait);
never read a gate's result through a pipe (`| tail` reports the tail's exit status,
not the gate's); and NEVER run a guest, Docker, `just conformance*`, or a bare
`cargo test --workspace`. Guests and the oracle are YOURS alone, run serially.

**Review is yours and it is not optional.** A worker's contract is a claim. Gate 1 is
mechanical (status/tests_passing/blockers, and reject a `stale` contract — an errored
turn that replays the previous turn's output). Gate 2 is reading the diff and
re-running the verification yourself. In one session three separate "greens" were
meaningless: a replayed contract, a probe gate that passed in 0.10s having run zero
guests, and a clippy failure masked by a pipe. Two workers reported green on code
that failed its own tests. Verify completeness claims with a grep, not with trust.

**Standing rules that cost real hours to learn.** Rebuild and re-sign before any
guest verdict, and prove the fix is in the binary (`strings target/release/carrick |
grep <marker>`) — a stale binary silently re-reports fixed failures. Attribute any
regression before fixing it: run the identical command on the pre-change binary.
Settle uid/capability/errno questions against the Docker oracle, not the man page.
A load-coupled failure is a CORRECTNESS signal, never an excuse — real Linux VMs do
not fail under load, and removing load-coupling is why HVPatch exists. Never weaken
an assertion to get green; if an expectation is obsolete, delete it deliberately in
its own commit citing the commit that obsoleted it, and confirm the behaviour is
still asserted somewhere.

**Remaining work, in order.** Phase B tasks 22-23 (container teardown + the Gate B
two-container probes), then C2 (`prepare.rs`: `Runtime::prepare(spec, launch,
extensions) -> PreparedRun`, plus the `Box<dyn Write + Send>` stdio sink replacing
the direct `libc::write` to the carrier's fds), C3 (the `carrick-embed` crate
itself), C4 (the signed `just test-embed` lane that codesigns test binaries and
fails closed on `HV_DENIED`), C5 (docs/handoff). Then phases D through J from the
spec — observer pipeline, VFS injection, clock domains and the virtual-time
scheduler, fault injection and quotas, network mocking, shared buffers, and
`carrick-conformance-next` — each with its own approved task plan after its
predecessor's gate closes.

**Open defects to close, not carry.** The `rlimitnproc` probe hangs where Linux
proceeds (errno right, liveness wrong). The `carrick-native-darwin` veneer readback
returns 0 after `enter()` — a W^X shadow-coherence bug, reproducible under load.
Both are named in memory with their evidence.

**Report honestly.** Say what is verified, what is assumed, and what is blocked.
Never describe carrick as production-ready or as a hardened boundary for untrusted
code. If a phase cannot close, say so plainly and say why, rather than lowering the
bar to reach green.
