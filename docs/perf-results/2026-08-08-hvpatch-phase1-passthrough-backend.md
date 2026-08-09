# HvPatch Phase 1 passthrough backend — functional gate complete

Date: 2026-08-08

Controller: `/Volumes/CaseSensitive/carrick/hybrid.md`, Phase 1

Implementation: `ef4b174d313880ea02f369b9605c2df74fd8938b`

Normalized records: [`hvpatch-phase1-passthrough-backend.jsonl`](hvpatch-phase1-passthrough-backend.jsonl)

## Decision

Phase 1's minimal product backend is complete and Phase 2 may proceed. The
`hvpatch` request is a distinct, macOS/AArch64-only backend, its image finalizer
cannot fall through to either existing backend, and both a static fixture and a
dynamic Ubuntu image execute through the signed product binary.

This milestone proves product wiring, pre-map ELF patching, nearby island
placement, register-safe passthrough, and trap-origin attribution. It does
**not** eliminate syscall exits: the Phase 1 island deliberately contains a
real `svc #0`. The controller's Phase 1 goal sentence says that stdout `write`
is eliminated, while its island specification says that every syscall still
exits. The latter is the implemented and measured contract; exit elimination
begins in Phase 2.

## Two required design corrections

### Preserve `TPIDR_EL0`

Phase 0 measured `mrs tpidr_el0` as exit-free and slightly faster than an info
page load on this host. The patcher therefore changes only exact `svc #0`
instructions. It leaves `TPIDR_EL0`, `CTR_EL0`, and `DCZID_EL0` reads intact;
the mature HVF lane configures their architectural state.

### Use a non-linking, site-specific stub

The controller proposed `bl shared_island; svc; ret`. That sequence is not
Linux-syscall transparent because `bl` overwrites guest `x30`. The static
fixture happened to pass, but the dynamic loader spun after later function
returns. LLDB showed the guest vCPU continuously running after only three event
ring entries, and inspection reduced the failure to the clobbered link
register.

The corrected transform is:

```text
site:       b site_stub
site_stub:  svc #0
            b site+4
```

It preserves every guest register, gives each patched site its own return
target, and keeps the slow fallback semantics. A red-first regression test
requires `B`, rejects `BL`, and verifies the return branch.

## Product and trace proof

The exact committed tree was built with `just build`, which relinked and signed
`target/release/carrick` with the hypervisor entitlement.

- Signed binary SHA-256:
  `59845b1fe06d5637ea38e637a2a30d00faf73223fada9e9906727a86084d5cc8`
- Mach-O UUID: `DC081655-2CD4-3854-A158-935DCCEB1463`
- `com.apple.security.hypervisor=true` was present.
- `__DATA,__dof_carrick` was present.
- Static fixture SHA-256:
  `bed8073226947f620b5578f3f61d1b8551e1abc777afcd2bbbaa04fd5c7cca31`

Functional receipts:

| Gate | Result |
|---|---|
| `run-elf --raw --exec-backend hvpatch .../hello-aarch64` | stdout `ok`, exit 0 |
| `run --raw --exec-backend hvpatch ubuntu:24.04 /bin/echo hello` | stdout `hello`, exit 0 |

The committed, perturbing
[`hvpatch-island-origin.d`](../../scripts/dtrace/hvpatch-island-origin.d)
script observed exactly two SVC traps in the static fixture:

| Linux syscall | Trap PC | Count |
|---|---:|---:|
| `write` (64) | `0x214004` | 1 |
| `exit_group` (94) | `0x21400c` | 1 |

The fixture's executable text is `0x200000..0x210143`; the generated stub
region begins at `0x214000`. The trace therefore attributes both exits to the
generated site stubs, not to original ELF sites. The capture SHA-256 is
`e2cc04d7bda19e40b3ce48b4c1f2b7a1348c930c087557ad9870ee665e8ffe16`.
The script documents its qualified provider ABI and fails visibly when no
events fire.

## Measured 20-exec micro-fixture

Workload, run sequentially three times per backend:

```sh
/bin/sh -c 'w0=$(date +%s%N); i=0; while [ $i -lt 20 ]; do \
  /usr/local/go/pkg/tool/linux_arm64/compile -V >/dev/null; \
  i=$((i+1)); done; w1=$(date +%s%N); echo $((w1-w0))'
```

Image:
`localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.

| Backend | In-guest elapsed samples (ms) | Median (ms) | Host user+sys samples (s) | Median (s) |
|---|---|---:|---|---:|
| VMM | 380.160, 395.742, 367.117 | 380.160 | 0.73, 0.90, 1.39 | 0.90 |
| Native | 1265.168, 1041.959, 1041.547 | 1041.959 | 2.27, 1.13, 1.13 | 1.13 |
| HvPatch | 383.276, 403.657, 378.314 | 383.276 | 0.73, 1.12, 2.07 | 1.12 |

Load average was approximately 2.72–3.00 and interactive Codex/UI work remained
active. The `/usr/bin/time` CPU and real samples are visibly load-sensitive and
are **provisional shape evidence only**. The tighter in-guest elapsed numbers
place Phase 1 HvPatch near VMM, which is expected because both still exit for
every syscall. No speedup is claimed.

The micro-fixture was captured immediately before a nonsemantic clippy cleanup
and the implementation commit. The exact committed binary is bound by signed
functional and DTrace receipts, but these performance samples are not claimed
as an exact-commit benchmark. Phase 2 must take a controlled, commit-bound
cold-build measurement before evaluating its numeric gate.

Current exec scope also matters: the initial shell and interpreter are patched,
but exec-replacement images still take the mature HVF reload path until Phase
4. The fixture is therefore not evidence that all 20 compiler images were
patched.

## Correctness and repository gates

- 11 focused HvPatch unit tests pass: patch range edges, exact-opcode
  selection, `x30` preservation, trailing bytes, manifests, information-page
  layout, island bytes, multiple executable regions, and unchanged TPIDR.
- Backend parser/serde/clap, page-profile, and image-finalizer routing tests
  pass.
- Static and dynamic signed product smokes pass.
- DTrace trap-origin proof passes with nonzero, island-resident events.
- `just ci` passed on the clean implementation commit `ef4b174d` on
  2026-08-08: fmt, workspace clippy, typed-domain lint, dependency policy,
  matrix drift, build/check/doc, serialized host tests, and integration suites.
  The largest affected suites reported 1,244 unit tests with 5 ignored and 296
  integration tests, with zero failures.

No Docker oracle or HvPatch conformance overlay exists yet. Phase 1 establishes
the backend method, not broad Linux compatibility.

## Phase boundary checkpoint

Phase 1 is **complete as a passthrough backend**.

- Implementation: `ef4b174d` (`feat(hvpatch): add phase one passthrough backend`).
- Verified exact binary: signed and DOF-bearing, with both product smokes green.
- Attribution: both static-fixture syscall exits originated in generated stubs.
- Performance: near-VMM on the narrow exec fixture; no exit or CPU win claimed.
- Next decision: proceed to Phase 2, but qualify each proposed in-guest syscall
  path independently against Linux semantics before using it in a cold-build
  count. In particular, the controller's proposed `wfe`/`sev` futex protocol
  is not accepted without proof that it preserves wait/wake, timeout,
  interruption, and scheduling semantics.

