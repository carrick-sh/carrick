# ARM ring-first independent review follow-up

Current product/fixture checkpoint: `ec8279a7235eb7044fbebd1b59d021c7fcf22a5f`.
This final correction gates owed-work replay on strict policy. OptOut
retains plain Forward for mmap, futex, clone and wait4 family declines;
`opt-out-transport-red-first.txt` records the failing and passing regression.
The director confirmed `x86_kvm_run` on `bad35bc69` matches origin/main.
Refused x86 family declines now increment only refused[native], no longer
also forwarded[canonical]; refusal counting is unchanged.
Current signed host source: `14ee884a37d66b794836b1204866ef50fe60c1f1`.
Current fixture input identity: `7751fc1f63ec8a53e4dc84d2b45f3bd8121a86fb568b119ea5da39e722ee9796`.
The new raw Strict, raw OptOut and GNU loader-only Strict/OptOut runs all
PASS, including negative controls, with zero survivors and no lease holder
after each run. `opt-out-*-signed-receipt.jsonl` retains authentic artifact,
source, fixture admission, execution and cleanup receipts;
`opt-out-signed-verdicts.json` retains counters and explicit cleanup.
`opt-out-vmfree-verification.json` records all final green native gates.
Raw and GNU loader-only witnesses PASS under both policies; fork/wait retains
the director-attributed main COW inventory defect. N1-N3 corrections and all
focused native gates pass. PR #132 is ready for independent re-review; the
director owns KVM execution and the stacked full gate. Earlier sections
retain the first-round checkpoint `637fb416c` and its historical evidence.

## Red-first corrections

`red-first-evidence.txt` retains the actual failing assertions and compile
errors before each correction:

- P0-1: the x86 context selected Aarch64. Production frame policy now chooses
  X86 and strictness without invoking an ARM aperture callback; the fixed
  accessor only exists on bare-metal AArch64 and is unsafe.
- P0-2: strict mmap fallback returned Served instead of Forward. Typed
  forward reasons distinguish unported calls, family fallback, host work and
  Handback. Only unported calls undergo the allowlist decision. Owed work
  returns WithWork and publishes the original-call replay. A separate red
  retained-Handback witness found and corrected Forward instead of WithWork.
- P1-3: missing admission bypassed policy. It now uses the shared evaluator;
  the final witness requires counted ENOSYS rather than bypassing refusal.
- P1-4: a zero control record disabled strict policy. The bit now encodes
  OPT_OUT; zero and an absent host region enforce strict. The ABI hash binds
  the new polarity.
- P2-5: aperture address validation was absent. Host access checks bounds,
  alignment and addition overflow before dereference and requires mapping
  lifetime custody from its unsafe caller.
- P2-6: restart reconstructed None instead of persisted OptOut. Container
  configuration now persists the resolved typed policy through serialization.
- P2-7: the rootfs debug API lacked its typed policy argument. Its signature
  now requires ArmRingFirst; convenience wrappers explicitly select Strict.
- P2-8: x86 getuid counted canonical 174 rather than native 102. NativeNr and
  SyscallResult cross the evaluator; LinuxErrno and EXIT_GROUP come from the
  shared ABI. One declaration generates the classified dense lookup; both
  ISA memberships are checked exhaustively through 512.
- P2-9: readahead was refused and pselect6 was permanent. Host-file admission
  now includes readahead, fadvise64 and execveat. Guest descriptor and anonymous
  memory debt is temporary; rt_sigreturn is completion Handback. The revised
  census has 92 permanent, 30 temporary, 17 wired, 134 refused and 65 unclaimed
  rows. The ARM set has those 122 crossings plus two terminal fallbacks.

The genuine GNU fixture has a glibc main/CRT, PT_INTERP and libc.so.6 dependency.
It exercises ld.so file-backed mmap and fork once. Its parent blocks SIGCHLD,
uses a nonblocking signalfd with one five-second poll, and reaps once with
WNOHANG. Pipe EOF was replaced because descriptor closure does not establish
waitable child state. Stdout readiness is also bounded. The raw fixture
continues to test strict ENOSYS and opt-out accounting separately.

## Verification

`vmfree-verification.json` records commands, results and output tails. The
required personality, EL1 library, ABI, kernel semantics, clippy and formatting
checks pass. Host hatch and production x86 context suites pass as well.
The bare-metal x86 CPL0 compile check passes without warnings; execution on KVM
is unavailable on this Mac and remains director-owned.

The real-base domain gate passes with 1,232 source counters and native compiler
profiles macos-cli-default, macos-runtime-default and macos-hvf-default. Six
Linux/BSD profiles remain pending on this Mac; this is not matrix completeness.

## First-round signed review verdicts

The monitored recipe finished in 504.41 seconds, below ten minutes. Both raw
witnesses PASS: Strict getuid refusal/forward = 1/0; OptOut = 0/1. Each has
exit_group refusal/forward = 0/1 and clock host forwards = 0.
Both glibc/fork-wait witnesses FAIL with the identical process-child fault:
`HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage`.
The error prevents their counter assertions from executing; their refusal
counts are unavailable, not presumed zero. The signed negative control passes.
Runner, CLI-suffix and explicit cleanup all leave zero survivors.

`signed-result.json`, `signed-verdicts.txt`, `signed-failure-identity.json`
and `fixture-validation.json` retain the exact command, artifact, failure and
clean input-identity admission. The failed signed executable and dSYM are
retained locally as `target/ringswitch-review-failed-signed`.
The test SHA-256 is
`60a5b5100171e092176ae7282054ceff684c6bcf3835ec1c40fd228975e5dbf1`;
the glibc guest ELF is
`8d3fc3dec6d2e94b215a09c0c5a44505091b1bc62f788287cd0c123d9d3971e7`.
The final archive SHA-256 is
`cc87e661e2d5500b114ef4080041f7055c399848d620ba35016ae7d7d3be2e87`.

## Main control attribution

The director-approved main control `10e41549e0e27546e0b536a7ada847e8c10365d7`
contains only fixture, test and xtask fixture-plumbing changes over product
baseline `dfc9100e277339016f537ba09e2b475470c953b6`. Its runtime, memory,
HVF, kernel, EL1, ABI, personality, engine and CLI product sources are unchanged.
The published archive verifies 1,135 executables with clean input admission.
Its GNU guest ELF has the identical SHA-256 recorded above.

| Runtime | Signed witness | Verdict |
| --- | --- | --- |
| Ring-switch Strict | Raw | PASS; getuid refusal/forward 1/0 |
| Ring-switch OptOut | Raw | PASS; getuid refusal/forward 0/1 |
| Ring-switch Strict | GNU loader + fork/wait | FAIL; child COW inventory |
| Ring-switch OptOut | GNU loader + fork/wait | FAIL; child COW inventory |
| Main product control | Identical GNU loader + fork/wait | FAIL; identical child COW inventory |

The main guest fails after 5.09 seconds with the exact same error:
`HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage`.
The monitored main recipe finishes in 235.63 seconds, with negative control
PASS, explicit cleanup exit zero and zero survivors. The shared host lease
has no holder after completion. Main refusal counts are unavailable because
the child fault prevents counter assertions from executing.

The main signed test SHA-256 is
`ac7fabcda9a9eb2cbe57c0beb4e071d1a65371e557e7453d540544661b55a427`.
`main-control-signed-failure-identity.json` retains the binary, CLI, guest,
CDHash, LC_UUID, entitlement and DOF identities; the accompanying result,
verdict and fixture-validation files retain the exact command and admission.
The failed executable and dSYM are retained in the control worktree as
`target/ringswitch-main-control-failed-signed`.

The fault address equals LINUX_VVAR_BASE. The fork refresh path attempts a
privileged COW write of the vvar RNG-generation field; exact compound inventory
coverage rejects it. The A/B control establishes that this witness failure
exists on main as well as both switch policies. Per the director's ruling,
the switch is review-ready and the inherited inventory defect belongs to the
ARM fork lane. The GNU tests remain failing assertions; none is weakened or
converted to an expected failure. No COW runtime change is included here.
No unchanged signed artifact was retried. No Docker, full acceptance gate or
runtime-ratio claim is included. KVM execution and the stacked full gate
remain director-owned.

## Second independent review (2026-10-09)

The second review supersedes the earlier raw-only closure. N1-N3 corrections
now pass and signed loader-only evidence is complete under both policies. Each new defect fails first in VM-free tests;
`re-review-red-first.txt` retains the assertions. x86 now evaluates every
forwarding completion, strict ARM refuses unported calls before owed-work
transport, and replay conversion is restricted to effect-free ARM Forward
with entry-saved argument zero. Handback and AccountedForward preserve
Forward; x86 has no replay conversion. Production x86 witnesses now cover
both pending-work settings and require counted refusals outside the eight
crossings. The GNU fixture gains a loader-only mode without fork; its new
signed bindings require completing libc calls, file-backed mmap forwarding,
exit forwarding and exact getuid policy counters. Current signed verification is recorded below; director-owned KVM comparison
remains pending.

### Loader counter correction

The first second-review signed recipe finishes in 247.74s. Both loader-only
programs successfully return the expected output and policy getuid counters,
but their new tests fail on an incorrect requirement for getpid personality
accounting. The default mailbox identity shim reads the process PID and
returns before personality dispatch. Its existing bytecode tests prove this
path: `shim_dispatches_only_process_identity` and
`mailbox_vector_retains_identity_fast_paths_when_enabled` both pass.
The corrected witness requires a positive guest PID and exactly zero
refusal, served and forwarded personality counters for getpid. Other loader,
I/O, mmap, getuid and exit assertions are retained. This changed host witness
requires a new signed artifact; the guest/runtime and published fixture input
identity remain unchanged. The failed artifact and dSYM are preserved as
`target/ringswitch-rereview-counter-red-signed`; its SHA-256 is
`0287547b7483eb522a45ba2fd5fc05234fd8f615ffebfa57ec3024cdda893774`.
The `re-review-counter-red-*` records retain the failing assertions, exact
counters, artifact identities, clean admission and zero-survivor cleanup.
The corrected witness now passes under both policies on the new artifact below.

## Current signed verdicts after N1-N3

Command and run ID are retained in `re-review-signed-result.json`:
`CARRICK_RUN_ID=ring-switch-loader-proof-20261009-ff633691b-1
CARRICK_CONTRACT_ID=kernel.el1.arm-ring-first-crossing
just test-embed arm_ring_first_ --nocapture` (one shell command).
The recipe finishes in 276.51 seconds, below ten minutes. The four completing
witnesses PASS; the two fork witnesses FAIL with the inherited inventory
error. Negative control and builder policy unit test PASS. Harness, CLI-suffix
and explicit cleanup leave zero survivors, and the shared lease is released.

| Witness | Strict | OptOut |
| --- | --- | --- |
| Raw getuid refusal / forward | PASS; 1 / 0 | PASS; 0 / 1 |
| GNU loader-only getuid refusal / forward | PASS; 1 / 0 | PASS; 0 / 1 |
| GNU loader-only mmap refusal / served / forward | 0 / 1 / 5 | 0 / 1 / 5 |
| GNU loader-only openat / read / write forwards | 3 / 2 / 1 | 3 / 2 / 1 |
| GNU loader-only exit_group refusal / forward | 0 / 1 | 0 / 1 |
| GNU loader-only getpid dispatcher refusal / served / forward | 0 / 0 / 0 (identity shim) | 0 / 0 / 0 (identity shim) |
| GNU loader-only clone / wait4 forwards | 0 / 0 | 0 / 0 |
| GNU fork/wait | FAIL; main-equal child COW inventory | FAIL; main-equal child COW inventory |

The GNU programs require successful clock, positive PID, /dev/null I/O,
policy-specific UID handling, exact output and exit. Their PT_INTERP and
libc.so.6 dependency ensure real dynamic libc startup. Their completing
counter checks prove strict libc execution without the known fork defect.
Fork counters remain unavailable because the child error precedes assertions.
The current error is again:
`HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage`.
The first-round byte-identical main control above establishes that this
mechanism predates the switch; its old GNU ELF hash is distinguished from the
new fixture with loader-only mode. The ARM fork lane retains that defect.

Current signed test SHA-256:
`ec77908a088c62ad684665218581fbba41e2294841468a62b7f9e5887da85b08`.
CLI SHA-256:
`7cb3e12e1fbe0878d2b7e6e4bb0cb83cecb6c2c0dcb00d056fc5439a10ab4750`.
GNU guest SHA-256:
`69f6c577f5fe1f5cf67877804d64c9535eb1890d1d3efe96b4612a6c525dfc7d`.
Published bundle SHA-256:
`05c18f1c96019cde74c9de19bd26c2ec4f467e741c1cbcdc59d6ab8c1ab8397a`.
`re-review-signed-identity.json` retains CDHash, LC_UUID, entitlement and DOF;
`re-review-signed-fixture-validation.json` retains the clean exact input
admission. The artifact and dSYM are preserved as
`target/ringswitch-loader-proof-signed`. Final review readiness does not claim
KVM execution, Linux/BSD native profile completeness or a stacked full gate.
