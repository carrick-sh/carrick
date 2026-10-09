# ARM ring-first independent review follow-up

Runtime/witness checkpoint: `637fb416c` (full identity in the verification
receipt). This evidence supersedes the earlier raw-only closure at
`54d6b0210` for PR #132. The director owns the KVM run and stacked full gate.

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

## Signed review verdicts

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

The earlier review-ready ruling is superseded pending N1-N3 corrections and
signed loader-only evidence. Each new defect fails first in VM-free tests;
`re-review-red-first.txt` retains the assertions. x86 now evaluates every
forwarding completion, strict ARM refuses unported calls before owed-work
transport, and replay conversion is restricted to effect-free ARM Forward
with entry-saved argument zero. Handback and AccountedForward preserve
Forward; x86 has no replay conversion. Production x86 witnesses now cover
both pending-work settings and require counted refusals outside the eight
crossings. The GNU fixture gains a loader-only mode without fork; its new
signed bindings require completing libc calls, file-backed mmap forwarding,
exit forwarding and exact getuid policy counters. Final signed verification
and director-owned KVM comparison remain pending.

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
Signed verification of the corrected witness remains pending.
