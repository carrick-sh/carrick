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

The fault address equals LINUX_VVAR_BASE. The fork refresh path attempts a
privileged COW write of the vvar RNG-generation field; exact compound inventory
coverage rejects it. This mechanism and these source files are unchanged from
origin/main. That alone does not establish baseline attribution: per director
ruling, an isolated unmodified-product main A/B control is being prepared with
the identical GNU fixture. No unchanged signed artifact was retried, no gate
assertion was weakened, and no COW runtime change is included here.
No Docker, full acceptance gate or runtime-ratio claim is included.
