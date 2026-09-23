# Real guest semantic control for the DSR experiment

The freshly rebuilt perf_inotify09_scale invalid-contract mode executes both
inotify syscalls in a Linux ELF at scales 1/8/32/128 and reports actual return
and errno values. Signed HVF and native ARM64 Docker outputs match exactly:
add/remove return -1, errno 9, stable=1 at every scale. Raw streams, commands,
source snapshot and executable hashes are retained. This is an untimed semantic
control, not new timing or a DSR pass. The original watch-only timing path is
unchanged. Its previously measured binary hash remains historical evidence;
this rebuilt executable has a new identity.

## Native adapter requirements before timing acceptance

Proposed contract identity: kernel.execution.native-synchronous-syscall.
It must be registered with actual structural observations before implementation
is promoted; no descriptor or passing native binding is claimed yet.

- Execute guest ELF instructions, not a Rust closure with fabricated arguments.
- Decode/translate SVC and continue at the correct guest PC. Preserve all guest
  register, SIMD, flags, stack and TLS state except documented syscall results.
  Darwin x18 and translator-reserved registers require explicit virtualization.
- Bind one exact current Kernel thread/MM/generation. Guest address values remain
  semantic VAs; every translated access resolves through that MM's backing.
  Two tasks with identical guest VAs must reach distinct private bytes. No old
  host-VA-equals-guest-VA model or one-host-process-per-guest restoration.
- Use current policy/interceptor/observer preparation and one completion per
  syscall, including EBADF. Preserve cancellation and pending-signal delivery
  before guest resume. A synchronous fast return must retain task authority.
- Unknown instructions, stale translations and unsupported lifecycle operations
  fail closed; they cannot silently execute as Darwin operations. Exec/mprotect/
  self-modifying code revoke affected translations by exact generation.
- First real guest control is invalid-contract. Then unchanged-watch/churn,
  TLS/register stress, signal-at-entry/return, two-MM alias isolation, cancellation
  and concurrent scheduling. A passing invalid-fd loop does not qualify memory
  translation, language runtimes or migration.
- Structural scales 1/8/32/128: two semantic dispatches and completions per pair,
  no HVF transitions in the native arm, no avoidable per-call heap allocation.
  Counters must measure the live path; no inferred-zero observations.
- Untraced timing uses the same ELF and workload phase in native adapter and HVF,
  plus native Linux. Compute and memory-heavy controls must expose translation
  costs that may erase syscall savings. Warm/cold code-cache costs remain visible.

## Reuse boundary established from current history

The current workspace has no callable DSR execution backend. The pre-removal
revision cc7d9eaa2^ contains carrick-dsr, carrick-dsr-aarch64 and native host
integration. The ISA crate includes decode/block/emit, reserved-register gateway,
mapped memory, translation/cache identity, and signal-sensitive gateway phases.
Its host identity-memory and fork assumptions are not today's unified MM model.
Reusing the old backend wholesale is therefore not an acceptable experiment.

Next implementation slice: isolate the pure decode/block/emit machinery behind
an exact-MM translation capability and current native JIT allocation authority.
Retain original project licensing and use the pinned BSD DynamoRIO architecture
reference for code-cache/direct-link design. Audit file-specific licenses before
copying external implementation code; repository umbrella licensing is not enough.
Only after current-MM memory and gateway state are real should the guest semantic
control above be called an executable DSR test. Until then native acceptance is
missing, not green and not a measured lower bound.
