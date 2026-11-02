# Native asynchronous core publication (#1454)

The zero-limit fixture repair does not implement asynchronous core
publication. The unlimited-limit coredumpbit acceptance criteria remain open.

At admitted main 9ac4c237f6c796d7044233a292804324e7dd28f5:

- `carrick-el1-linux/src/signal_delivery.rs` calls
  `NativeProcessEntry::exit_with_signal` for asynchronous default termination.
- `native_process_runtime.rs::exit_with_signal` calls `exit_with_status` with
  `core_dumped=false`. That owner retires the child and publishes its wait
  status in ring, before any host core publisher participates.
- `carrick-runtime/src/vcpu_loop/binding.rs` prepares a core only for an
  exact fatal record through `fatal_for_terminal_owner`; recording a fault
  does not by itself transfer a native child's retirement to that owner.
- `carrick-runtime/src/vcpu_loop/crash.rs` requests
  `aarch64_core_registers`; `carrick-hal/src/threaded.rs` defaults that method
  to `Ok(None)`. The x86 engine has no override.
- `carrick-kernel/src/core_dump.rs` serializes and validates `EM_AARCH64`
  and AArch64 thread notes.

A shared publication service must retain exact native process/thread/MM
custody before child terminal publication, capture ISA-correct registers and
memory, publish under the child's cwd/limit/dumpability authority, then give
the neutral terminal owner the actual publication result. Failure and zero
limit must settle without a core bit. A host-only fallback at root exit cannot
repair an already-published native child wait status. The x86 register and ELF
note format must be implemented before claiming both-ISA publication.

## Unlimited-limit red-first witness

The KVM production CLI witness
`mounted_static_x86_signal_abort_with_core_publishes_dumped_status_and_file`
selects `CORE_ENABLED` in the existing `x86_signal_abort.S` fixture. Both
variants explicitly set and read back their limit. The zero-limit variant
requires CLD_KILLED and raw status 6. The unlimited variant requires
CLD_DUMPED, raw status 0x86, and a readable `core` with ELF64, ET_CORE and
EM_X86_64. Exit 90/91 identifies limit setup/readback, 92 signal setup/wait,
93 SIGCHLD metadata, 94 wait4, 95 file open/read and 96 ELF header validation;
97 means the child's fatal tgkill returned. It retains the existing bounded
SIGCHLD wait and CLI process-group cleanup.

With CARRICK_REQUIRE_KVM=1, the zero-limit comparison passes; the unlimited
case exits 93 after successful limit setup and readback. This checkpoint is
intentionally red and does not implement publication. It is not landing-ready.
The runner's native hard RLIMIT_CORE is zero: native unlimited execution exits
90 at setup and supplies no unlimited oracle evidence. It must not silently
substitute the zero-limit outcome for the required unlimited behavior. Signed
ARM, native unlimited oracle, structural publication budgets and final
artifact promotion remain unproved.
