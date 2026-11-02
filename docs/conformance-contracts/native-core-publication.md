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
