//! # carrick-kernel-example
//!
//! The template for a bring-your-own execution backend on
//! [`carrick_kernel`]. It has no VM: Linux tasks are host threads and guest
//! memory is a `Vec<u8>`. What it implements is exactly what a backend must:
//!
//! - construct the kernel with its own bridges and its own `MmBackend`
//!   ([`ScriptedBackend::run_root`], [`ExampleProcess::boot_root`]);
//! - translate its trap source into `SyscallRequest`s (here, a script of
//!   [`Step`]s);
//! - interpret every `DispatchOutcome` it meets (`Task::issue` in
//!   `scripted.rs`: `Returned`, `Errno`, `Exit`, `Fork`, `WaitOnHvpatchChild`,
//!   `WaitOnFds`, `SchedulerYield`; anything else is refused by name);
//! - implement the process seams the dispatcher binds to
//!   ([`ExampleProcess`] as `CarrierProcess`, [`ExampleMmBackend`] as
//!   `MmBackend`, [`ExampleStage1Projection`] as `Stage1MmProjection`).
//!
//! What it deliberately does not do: run real guest code, fork host
//! processes, or emulate a CPU. A wait is a bounded re-dispatch after a
//! `yield_now` ([`WAIT_BOUND`]), not a parked continuation, and a child's
//! exit posts no `SIGCHLD` -- a scripted task has no signal delivery.
//!
//! It is built from `pub` items of `carrick-kernel`, `carrick-hal`,
//! `carrick-guest-mem` and `carrick-abi` alone. It takes `carrick-kernel` with
//! NO features -- the backend above is its own, over the kernel's ordinary
//! public surface, which is what a real backend author gets -- and needs
//! `carrick-hal`'s `test-support` only for the two Null bridges.
//! `tests/fork_pipe_wait.rs`
//! is the proof: `pipe2 -> fork -> (child: write, exit 7) -> read -> wait4 ->
//! exit` through `SyscallDispatcher`, and it fails to compile the moment one
//! of those items regresses to `pub(crate)`.
//!
//! **Status:** experimental, like the kernel it drives. It is not on the
//! product path and `carrick` ships none of it: the root manifest's
//! `default-members` keeps the product build to `carrick-cli`'s closure, and
//! `just check-layering` fails if that selection enables `test-support`.

pub mod driver;
pub mod memory;
pub mod operand;
pub mod process;
pub mod report;
pub mod scripted;
pub mod sys;

pub use memory::{GUEST_BASE, GUEST_LEN, TaskMemory};
pub use operand::{
    Expect, Operand, Save, Step, Syscall, await_parked, host_sleep_ms, last_child, slot,
};
pub use process::{
    AddressSpace, AddressSpaceError, AsidAllocator, ExampleInstallPermit, ExampleMmBackend,
    ExampleProcess, ExampleStage1Projection,
};
pub use report::{Completion, Output, RunReport};
pub use scripted::{ExampleError, ScriptedBackend, WAIT_BOUND};
