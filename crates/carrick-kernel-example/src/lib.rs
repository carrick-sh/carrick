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
//! - interpret outcomes in `driver::drive`: returns, process/thread exit,
//!   fork/clone, exact-thread signals, and shared kernel continuations;
//!   unsupported outcomes are refused by name;
//! - implement the process seams the dispatcher binds to
//!   ([`ExampleProcess`] as `CarrierProcess`, [`ExampleMmBackend`] as
//!   `MmBackend`, [`ExampleStage1Projection`] as `Stage1MmProjection`).
//!
//! What it deliberately does not do: run real guest code, fork host
//! processes, or emulate a CPU. Waits are parked as kernel continuations on
//! the shared wait service, bounded by [`WAIT_BOUND`] so a lost wake is a
//! failed run, not a hang.
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

pub use driver::{block_on_timeout, seed_initial_task_state};
pub use memory::{GUEST_BASE, GUEST_LEN, TaskMemory};
pub use operand::{
    Expect, Layout, Operand, RelocWidth, Relocation, Save, Step, Syscall, alloc_buffer, alloc_word,
    await_parked, in_out, last_child, negated, slot, tagged_in_out, tagged_out, write_buffer,
    write_word,
};
pub use process::{
    AddressSpace, AddressSpaceError, AsidAllocator, ExampleInstallPermit, ExampleMmBackend,
    ExampleProcess, ExampleStage1Projection,
};
pub use report::{Completion, Output, RunReport};
pub use scripted::{ExampleError, ScriptedBackend, WAIT_BOUND};
