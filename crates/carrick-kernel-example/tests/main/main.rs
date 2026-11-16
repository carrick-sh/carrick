//! Consolidated integration-test binary for `carrick-kernel-example`.
//!
//! Compiling all VM-free kernel-semantics and harness suites as modules of one
//! test binary links `carrick-kernel` and its dependency closure once instead
//! of once per test file (#2408).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(debug_assertions)]
mod admission_interleavings;
mod composition_root_packaging;
mod conflicting_tls_preemption;
mod contracts;
mod deferred_regressions;
mod fd_admission;
mod fork_clone_orderings;
mod fork_pipe_wait;
mod fork_threads_exit;
mod host_wait_cancellation;
mod n2_creation;
mod n2_task_lifecycle;
mod n2_task_transactions;
mod namespace_two_process;
mod native_execution_scope;
mod personality_handle_table;
mod personality_stack_arguments;
mod personality_user_copy;
mod ptrace_wait;
mod root_exit_full_width;
mod schedule_replay;
mod scheduler_affinity;
mod scheduler_handoff;
mod scheduler_preemption;
mod seam_reserve_commit;
pub mod semantics;
mod setid_birth_admission;
mod socket_close;
mod socket_receive;
mod spawn_birth_capacity;
mod stdio_host_wait_contention;
mod stdio_inherited_backpressure;
mod unicode_paths;

pub use semantics::common;
