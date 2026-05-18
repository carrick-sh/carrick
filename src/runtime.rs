use std::path::Path;

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{
    Aarch64SyscallFrame, DispatchError, DispatchOutcome, GuestMemory, SyscallDispatcher,
    SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::rootfs::RootFs;
use crate::trap::{HvfTrapEngine, TrapError};
use serde::Serialize;
use thiserror::Error;

pub const DEFAULT_MAX_TRAPS: usize = 1_000_000;

pub trait SyscallTrap {
    fn next_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError>;
    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError>;
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to load ELF image: {0}")]
    AddressSpace(#[from] AddressSpaceError),
    #[error("trap engine failed: {0}")]
    Trap(#[from] TrapError),
    #[error("syscall dispatch failed: {0}")]
    Dispatch(#[from] DispatchError),
    #[error("guest did not exit after {max_traps} traps")]
    TrapLimitExceeded { max_traps: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub traps: usize,
    pub report: CompatReport,
}

pub fn run_static_elf_with_hvf(
    path: impl AsRef<Path>,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    run_static_elf_with_hvf_and_dispatcher(path, SyscallDispatcher::new(), max_traps)
}

pub fn run_static_elf_with_hvf_and_dispatcher(
    path: impl AsRef<Path>,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let path = path.as_ref();
    run_static_elf_with_hvf_args_and_dispatcher(
        path,
        dispatcher,
        [path.to_string_lossy().into_owned()],
        std::iter::empty(),
        max_traps,
    )
}

pub fn run_static_elf_with_hvf_args_and_dispatcher<A, E>(
    path: impl AsRef<Path>,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let image = AddressSpace::load_elf(path)?
        .with_linux_initial_stack(argv, env)?
        .with_el0_trampoline()?;
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_static_elf_bytes_with_hvf_and_dispatcher(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let image = AddressSpace::load_elf_bytes(bytes)?.with_el0_trampoline()?;
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_static_elf_bytes_with_hvf_args_and_dispatcher<A, E>(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let image = AddressSpace::load_elf_bytes(bytes)?
        .with_linux_initial_stack(argv, env)?
        .with_el0_trampoline()?;
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_rootfs_elf_with_hvf_args_and_dispatcher<A, E>(
    path: impl AsRef<Path>,
    rootfs: &RootFs,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let image = AddressSpace::load_elf_from_rootfs(path, rootfs)?
        .with_linux_initial_stack(argv, env)?
        .with_el0_trampoline()?;
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_rootfs_elf_with_hvf_args<A, E>(
    path: impl AsRef<Path>,
    rootfs: &RootFs,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let path = path.as_ref();
    run_rootfs_elf_with_hvf_args_and_dispatcher(
        path,
        rootfs,
        SyscallDispatcher::with_rootfs_and_executable(
            rootfs.clone(),
            path.to_string_lossy().into_owned(),
        ),
        argv,
        env,
        max_traps,
    )
}

fn run_address_space_with_hvf_and_dispatcher(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let mut trap = HvfTrapEngine::new()?;
    trap.map_address_space(&image)?;
    run_combined_syscall_loop_with_dispatcher(&mut trap, dispatcher, max_traps)
}

pub fn run_syscall_loop<M, T>(
    memory: &mut M,
    trap: &mut T,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    run_syscall_loop_with_dispatcher(memory, trap, SyscallDispatcher::new(), max_traps)
}

pub fn run_syscall_loop_with_dispatcher<M, T>(
    memory: &mut M,
    trap: &mut T,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    run_split_loop(memory, trap, dispatcher, max_traps)
}

pub fn run_combined_syscall_loop<R>(
    runtime: &mut R,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    R: GuestMemory + SyscallTrap,
{
    run_combined_syscall_loop_with_dispatcher(runtime, SyscallDispatcher::new(), max_traps)
}

pub fn run_combined_syscall_loop_with_dispatcher<R>(
    runtime: &mut R,
    mut dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    R: GuestMemory + SyscallTrap,
{
    let mut reporter = CompatReporter::default();

    for traps in 1..=max_traps {
        let frame = runtime.next_syscall()?;
        let outcome = dispatcher.dispatch(
            SyscallRequest::from_aarch64_frame(frame),
            runtime,
            &mut reporter,
        )?;

        match outcome {
            DispatchOutcome::Exit { code } => {
                return Ok(RunResult {
                    exit_code: code,
                    stdout: dispatcher.stdout().to_vec(),
                    stderr: dispatcher.stderr().to_vec(),
                    traps,
                    report: reporter.finish(),
                });
            }
            DispatchOutcome::Returned { value } => runtime.complete_syscall(value)?,
            DispatchOutcome::Errno { errno } => runtime.complete_syscall(-(errno as i64))?,
        }
    }

    Err(RuntimeError::TrapLimitExceeded { max_traps })
}

fn run_split_loop<M, T>(
    memory: &mut M,
    trap: &mut T,
    mut dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    let mut reporter = CompatReporter::default();

    for traps in 1..=max_traps {
        let frame = trap.next_syscall()?;
        let outcome = dispatcher.dispatch(
            SyscallRequest::from_aarch64_frame(frame),
            memory,
            &mut reporter,
        )?;

        match outcome {
            DispatchOutcome::Exit { code } => {
                return Ok(RunResult {
                    exit_code: code,
                    stdout: dispatcher.stdout().to_vec(),
                    stderr: dispatcher.stderr().to_vec(),
                    traps,
                    report: reporter.finish(),
                });
            }
            DispatchOutcome::Returned { value } => trap.complete_syscall(value)?,
            DispatchOutcome::Errno { errno } => trap.complete_syscall(-(errno as i64))?,
        }
    }

    Err(RuntimeError::TrapLimitExceeded { max_traps })
}

impl SyscallTrap for HvfTrapEngine {
    fn next_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        self.run_until_syscall()
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.complete_syscall(return_value)
    }
}
