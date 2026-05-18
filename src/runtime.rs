use std::path::Path;

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{
    Aarch64SyscallFrame, DispatchError, DispatchOutcome, GuestMemory, SyscallDispatcher,
    SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
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
    let image = AddressSpace::load_elf(path)?;
    let mut trap = HvfTrapEngine::new()?;
    trap.map_address_space(&image)?;
    run_syscall_loop(&image, &mut trap, max_traps)
}

pub fn run_syscall_loop<M, T>(
    memory: &M,
    trap: &mut T,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new(memory);

    for traps in 1..=max_traps {
        let frame = trap.next_syscall()?;
        let outcome =
            dispatcher.dispatch(SyscallRequest::from_aarch64_frame(frame), &mut reporter)?;

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
