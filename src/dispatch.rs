use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::syscall::lookup_aarch64;
use serde::Serialize;
use thiserror::Error;

pub const LINUX_EBADF: i32 = 9;
pub const LINUX_EFAULT: i32 = 14;
pub const LINUX_ENOSYS: i32 = 38;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyscallRequest {
    pub number: u64,
    pub args: SyscallArgs,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Aarch64SyscallFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x8: u64,
}

impl SyscallRequest {
    pub fn new(number: u64, args: SyscallArgs) -> Self {
        Self { number, args }
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.args.0[index]
    }

    pub fn from_aarch64_frame(frame: Aarch64SyscallFrame) -> Self {
        Self {
            number: frame.x8,
            args: SyscallArgs::from([frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOutcome {
    Returned { value: i64 },
    Errno { errno: i32 },
    Exit { code: i32 },
}

impl DispatchOutcome {
    fn retval_errno(&self) -> (i64, Option<i32>) {
        match *self {
            DispatchOutcome::Returned { value } => (value, None),
            DispatchOutcome::Errno { errno } => (-(errno as i64), Some(errno)),
            DispatchOutcome::Exit { code } => (code as i64, None),
        }
    }
}

pub trait GuestMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl LinearMemory {
    pub fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self { base, bytes }
    }
}

impl GuestMemory for LinearMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(self.bytes[offset..end].to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryError {
    #[error("guest memory read is out of bounds at 0x{address:x} for {length} bytes")]
    OutOfBounds { address: u64, length: usize },
}

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("guest memory read length does not fit this host: {0}")]
    LengthTooLarge(u64),
}

pub struct SyscallDispatcher<'mem, M: GuestMemory> {
    memory: &'mem M,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl<'mem, M: GuestMemory> SyscallDispatcher<'mem, M> {
    pub fn new(memory: &'mem M) -> Self {
        Self {
            memory,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn dispatch(
        &mut self,
        request: SyscallRequest,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: name.to_owned(),
            args: request.args,
        });

        let outcome = match request.number {
            64 => self.write(request)?,
            93 => self.exit(request),
            _ => {
                reporter.record(CompatEvent::unhandled_syscall(
                    request.number,
                    name,
                    request.args,
                ));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOSYS,
                }
            }
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: name.to_owned(),
            retval,
            errno,
        });

        Ok(outcome)
    }

    fn write(&mut self, request: SyscallRequest) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0);
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let bytes = match self.memory.read_bytes(address, length) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        };

        match fd {
            1 => self.stdout.extend_from_slice(&bytes),
            2 => self.stderr.extend_from_slice(&bytes),
            _ => {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
        }

        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn exit(&self, request: SyscallRequest) -> DispatchOutcome {
        DispatchOutcome::Exit {
            code: request.arg(0) as i32,
        }
    }
}
