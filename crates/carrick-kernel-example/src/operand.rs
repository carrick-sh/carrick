//! Generic syscall vocabulary: operands, save directives, expectations, and steps.

use carrick_abi::{CanonicalNr, LinuxErrno};

/// Where a syscall takes an argument from or materialises a buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A literal integer value.
    Lit(i64),
    /// A value saved into a slot by an earlier syscall in this task (inherited across fork).
    Slot(usize),
    /// The pid of the most recent fork child of this task.
    LastChild,
    /// A byte buffer materialised into task memory; the syscall argument is its guest address.
    Bytes(Vec<u8>),
    /// A NUL-terminated C string materialised into task memory.
    CStr(String),
    /// A zeroed output buffer of `n` bytes allocated in task memory; captured into the report after the call.
    Out(usize),
    /// A buffer initialized with bytes whose updated contents are captured into the report after the call.
    InOut(Vec<u8>),
}

/// A value to save from a syscall's result or output buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Save {
    /// Save the syscall return value into `slot`.
    Ret(usize),
    /// Read the `index`-th `i32` (little-endian) of the `Out` buffer at argument `arg` into `slot`.
    OutI32 {
        arg: usize,
        index: usize,
        slot: usize,
    },
}

/// The expected outcome of a syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Any successful outcome is accepted: return values or process exits. Fails if an unexpected errno is returned.
    Any,
    /// Expect a successful return value `v`. Fails on errno, exit, or mismatching return value.
    Ret(i64),
    /// Expect an errno `e`. Fails on normal return, exit, or mismatching errno.
    Errno(LinuxErrno),
    /// Expect the task to die by signal `signal` while inside this syscall.
    Death(i32),
}

/// A single syscall description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Syscall {
    /// Diagnostic label for this syscall.
    pub label: &'static str,
    /// Canonical syscall number.
    pub nr: CanonicalNr,
    /// 6 syscall arguments.
    pub args: [Operand; 6],
    /// Save actions to run upon completion.
    pub saves: Vec<Save>,
    /// Expected outcome.
    pub expect: Expect,
}

impl Syscall {
    /// Create a new syscall with `Expect::Any` and no saves.
    pub const fn new(label: &'static str, nr: CanonicalNr, args: [Operand; 6]) -> Self {
        Self {
            label,
            nr,
            args,
            saves: Vec::new(),
            expect: Expect::Any,
        }
    }

    /// Set expectation to `Expect::Ret(v)`.
    pub fn ret(mut self, v: i64) -> Self {
        self.expect = Expect::Ret(v);
        self
    }

    /// Set expectation to `Expect::Errno(e)`.
    pub fn errno(mut self, e: LinuxErrno) -> Self {
        self.expect = Expect::Errno(e);
        self
    }

    /// Set expectation to `Expect::Death(signal)`.
    pub fn death(mut self, signal: i32) -> Self {
        self.expect = Expect::Death(signal);
        self
    }

    /// Save the return value into `slot`.
    pub fn save(mut self, slot: usize) -> Self {
        self.saves.push(Save::Ret(slot));
        self
    }

    /// Read the `index`-th `i32` of the `Out` buffer at `arg` into `slot`.
    pub fn save_out_i32(mut self, arg: usize, index: usize, slot: usize) -> Self {
        self.saves.push(Save::OutI32 { arg, index, slot });
        self
    }
}

/// One step in a task script.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Issue a syscall.
    Sys(Syscall),
    /// The script the child of the preceding fork runs.
    ChildMarker(Vec<Step>),
    /// Wait for another task to park/enroll in a specific syscall before continuing.
    AwaitParked {
        /// PID operand of the task to await.
        pid: Operand,
        /// Syscall label that must be parked/enrolled.
        label: &'static str,
    },
}

/// Await enrollment/parking of syscall `label` on task `pid`.
pub fn await_parked(pid: impl Into<Operand>, label: &'static str) -> Step {
    Step::AwaitParked {
        pid: pid.into(),
        label,
    }
}

/// Reference slot `i` of the task's slot table.
pub const fn slot(i: usize) -> Operand {
    Operand::Slot(i)
}

/// Reference the pid of the most recent fork child.
pub const fn last_child() -> Operand {
    Operand::LastChild
}

/// A buffer initialized with `bytes` whose updated contents are captured into the report after the call.
pub fn in_out(bytes: &[u8]) -> Operand {
    Operand::InOut(bytes.to_vec())
}

impl From<i64> for Operand {
    fn from(v: i64) -> Self {
        Operand::Lit(v)
    }
}

impl From<i32> for Operand {
    fn from(v: i32) -> Self {
        Operand::Lit(v as i64)
    }
}

impl From<u32> for Operand {
    fn from(v: u32) -> Self {
        Operand::Lit(v as i64)
    }
}

impl From<usize> for Operand {
    fn from(v: usize) -> Self {
        Operand::Lit(v as i64)
    }
}

impl From<u64> for Operand {
    fn from(v: u64) -> Self {
        Operand::Lit(v as i64)
    }
}

impl From<&[u8]> for Operand {
    fn from(bytes: &[u8]) -> Self {
        Operand::Bytes(bytes.to_vec())
    }
}

impl From<Vec<u8>> for Operand {
    fn from(bytes: Vec<u8>) -> Self {
        Operand::Bytes(bytes)
    }
}

impl From<&str> for Operand {
    fn from(s: &str) -> Self {
        Operand::CStr(s.to_string())
    }
}

impl From<String> for Operand {
    fn from(s: String) -> Self {
        Operand::CStr(s)
    }
}
