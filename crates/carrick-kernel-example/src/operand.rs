//! Generic syscall vocabulary: operands, save directives, expectations, and steps.

use carrick_abi::{CanonicalNr, LinuxErrno};

/// Width and encoding of a relocation field in a memory layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocWidth {
    /// 1-byte integer.
    U8,
    /// 2-byte unsigned integer (little-endian).
    U16,
    /// 2-byte signed integer (little-endian).
    I16,
    /// 4-byte unsigned integer (little-endian).
    U32,
    /// 4-byte signed integer (little-endian).
    I32,
    /// 8-byte unsigned integer (little-endian) / pointer.
    U64,
    /// 8-byte signed integer (little-endian).
    I64,
}

impl RelocWidth {
    /// The size in bytes of this relocation width.
    pub const fn bytes(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 => 4,
            Self::U64 | Self::I64 => 8,
        }
    }
}

/// A relocation directive inside a [`Layout`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// Byte offset within the layout buffer.
    pub offset: usize,
    /// Width and type of the value to write.
    pub width: RelocWidth,
    /// Target operand to resolve and write.
    pub operand: Operand,
}

/// A generic typed memory layout with checked relocations and nested operands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Initial / template bytes of the layout buffer.
    pub bytes: Vec<u8>,
    /// Relocations to apply to these bytes during resolution.
    pub relocations: Vec<Relocation>,
    /// Whether this layout buffer itself should be captured into the report outputs.
    pub capture: bool,
    /// An optional diagnostic / indexing tag for unambiguous output buffer identification.
    pub tag: Option<&'static str>,
}

impl Layout {
    /// Create a new zero-initialized layout of `size` bytes.
    pub fn new(size: usize) -> Self {
        Self {
            bytes: vec![0u8; size],
            relocations: Vec::new(),
            capture: false,
            tag: None,
        }
    }

    /// Create a layout initialized with `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            relocations: Vec::new(),
            capture: false,
            tag: None,
        }
    }

    /// Configure whether this layout should be captured into the report after the syscall completes.
    pub const fn with_capture(mut self, capture: bool) -> Self {
        self.capture = capture;
        self
    }

    /// Assign a diagnostic / indexing tag to this layout.
    pub const fn with_tag(mut self, tag: &'static str) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Add a relocation at `offset` with `width` pointing to `operand`.
    pub fn with_reloc(
        mut self,
        offset: usize,
        width: RelocWidth,
        operand: impl Into<Operand>,
    ) -> Self {
        self.relocations.push(Relocation {
            offset,
            width,
            operand: operand.into(),
        });
        self
    }

    /// Write an immediate `u8` at `offset` via a checked relocation.
    pub fn with_u8(self, offset: usize, val: u8) -> Self {
        self.with_reloc(offset, RelocWidth::U8, val as i64)
    }

    /// Write an immediate `u16` (little-endian) at `offset` via a checked relocation.
    pub fn with_u16(self, offset: usize, val: u16) -> Self {
        self.with_reloc(offset, RelocWidth::U16, val as i64)
    }

    /// Write an immediate `i16` (little-endian) at `offset` via a checked relocation.
    pub fn with_i16(self, offset: usize, val: i16) -> Self {
        self.with_reloc(offset, RelocWidth::I16, val as i64)
    }

    /// Write an immediate `u32` (little-endian) at `offset` via a checked relocation.
    pub fn with_u32(self, offset: usize, val: u32) -> Self {
        self.with_reloc(offset, RelocWidth::U32, val as i64)
    }

    /// Write an immediate `i32` (little-endian) at `offset` via a checked relocation.
    pub fn with_i32(self, offset: usize, val: i32) -> Self {
        self.with_reloc(offset, RelocWidth::I32, val as i64)
    }

    /// Write an immediate `u64` (little-endian) at `offset` via a checked relocation.
    pub fn with_u64(self, offset: usize, val: u64) -> Self {
        self.with_reloc(offset, RelocWidth::U64, val as i64)
    }

    /// Write an immediate `i64` (little-endian) at `offset` via a checked relocation.
    pub fn with_i64(self, offset: usize, val: i64) -> Self {
        self.with_reloc(offset, RelocWidth::I64, val)
    }
}

/// Where a syscall takes an argument from or materialises a buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A literal integer value.
    Lit(i64),
    /// A value saved into a slot by an earlier syscall in this task (inherited across fork).
    Slot(usize),
    /// Negation of a value saved into a slot: `-slot[s]` (useful for group pids).
    Negated(usize),
    /// The pid of the most recent fork child of this task.
    LastChild,
    /// A byte buffer materialised into task memory; the syscall argument is its guest address.
    Bytes(Vec<u8>),
    /// A NUL-terminated C string materialised into task memory.
    CStr(String),
    /// A zeroed output buffer of `n` bytes allocated in task memory; captured into the report after the call.
    Out(usize),
    /// A zeroed output buffer of `n` bytes with a diagnostic tag; captured into the report after the call.
    TaggedOut(&'static str, usize),
    /// A buffer initialized with bytes whose updated contents are captured into the report after the call.
    InOut(Vec<u8>),
    /// A buffer initialized with bytes and a tag whose updated contents are captured into the report after the call.
    TaggedInOut(&'static str, Vec<u8>),
    /// A typed memory layout with relocations and optional nested operands.
    Layout(Box<Layout>),
}

/// A value to save from a syscall's result or output buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Save {
    /// Save the syscall return value into `slot`.
    Ret(usize),
    /// Read the `index`-th `i32` (offset = index * 4, little-endian) of the `Out` buffer at argument `arg` into `slot`.
    OutI32 {
        arg: usize,
        index: usize,
        slot: usize,
    },
    /// Read an `i32` at byte `offset` (little-endian) from the output buffer at argument `arg` into `slot`.
    OutI32At {
        arg: usize,
        offset: usize,
        slot: usize,
    },
    /// Read an `i32` at byte `offset` (little-endian) from the output buffer with `tag` into `slot`.
    TaggedOutI32 {
        tag: &'static str,
        offset: usize,
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

    /// Read an `i32` at byte `offset` of the `Out` buffer at `arg` into `slot`.
    pub fn save_out_i32_at(mut self, arg: usize, offset: usize, slot: usize) -> Self {
        self.saves.push(Save::OutI32At { arg, offset, slot });
        self
    }

    /// Read an `i32` at byte `offset` of the tagged output buffer `tag` into `slot`.
    pub fn save_tagged_out_i32(mut self, tag: &'static str, offset: usize, slot: usize) -> Self {
        self.saves.push(Save::TaggedOutI32 { tag, offset, slot });
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
    /// Allocate a persistent buffer in task memory initialized with `bytes` and store its guest address in `slot`.
    AllocBuffer {
        /// Target slot index to save the allocated guest address.
        slot: usize,
        /// Initial bytes to populate in the buffer.
        bytes: Vec<u8>,
    },
    /// Write `bytes` to the persistent buffer address stored in `slot`.
    WriteBuffer {
        /// Slot holding the guest address to write to.
        slot: usize,
        /// Bytes to write.
        bytes: Vec<u8>,
    },
}

/// Allocate a persistent buffer initialized with `bytes` in task memory and store its address in `slot`.
pub fn alloc_buffer(slot: usize, bytes: impl Into<Vec<u8>>) -> Step {
    Step::AllocBuffer {
        slot,
        bytes: bytes.into(),
    }
}

/// Allocate a 4-byte 32-bit integer word in task memory and store its address in `slot`.
pub fn alloc_word(slot: usize, val: i32) -> Step {
    alloc_buffer(slot, val.to_le_bytes().to_vec())
}

/// Write `bytes` to the persistent buffer address stored in `slot`.
pub fn write_buffer(slot: usize, bytes: impl Into<Vec<u8>>) -> Step {
    Step::WriteBuffer {
        slot,
        bytes: bytes.into(),
    }
}

/// Write a 4-byte 32-bit integer word to the persistent buffer address stored in `slot`.
pub fn write_word(slot: usize, val: i32) -> Step {
    write_buffer(slot, val.to_le_bytes().to_vec())
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

/// Reference the negation of slot `i`: `-slot[i]`.
pub const fn negated(i: usize) -> Operand {
    Operand::Negated(i)
}

/// Reference the pid of the most recent fork child.
pub const fn last_child() -> Operand {
    Operand::LastChild
}

/// A zeroed output buffer of `n` bytes with a diagnostic tag.
pub const fn tagged_out(tag: &'static str, size: usize) -> Operand {
    Operand::TaggedOut(tag, size)
}

/// A buffer initialized with `bytes` whose updated contents are captured into the report after the call.
pub fn in_out(bytes: &[u8]) -> Operand {
    Operand::InOut(bytes.to_vec())
}

/// A buffer initialized with `bytes` and a diagnostic tag whose updated contents are captured into the report after the call.
pub fn tagged_in_out(tag: &'static str, bytes: &[u8]) -> Operand {
    Operand::TaggedInOut(tag, bytes.to_vec())
}

impl From<Layout> for Operand {
    fn from(l: Layout) -> Self {
        Operand::Layout(Box::new(l))
    }
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
