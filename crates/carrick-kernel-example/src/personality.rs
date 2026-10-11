use carrick_core::personality::{
    CallContext, CallOrdinal, EntryDecodeError, Personality, PersonalityAbi, TaskKey, ThreadKey,
};
use carrick_guest_arch::{
    Aarch64Register, Aarch64Registers, ArchTypes, EntryArch, EntryBackend, EntryEvent, GuestIsa,
    KernelStackPointer, NativeAbi, NativeEntrySnapshot, NativeReturnWord, ThreadPointerRegister,
    UserReturn, UserVa, X86Register, X86Registers,
};
use parking_lot::RwLock;
use std::collections::HashMap;

/// In-tree test personality with configurable thread base pointer register.
#[derive(Debug)]
pub struct ExamplePersonality {
    default_register: ThreadPointerRegister,
    thread_overrides: RwLock<HashMap<ThreadKey, ThreadPointerRegister>>,
    task_overrides: RwLock<HashMap<TaskKey, ThreadPointerRegister>>,
}

impl ExamplePersonality {
    /// Create an instance using the architecture's non-standard thread pointer register:
    /// `GS` on x86_64, `x18` on AArch64.
    pub fn new() -> Self {
        #[cfg(target_arch = "x86_64")]
        let default_register = ThreadPointerRegister::GS;
        #[cfg(target_arch = "aarch64")]
        let default_register = ThreadPointerRegister::X18;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let default_register = ThreadPointerRegister::GS;

        Self {
            default_register,
            thread_overrides: RwLock::new(HashMap::new()),
            task_overrides: RwLock::new(HashMap::new()),
        }
    }

    /// Create an instance with an explicit default thread pointer register.
    pub fn with_default_register(default_register: ThreadPointerRegister) -> Self {
        Self {
            default_register,
            thread_overrides: RwLock::new(HashMap::new()),
            task_overrides: RwLock::new(HashMap::new()),
        }
    }

    /// Configure a thread-specific thread pointer register.
    pub fn configure_thread(&self, thread: ThreadKey, register: ThreadPointerRegister) {
        self.thread_overrides.write().insert(thread, register);
    }

    /// Configure a task-specific thread pointer register.
    pub fn configure_task(&self, task: TaskKey, register: ThreadPointerRegister) {
        self.task_overrides.write().insert(task, register);
    }
}

impl Default for ExamplePersonality {
    fn default() -> Self {
        Self::new()
    }
}

impl Personality for ExamplePersonality {
    fn name(&self) -> &'static str {
        "example"
    }

    fn thread_pointer_register(&self) -> ThreadPointerRegister {
        self.default_register
    }

    fn thread_pointer_register_for_thread(&self, thread: ThreadKey) -> ThreadPointerRegister {
        self.thread_overrides
            .read()
            .get(&thread)
            .copied()
            .unwrap_or(self.default_register)
    }

    fn thread_pointer_register_for_task(&self, task: TaskKey) -> ThreadPointerRegister {
        self.task_overrides
            .read()
            .get(&task)
            .copied()
            .unwrap_or(self.default_register)
    }
}

/// A decoded invocation produced by [`PersonalityAbi::decode`] for [`ExamplePersonality`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExampleCall {
    pub ordinal: CallOrdinal,
    pub args: [u64; 6],
    pub stack: UserVa,
}

/// Snapshot accessor trait for synthetic test entry frames.
pub trait ExampleFrameSnapshot {
    fn read_x86(&self, register: X86Register) -> Result<u64, EntryDecodeError> {
        let _ = register;
        Err(EntryDecodeError::UnsupportedAbi)
    }

    fn read_aarch64(&self, register: Aarch64Register) -> Result<u64, EntryDecodeError> {
        let _ = register;
        Err(EntryDecodeError::UnsupportedAbi)
    }

    fn set_return_result(&mut self, result: u64) -> Result<(), EntryDecodeError> {
        let _ = result;
        Ok(())
    }
}

impl<A: EntryArch> PersonalityAbi<A> for ExamplePersonality
where
    A::NativeFrame: ExampleFrameSnapshot,
    EntryDecodeError: From<A::Error>,
{
    type Call = ExampleCall;

    fn decode(&self, cx: &mut CallContext<'_, A>) -> Result<Self::Call, EntryDecodeError> {
        let snapshot = cx.snapshot()?;
        let stack = cx.user_stack_pointer()?;
        match snapshot.isa {
            GuestIsa::X86_64 => {
                if snapshot.abi != NativeAbi::X86_64Syscall {
                    return Err(EntryDecodeError::UnsupportedAbi);
                }
                let ordinal = CallOrdinal::from_raw(snapshot.frame.read_x86(X86Register::Rax)?);
                let args = [
                    snapshot.frame.read_x86(X86Register::Rdi)?,
                    snapshot.frame.read_x86(X86Register::Rsi)?,
                    snapshot.frame.read_x86(X86Register::Rdx)?,
                    snapshot.frame.read_x86(X86Register::R10)?,
                    snapshot.frame.read_x86(X86Register::R8)?,
                    snapshot.frame.read_x86(X86Register::R9)?,
                ];
                Ok(ExampleCall {
                    ordinal,
                    args,
                    stack,
                })
            }
            GuestIsa::Aarch64 => {
                if snapshot.abi != NativeAbi::Aarch64El0 {
                    return Err(EntryDecodeError::UnsupportedAbi);
                }
                let ordinal =
                    CallOrdinal::from_raw(snapshot.frame.read_aarch64(Aarch64Register::X8)?);
                let args = [
                    snapshot.frame.read_aarch64(Aarch64Register::X0)?,
                    snapshot.frame.read_aarch64(Aarch64Register::X1)?,
                    snapshot.frame.read_aarch64(Aarch64Register::X2)?,
                    snapshot.frame.read_aarch64(Aarch64Register::X3)?,
                    snapshot.frame.read_aarch64(Aarch64Register::X4)?,
                    snapshot.frame.read_aarch64(Aarch64Register::X5)?,
                ];
                Ok(ExampleCall {
                    ordinal,
                    args,
                    stack,
                })
            }
        }
    }

    fn encode_return(
        &self,
        result: NativeReturnWord,
        frame: &mut A::NativeFrame,
    ) -> Result<(), EntryDecodeError> {
        frame.set_return_result(result.0)
    }
}

/// Simulated architectural entry frame for testing named register snapshots and stack argument decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExampleFrame {
    pub ordinal: CallOrdinal,
    pub reg_args: [u64; 6],
    pub user_sp: UserVa,
    pub result: u64,
}

impl ExampleFrame {
    pub fn read_x86_reg(&self, register: X86Register) -> u64 {
        match register {
            X86Register::Rax => self.ordinal.raw(),
            X86Register::Rdi => self.reg_args[0],
            X86Register::Rsi => self.reg_args[1],
            X86Register::Rdx => self.reg_args[2],
            X86Register::R10 => self.reg_args[3],
            X86Register::R8 => self.reg_args[4],
            X86Register::R9 => self.reg_args[5],
            X86Register::Rsp => self.user_sp.raw(),
            _ => 0,
        }
    }

    pub fn read_aarch64_reg(&self, register: Aarch64Register) -> u64 {
        match register {
            Aarch64Register::X8 => self.ordinal.raw(),
            Aarch64Register::X0 => self.reg_args[0],
            Aarch64Register::X1 => self.reg_args[1],
            Aarch64Register::X2 => self.reg_args[2],
            Aarch64Register::X3 => self.reg_args[3],
            Aarch64Register::X4 => self.reg_args[4],
            Aarch64Register::X5 => self.reg_args[5],
            Aarch64Register::Sp => self.user_sp.raw(),
            _ => 0,
        }
    }
}

impl X86Registers for ExampleFrame {
    fn read(&self, register: X86Register) -> u64 {
        self.read_x86_reg(register)
    }
}

impl Aarch64Registers for ExampleFrame {
    fn read(&self, register: Aarch64Register) -> u64 {
        self.read_aarch64_reg(register)
    }
}

impl ExampleFrameSnapshot for ExampleFrame {
    fn read_x86(&self, register: X86Register) -> Result<u64, EntryDecodeError> {
        Ok(self.read_x86_reg(register))
    }

    fn read_aarch64(&self, register: Aarch64Register) -> Result<u64, EntryDecodeError> {
        Ok(self.read_aarch64_reg(register))
    }

    fn set_return_result(&mut self, result: u64) -> Result<(), EntryDecodeError> {
        self.result = result;
        Ok(())
    }
}

/// Simulated architecture entry backend for VM-free scenario and stack argument tests.
#[derive(Debug)]
pub struct ExampleEntryBackend {
    pages: HashMap<u64, (bool, [u8; 4096])>,
    isa: GuestIsa,
    abi: NativeAbi,
}

impl Default for ExampleEntryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ExampleEntryBackend {
    /// Create a new empty simulated entry backend defaulting to x86_64.
    pub fn new() -> Self {
        Self {
            pages: HashMap::new(),
            isa: GuestIsa::X86_64,
            abi: NativeAbi::X86_64Syscall,
        }
    }

    /// Configure the ISA and entry ABI for this backend.
    pub fn with_isa(mut self, isa: GuestIsa, abi: NativeAbi) -> Self {
        self.isa = isa;
        self.abi = abi;
        self
    }

    /// Map a 4096-byte page at the given virtual address with the specified read permission.
    pub fn map_page(&mut self, va: u64, readable: bool) {
        let page_base = va & !0xfff;
        self.pages
            .entry(page_base)
            .or_insert((readable, [0u8; 4096]))
            .0 = readable;
    }

    /// Write an unsigned 64-bit little-endian value at the specified virtual address.
    pub fn write_u64(&mut self, va: u64, val: u64) {
        let page_base = va & !0xfff;
        let offset = (va & 0xfff) as usize;
        let entry = self.pages.entry(page_base).or_insert((true, [0u8; 4096]));
        if offset + 8 <= 4096 {
            entry.1[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    /// Write arbitrary bytes at the specified virtual address.
    pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let addr = va + i as u64;
            let page_base = addr & !0xfff;
            let offset = (addr & 0xfff) as usize;
            let entry = self.pages.entry(page_base).or_insert((true, [0u8; 4096]));
            entry.1[offset] = b;
        }
    }

    /// Construct a synthetic native frame.
    pub fn create_frame(&self, ordinal: u64, reg_args: [u64; 6], user_sp: u64) -> ExampleFrame {
        ExampleFrame {
            ordinal: CallOrdinal::from_raw(ordinal),
            reg_args,
            user_sp: UserVa::new(user_sp),
            result: 0,
        }
    }
}

impl ArchTypes for ExampleEntryBackend {
    type Error = EntryDecodeError;
    type NativeFrame = ExampleFrame;
    type SavedContext = ();
    type Context = [u64; 4];
    type Root = u64;
    type MmOwner = ();
    type DrainTicket = ();
    type DrainReceipt = ();
    type UserTransfer = ();
    type HardwareInterrupt = u32;
    type InterruptMask = u32;
}

impl EntryBackend for ExampleEntryBackend {
    fn current_stack_pointer(&mut self) -> Result<KernelStackPointer, Self::Error> {
        Ok(KernelStackPointer::new(0x7000_0000))
    }

    fn decode_entry(&mut self, _frame: &Self::NativeFrame) -> Result<EntryEvent, Self::Error> {
        Err(EntryDecodeError::InvalidFrame)
    }

    fn snapshot<'a>(
        &mut self,
        frame: &'a Self::NativeFrame,
    ) -> Result<NativeEntrySnapshot<'a, Self::NativeFrame>, Self::Error> {
        Ok(NativeEntrySnapshot {
            isa: self.isa,
            abi: self.abi,
            frame,
        })
    }

    fn set_result(
        &mut self,
        frame: &mut Self::NativeFrame,
        result: NativeReturnWord,
    ) -> Result<(), Self::Error> {
        frame.result = result.0;
        Ok(())
    }

    fn save_context(
        &mut self,
        _frame: &Self::NativeFrame,
    ) -> Result<Self::SavedContext, Self::Error> {
        Ok(())
    }

    fn load_context(
        &mut self,
        _frame: &mut Self::NativeFrame,
        _saved: &Self::SavedContext,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn prepare_user_return(
        &mut self,
        _frame: &Self::NativeFrame,
    ) -> Result<UserReturn, Self::Error> {
        Err(EntryDecodeError::InvalidFrame)
    }

    fn user_stack_pointer(&mut self, frame: &Self::NativeFrame) -> Result<UserVa, Self::Error> {
        let va = frame.user_sp.raw();
        let page_base = va & !0xfff;
        let (readable, _) = self.pages.get(&page_base).ok_or(EntryDecodeError::Fault)?;
        if !readable {
            return Err(EntryDecodeError::Fault);
        }
        Ok(frame.user_sp)
    }
}
