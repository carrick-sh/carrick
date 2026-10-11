use carrick_core::personality::{
    CallContext, CallOrdinal, EntryDecodeError, Personality, PersonalityAbi, ServiceError, TaskKey,
    ThreadKey,
};
use carrick_guest_arch::{
    Aarch64Register, Aarch64Registers, Access, AddressContext, ArchTypes, CopyProgress,
    DefaultMmOwner, EntryArch, EntryBackend, EntryEvent, GuestIsa, GuestLen, KernelStackPointer,
    MmuArch, MmuBackend, NativeAbi, NativeEntrySnapshot, NativeReturnWord, ThreadPointerRegister,
    TransferDirection, UserRange, UserReturn, UserVa, X86Register, X86Registers,
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
    pub args: [u64; 8],
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

impl<A: EntryArch + MmuArch + DefaultMmOwner> PersonalityAbi<A> for ExamplePersonality
where
    A::NativeFrame: ExampleFrameSnapshot,
    EntryDecodeError: From<A::Error>,
    ServiceError: From<A::Error>,
{
    type Call = ExampleCall;

    fn decode(&self, cx: &mut CallContext<'_, A>) -> Result<Self::Call, EntryDecodeError> {
        let snapshot = cx.snapshot()?;
        let stack = cx.user_stack_pointer()?;
        let (ordinal, reg_args) = match snapshot.isa {
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
                (ordinal, args)
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
                (ordinal, args)
            }
        };

        // In this test ABI, spilled arguments 7 and 8 are decoded from the guest user stack at sp+0 and sp+8.
        let mut arg7_bytes = [0u8; 8];
        let mut arg8_bytes = [0u8; 8];
        cx.user().copy_in(stack, &mut arg7_bytes)?;
        let sp_plus_8 = UserVa::new(stack.raw().checked_add(8).ok_or(EntryDecodeError::Fault)?);
        cx.user().copy_in(sp_plus_8, &mut arg8_bytes)?;

        let mut args = [0u64; 8];
        args[..6].copy_from_slice(&reg_args);
        args[6] = u64::from_le_bytes(arg7_bytes);
        args[7] = u64::from_le_bytes(arg8_bytes);

        Ok(ExampleCall {
            ordinal,
            args,
            stack,
        })
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

/// Page state tracking read and write permissions for VM-free test addresses.
#[derive(Clone, Debug)]
pub struct PageState {
    pub readable: bool,
    pub writable: bool,
    pub data: [u8; 4096],
}

/// Bounded transfer state for the example personality entry backend.
pub struct ExampleUserTransfer {
    user: UserVa,
    kernel: core::ptr::NonNull<u8>,
    total: GuestLen,
    completed: GuestLen,
    direction: TransferDirection,
}

/// Simulated architecture entry backend for VM-free scenario and stack argument tests.
#[derive(Debug)]
pub struct ExampleEntryBackend {
    pages: HashMap<u64, PageState>,
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

    /// Map a 4096-byte page at the given virtual address with read-only permission.
    pub fn map_page(&mut self, va: u64, readable: bool) {
        self.map_page_with_perms(va, readable, false);
    }

    /// Map a 4096-byte page at the given virtual address with explicit read and write permissions.
    pub fn map_page_with_perms(&mut self, va: u64, readable: bool, writable: bool) {
        let page_base = va & !0xfff;
        let entry = self.pages.entry(page_base).or_insert_with(|| PageState {
            readable,
            writable,
            data: [0u8; 4096],
        });
        entry.readable = readable;
        entry.writable = writable;
    }

    /// Write an unsigned 64-bit little-endian value at the specified virtual address.
    pub fn write_u64(&mut self, va: u64, val: u64) {
        let page_base = va & !0xfff;
        let offset = (va & 0xfff) as usize;
        let entry = self.pages.entry(page_base).or_insert_with(|| PageState {
            readable: true,
            writable: true,
            data: [0u8; 4096],
        });
        if offset + 8 <= 4096 {
            entry.data[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    /// Write arbitrary bytes at the specified virtual address.
    pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let addr = va + i as u64;
            let page_base = addr & !0xfff;
            let offset = (addr & 0xfff) as usize;
            let entry = self.pages.entry(page_base).or_insert_with(|| PageState {
                readable: true,
                writable: true,
                data: [0u8; 4096],
            });
            entry.data[offset] = b;
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
    type UserTransfer = ExampleUserTransfer;
    type HardwareInterrupt = u32;
    type InterruptMask = u32;
}

impl DefaultMmOwner for ExampleEntryBackend {
    fn default_owner() -> Option<&'static Self::MmOwner> {
        static DEFAULT_OWNER: () = ();
        Some(&DEFAULT_OWNER)
    }
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
        let page = self.pages.get(&page_base).ok_or(EntryDecodeError::Fault)?;
        if !page.readable {
            return Err(EntryDecodeError::Fault);
        }
        Ok(frame.user_sp)
    }
}

impl MmuBackend for ExampleEntryBackend {
    fn live_root(&mut self) -> Result<Self::Root, Self::Error> {
        Ok(0)
    }

    fn read_user_word(
        &mut self,
        _owner: &Self::MmOwner,
        address: UserVa,
        width: GuestLen,
    ) -> Result<u64, Self::Error> {
        let va = address.raw();
        let page_base = va & !0xfff;
        let page_offset = (va & 0xfff) as usize;
        let page = self.pages.get(&page_base).ok_or(EntryDecodeError::Fault)?;
        if !page.readable {
            return Err(EntryDecodeError::Fault);
        }
        match width.raw() {
            4 => {
                if page_offset + 4 > 4096 {
                    return Err(EntryDecodeError::Fault);
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&page.data[page_offset..page_offset + 4]);
                Ok(u32::from_le_bytes(bytes) as u64)
            }
            8 => {
                if page_offset + 8 > 4096 {
                    return Err(EntryDecodeError::Fault);
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&page.data[page_offset..page_offset + 8]);
                Ok(u64::from_le_bytes(bytes))
            }
            _ => Err(EntryDecodeError::InvalidWidth),
        }
    }

    fn validate_user_access(
        &mut self,
        _owner: &Self::MmOwner,
        range: UserRange,
        access: Access,
    ) -> Result<GuestLen, Self::Error> {
        if !range.in_lower_half() {
            return Ok(GuestLen::new(0));
        }
        let start = range.start().raw();
        let len = range.len().raw();
        let mut checked = 0u64;
        while checked < len {
            let addr = start + checked;
            let page_base = addr & !0xfff;
            let page_offset = (addr & 0xfff) as usize;
            let page_rem = (4096 - page_offset) as u64;
            let step = (len - checked).min(page_rem);
            let Some(page) = self.pages.get(&page_base) else {
                break;
            };
            let allowed = match access {
                Access::Read => page.readable,
                Access::Write => page.writable,
                Access::Execute => false,
            };
            if !allowed {
                break;
            }
            checked += step;
        }
        Ok(GuestLen::new(checked))
    }

    fn install_context(&mut self, _context: AddressContext<Self::Root>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn request_invalidation(
        &mut self,
        _context: AddressContext<Self::Root>,
        _range: UserRange,
    ) -> Result<Self::DrainTicket, Self::Error> {
        Ok(())
    }

    fn ack_drain(&mut self, _ticket: Self::DrainTicket) -> Result<Self::DrainReceipt, Self::Error> {
        Ok(())
    }

    fn open_user_transfer(
        &mut self,
        _owner: &Self::MmOwner,
        user: UserVa,
        kernel: core::ptr::NonNull<u8>,
        len: GuestLen,
        direction: TransferDirection,
    ) -> Result<Self::UserTransfer, Self::Error> {
        let range = UserRange::checked(user, len).ok_or(EntryDecodeError::OutOfBounds)?;
        if !range.in_lower_half() {
            return Err(EntryDecodeError::OutOfBounds);
        }
        Ok(ExampleUserTransfer {
            user,
            kernel,
            total: len,
            completed: GuestLen::new(0),
            direction,
        })
    }

    fn copy_user_chunk(
        &mut self,
        transfer: &mut Self::UserTransfer,
        limit: GuestLen,
    ) -> Result<CopyProgress, Self::Error> {
        let remaining = transfer.total.raw() - transfer.completed.raw();
        if remaining == 0 || limit.raw() == 0 {
            return Ok(CopyProgress {
                completed: GuestLen::new(0),
                remaining: GuestLen::new(remaining),
            });
        }
        let cur_va = transfer.user.raw() + transfer.completed.raw();
        let page_base = cur_va & !0xfff;
        let page_offset = (cur_va & 0xfff) as usize;
        let page_remaining = 4096 - page_offset;
        let chunk_len = (limit.raw().min(remaining).min(page_remaining as u64)) as usize;

        let page = self
            .pages
            .get_mut(&page_base)
            .ok_or(EntryDecodeError::Fault)?;
        match transfer.direction {
            TransferDirection::FromUser => {
                if !page.readable {
                    return Err(EntryDecodeError::Fault);
                }
                // SAFETY: transfer.kernel is valid for transfer.total bytes and does not alias user pages.
                unsafe {
                    let kptr = transfer
                        .kernel
                        .as_ptr()
                        .add(transfer.completed.raw() as usize);
                    core::ptr::copy_nonoverlapping(&page.data[page_offset], kptr, chunk_len);
                }
            }
            TransferDirection::ToUser => {
                if !page.writable {
                    return Err(EntryDecodeError::Fault);
                }
                // SAFETY: transfer.kernel is valid for transfer.total bytes and does not alias user pages.
                unsafe {
                    let kptr = transfer
                        .kernel
                        .as_ptr()
                        .add(transfer.completed.raw() as usize);
                    core::ptr::copy_nonoverlapping(kptr, &mut page.data[page_offset], chunk_len);
                }
            }
        }
        transfer.completed = GuestLen::new(transfer.completed.raw() + chunk_len as u64);
        let new_remaining = transfer.total.raw() - transfer.completed.raw();
        Ok(CopyProgress {
            completed: GuestLen::new(chunk_len as u64),
            remaining: GuestLen::new(new_remaining),
        })
    }
}
