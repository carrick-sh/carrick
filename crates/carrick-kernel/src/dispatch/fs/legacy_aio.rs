use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacyAioEventCount;

impl LegacyAioEventCount {
    const MAX: u64 = 65_536;

    fn for_setup(raw: u64) -> Result<Self, LinuxErrno> {
        if raw == 0 || (raw as i64) < 0 || raw > i32::MAX as u64 {
            return Err(LINUX_EINVAL);
        }
        if raw > Self::MAX {
            return Err(LINUX_EAGAIN);
        }
        Ok(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacyAioSubmitCount(u64);

impl LegacyAioSubmitCount {
    fn from_guest(raw: u64) -> Result<Self, LinuxErrno> {
        if (raw as i64) < 0 {
            return Err(LINUX_EINVAL);
        }
        Ok(Self(raw))
    }

    fn is_zero(self) -> bool {
        self.0 == 0
    }

    fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacyAioGetEventsRange {
    max: u64,
}

impl LegacyAioGetEventsRange {
    fn from_guest(min_raw: u64, max_raw: u64) -> Result<Self, LinuxErrno> {
        let min_signed = min_raw as i64;
        let max_signed = max_raw as i64;
        if min_signed < 0 || max_signed < 0 || min_raw > max_raw {
            return Err(LINUX_EINVAL);
        }
        Ok(Self { max: max_raw })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyAioOpcode {
    Pread,
    Pwrite,
    Preadv,
    Pwritev,
}

impl LegacyAioOpcode {
    const PREAD_RAW: u16 = 0;
    const PWRITE_RAW: u16 = 1;
    const PREADV_RAW: u16 = 7;
    const PWRITEV_RAW: u16 = 8;

    fn from_wire(raw: u16) -> Result<Self, LinuxErrno> {
        match raw {
            Self::PREAD_RAW => Ok(Self::Pread),
            Self::PWRITE_RAW => Ok(Self::Pwrite),
            Self::PREADV_RAW => Ok(Self::Preadv),
            Self::PWRITEV_RAW => Ok(Self::Pwritev),
            _ => Err(LINUX_EINVAL),
        }
    }

    fn needs_readable_fd(self) -> bool {
        matches!(self, Self::Pread | Self::Preadv)
    }

    fn needs_writable_fd(self) -> bool {
        matches!(self, Self::Pwrite | Self::Pwritev)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacyAioIocb {
    opcode: LegacyAioOpcode,
    fd: Fd,
    address: u64,
    data: u64,
    rw_flags: u32,
}

impl LegacyAioIocb {
    fn read(memory: &impl CurrentMmMemory, address: GuestPtr) -> Result<Self, LinuxErrno> {
        if address.0 == 0 {
            return Err(LINUX_EFAULT);
        }
        let iocb: LinuxIocb = memory.read_struct(address.0).map_err(|_| LINUX_EFAULT)?;
        Ok(Self {
            opcode: LegacyAioOpcode::from_wire(iocb.aio_lio_opcode)?,
            fd: Fd(iocb.aio_fildes as i32),
            address: address.0,
            data: iocb.aio_data,
            rw_flags: iocb.aio_reserved1,
        })
    }
}

fn legacy_aio_context_exists(this: &FsView<'_>, ctx: LegacyAioContextId) -> bool {
    this.captured_mm()
        .read_legacy_aio_contexts()
        .contains_key(&ctx)
}

fn legacy_aio_immediate_completion(
    this: &FsView<'_>,
    iocb: LegacyAioIocb,
) -> Option<crate::linux_abi::LinuxIoEvent> {
    if iocb.opcode != LegacyAioOpcode::Pread
        || !crate::linux_abi::LinuxRwfFlags::from_bits_retain(u64::from(iocb.rw_flags))
            .contains(crate::linux_abi::LinuxRwfFlags::NOWAIT)
    {
        return None;
    }
    let open_file = this.open_file(iocb.fd.0)?;
    if !open_file.description().is_empty_pipe_reader_with_writer() {
        return None;
    }
    Some(crate::linux_abi::LinuxIoEvent {
        data: iocb.data,
        obj: iocb.address,
        result: -i64::from(LINUX_EAGAIN.get()),
        result2: 0,
    })
}

fn legacy_aio_iocb_errno(this: &FsView<'_>, iocb: LegacyAioIocb) -> Option<LinuxErrno> {
    let open_file = this.open_file(iocb.fd.0)?;
    let access = open_file.description.common().status_flags() & LINUX_O_ACCMODE;
    if iocb.opcode.needs_readable_fd() && access == LINUX_O_WRONLY {
        return Some(LINUX_EBADF);
    }
    if iocb.opcode.needs_writable_fd() {
        if access == LINUX_O_RDONLY {
            return Some(LINUX_EBADF);
        }
        if let Some(open) = open_file.description.read() {
            match &*open {
                OpenDescription::File {
                    writable: false, ..
                }
                | OpenDescription::HostFile {
                    writable: false, ..
                } => return Some(LINUX_EBADF),
                _ => {}
            }
        }
    }
    None
}

pub(super) fn io_setup<M: CurrentMmMemory>(
    this: &FsView<'_>,
    cx: &mut SyscallCtx<M>,
    nr_events: u64,
    ctxp: GuestPtr,
) -> Result<DispatchOutcome, DispatchError> {
    if let Err(errno) = LegacyAioEventCount::for_setup(nr_events) {
        return Ok(DispatchOutcome::errno(errno));
    }
    if ctxp.0 == 0 {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    let current = match read_u64(&*cx.memory, ctxp.0) {
        Ok(value) => value,
        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
    };
    if current != 0 {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    let raw = this.captured_mm().allocate_legacy_aio_context();
    let ctx_id = LegacyAioContextId::allocated_from(raw);
    this.captured_mm()
        .write_legacy_aio_contexts()
        .insert(ctx_id, std::collections::VecDeque::new());
    if cx
        .memory
        .write_bytes(ctxp.0, &ctx_id.get().to_le_bytes())
        .is_err()
    {
        this.captured_mm()
            .write_legacy_aio_contexts()
            .remove(&ctx_id);
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    Ok(DispatchOutcome::Returned { value: 0 })
}

pub(super) fn io_destroy(
    this: &FsView<'_>,
    raw_ctx: u64,
) -> Result<DispatchOutcome, DispatchError> {
    let Some(ctx) = LegacyAioContextId::from_guest(raw_ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    if this
        .captured_mm()
        .write_legacy_aio_contexts()
        .remove(&ctx)
        .is_some()
    {
        Ok(DispatchOutcome::Returned { value: 0 })
    } else {
        Ok(DispatchOutcome::errno(LINUX_EINVAL))
    }
}

pub(super) fn io_submit<M: CurrentMmMemory>(
    this: &FsView<'_>,
    cx: &mut SyscallCtx<M>,
    raw_ctx: u64,
    raw_count: u64,
    iocbpp: GuestPtr,
) -> Result<DispatchOutcome, DispatchError> {
    let Some(ctx) = LegacyAioContextId::from_guest(raw_ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    if !legacy_aio_context_exists(this, ctx) {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    let count = match LegacyAioSubmitCount::from_guest(raw_count) {
        Ok(value) => value,
        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
    };
    if count.is_zero() {
        return Ok(DispatchOutcome::Returned { value: 0 });
    }
    if iocbpp.0 == 0 {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    let mut immediate = Vec::new();
    for idx in 0..count.get() {
        let Some(slot_addr) = iocbpp.0.checked_add(idx.saturating_mul(8)) else {
            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
        };
        let iocb_addr = match read_u64(&*cx.memory, slot_addr) {
            Ok(value) => value,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        let iocb = match LegacyAioIocb::read(&*cx.memory, GuestPtr(iocb_addr)) {
            Ok(value) => value,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        if this.open_file(iocb.fd.0).is_none() {
            return Ok(DispatchOutcome::errno(LINUX_EBADF));
        }
        if let Some(errno) = legacy_aio_iocb_errno(this, iocb) {
            return Ok(DispatchOutcome::errno(errno));
        }
        if let Some(event) = legacy_aio_immediate_completion(this, iocb) {
            immediate.push(event);
        }
    }
    if !immediate.is_empty() {
        let mm = this.captured_mm();
        let mut contexts = mm.write_legacy_aio_contexts();
        let Some(completions) = contexts.get_mut(&ctx) else {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        };
        completions.extend(immediate);
    }
    Ok(DispatchOutcome::returned_u64_or_errno(count.get()))
}

pub(super) fn io_cancel<M: CurrentMmMemory>(
    this: &FsView<'_>,
    cx: &mut SyscallCtx<M>,
    raw_ctx: u64,
    iocb: GuestPtr,
    result: GuestPtr,
) -> Result<DispatchOutcome, DispatchError> {
    if LegacyAioIocb::read(&*cx.memory, iocb).is_err()
        || result.0 == 0
        || cx.memory.read_bytes(result.0, 32).is_err()
    {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    let Some(ctx) = LegacyAioContextId::from_guest(raw_ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    if !legacy_aio_context_exists(this, ctx) {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    Ok(DispatchOutcome::errno(LINUX_EINVAL))
}

pub(super) fn io_getevents<M: CurrentMmMemory>(
    this: &FsView<'_>,
    cx: &mut SyscallCtx<M>,
    raw_ctx: u64,
    min_nr: u64,
    nr: u64,
    events: GuestPtr,
) -> Result<DispatchOutcome, DispatchError> {
    let Some(ctx) = LegacyAioContextId::from_guest(raw_ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    if !legacy_aio_context_exists(this, ctx) {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    let range = match LegacyAioGetEventsRange::from_guest(min_nr, nr) {
        Ok(value) => value,
        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
    };
    if range.max > 0 && (events.0 == 0 || cx.memory.read_bytes(events.0, 32).is_err()) {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    let mm = this.captured_mm();
    let mut contexts = mm.write_legacy_aio_contexts();
    let Some(completions) = contexts.get_mut(&ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    let available = completions.len().min(range.max as usize);
    for (index, event) in completions.iter().take(available).enumerate() {
        let Some(address) = events.0.checked_add((index as u64).saturating_mul(32)) else {
            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
        };
        if write_kernel_struct_raw(cx.memory, address, event).is_err() {
            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
        }
    }
    completions.drain(..available);
    Ok(DispatchOutcome::returned_len_or_errno(available))
}

impl<'a> FsView<'a> {
    define_syscall! {
        fn io_setup(this, cx, nr_events: u64, ctxp: GuestPtr) {
            io_setup(this, cx, nr_events, ctxp)
        }

        fn io_destroy(this, _cx, raw_ctx: u64) {
            io_destroy(this, raw_ctx)
        }

        fn io_submit(this, cx, raw_ctx: u64, raw_count: u64, iocbpp: GuestPtr) {
            io_submit(this, cx, raw_ctx, raw_count, iocbpp)
        }

        fn io_cancel(this, cx, raw_ctx: u64, iocb: GuestPtr, result: GuestPtr) {
            io_cancel(this, cx, raw_ctx, iocb, result)
        }

        fn io_getevents(this, cx, raw_ctx: u64, min_nr: u64, nr: u64, events: GuestPtr, _timeout: GuestPtr) {
            io_getevents(this, cx, raw_ctx, min_nr, nr, events)
        }
    }
}
