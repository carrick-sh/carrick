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
}

impl LegacyAioIocb {
    const WIRE_SIZE: usize = 64;
    const OPCODE_OFFSET: usize = 16;
    const FD_OFFSET: usize = 20;

    fn read(memory: &impl GuestMemory, address: GuestPtr) -> Result<Self, LinuxErrno> {
        if address.0 == 0 {
            return Err(LINUX_EFAULT);
        }
        let bytes = memory
            .read_bytes(address.0, Self::WIRE_SIZE)
            .map_err(|_| LINUX_EFAULT)?;
        let opcode_raw =
            u16::from_le_bytes([bytes[Self::OPCODE_OFFSET], bytes[Self::OPCODE_OFFSET + 1]]);
        let fd_raw = i32::from_le_bytes([
            bytes[Self::FD_OFFSET],
            bytes[Self::FD_OFFSET + 1],
            bytes[Self::FD_OFFSET + 2],
            bytes[Self::FD_OFFSET + 3],
        ]);
        Ok(Self {
            opcode: LegacyAioOpcode::from_wire(opcode_raw)?,
            fd: Fd(fd_raw),
        })
    }
}

fn legacy_aio_context_exists(this: &SyscallDispatcher, ctx: LegacyAioContextId) -> bool {
    this.io.legacy_aio_contexts.read().contains(&ctx)
}

fn legacy_aio_iocb_errno(this: &SyscallDispatcher, iocb: LegacyAioIocb) -> Option<LinuxErrno> {
    let open_file = this.open_file(iocb.fd.0)?;
    let open = open_file.description.read();
    let access = open.status_flags() & LINUX_O_ACCMODE;
    if iocb.opcode.needs_readable_fd() && access == LINUX_O_WRONLY {
        return Some(LINUX_EBADF);
    }
    if iocb.opcode.needs_writable_fd() {
        match &*open {
            OpenDescription::File {
                writable: false, ..
            }
            | OpenDescription::HostFile {
                writable: false, ..
            } => return Some(LINUX_EBADF),
            _ if access == LINUX_O_RDONLY => return Some(LINUX_EBADF),
            _ => {}
        }
    }
    None
}

pub(super) fn io_setup<M: GuestMemory>(
    this: &SyscallDispatcher,
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
    let raw = this
        .io
        .next_legacy_aio_context
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ctx_id = LegacyAioContextId::allocated_from(raw);
    this.io.legacy_aio_contexts.write().insert(ctx_id);
    if cx
        .memory
        .write_bytes(ctxp.0, &ctx_id.get().to_le_bytes())
        .is_err()
    {
        this.io.legacy_aio_contexts.write().remove(&ctx_id);
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    Ok(DispatchOutcome::Returned { value: 0 })
}

pub(super) fn io_destroy(
    this: &SyscallDispatcher,
    raw_ctx: u64,
) -> Result<DispatchOutcome, DispatchError> {
    let Some(ctx) = LegacyAioContextId::from_guest(raw_ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    if this.io.legacy_aio_contexts.write().remove(&ctx) {
        Ok(DispatchOutcome::Returned { value: 0 })
    } else {
        Ok(DispatchOutcome::errno(LINUX_EINVAL))
    }
}

pub(super) fn io_submit<M: GuestMemory>(
    this: &SyscallDispatcher,
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
    }
    Ok(DispatchOutcome::Returned {
        value: count.get() as i64,
    })
}

pub(super) fn io_cancel<M: GuestMemory>(
    this: &SyscallDispatcher,
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

pub(super) fn io_getevents<M: GuestMemory>(
    this: &SyscallDispatcher,
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
    Ok(DispatchOutcome::Returned { value: 0 })
}
