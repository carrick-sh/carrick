use super::*;

#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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

#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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

#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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

#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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

#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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
        if let Some(open) = crate::kernel::FileDescription::inspect(&open_file.description) {
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
    let out = match crate::dispatch::copyout::prepare(
        cx.kernel,
        cx.memory,
        [Some(crate::dispatch::copyout::UserSlot::new(ctxp.0, 8))],
    ) {
        Ok(out) => out,
        Err(refusal) => return Ok(refusal.into_outcome()),
    };
    let raw = this.captured_mm().allocate_legacy_aio_context();
    let ctx_id = LegacyAioContextId::allocated_from(raw);
    this.captured_mm()
        .write_legacy_aio_contexts()
        .insert(ctx_id, std::collections::VecDeque::new());
    if out.commit([&ctx_id.get().to_le_bytes()]).is_err() {
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
        let iocb = match crate::dispatch::fs::legacy_aio::LegacyAioIocb::read(
            &*cx.memory,
            GuestPtr(iocb_addr),
        ) {
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
    if crate::dispatch::fs::legacy_aio::LegacyAioIocb::read(&*cx.memory, iocb).is_err()
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
    let mm = this.captured_mm();
    let mut contexts = mm.write_legacy_aio_contexts();
    let Some(completions) = contexts.get_mut(&ctx) else {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    };
    let available = completions
        .len()
        .min(usize::try_from(range.max).unwrap_or(usize::MAX));
    // Unlike a stream read, io_getevents has a minimum result count. Copy
    // through bounded permits without shortening a ready result to one window.
    // The queue stays intact until every copy finishes: refusal after an earlier
    // window can redispatch safely because no completion has been consumed.
    let mut copied = 0usize;
    let mut effect = None;
    while copied < available {
        let Some(address) = copied
            .checked_mul(32)
            .and_then(|offset| u64::try_from(offset).ok())
            .and_then(|offset| events.0.checked_add(offset))
        else {
            break;
        };
        let out = match crate::dispatch::copyout::prepare_array(
            cx.kernel,
            cx.memory,
            carrick_guest_mem::GuestVa::new(address),
            available - copied,
            32,
        ) {
            Ok(out) => out,
            Err(refusal) => return Ok(refusal.into_outcome()),
        };
        let count = out.records();
        if count == 0 {
            break;
        }
        let mut bytes = Vec::with_capacity(count * 32);
        for event in completions.range(copied..copied + count) {
            bytes.extend_from_slice(event.abi_bytes());
        }
        let (result, next_effect) = out.commit_retaining(&bytes);
        effect = effect.or(next_effect);
        if let Err(fault) = result {
            return Ok(fault.outcome());
        }
        copied += count;
    }
    if available != 0 && copied == 0 {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    completions.drain(..copied);
    drop(effect);
    Ok(DispatchOutcome::returned_len_or_errno(copied))
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

#[cfg(test)]
mod s1_tests {
    use super::*;
    use crate::dispatch::copyout::owner_fixture::OwnerRefusingMemory;

    #[test]
    fn s1_aio_large_output_preserves_minimum_and_refused_window() {
        for refuse_second in [false, true] {
            let mut dispatcher = SyscallDispatcher::new();
            let context = dispatcher.capture_one_task_context().unwrap();
            let mm = context.shared().mm();
            let raw = mm.allocate_legacy_aio_context();
            let id = LegacyAioContextId::allocated_from(raw);
            let event = crate::linux_abi::LinuxIoEvent {
                data: 711,
                obj: 1,
                result: 8,
                result2: 0,
            };
            mm.write_legacy_aio_contexts()
                .insert(id, std::iter::repeat_n(event, 130).collect());
            let mut memory = OwnerRefusingMemory::new(0x1000, 0x2000, 0xa5);
            let request = SyscallRequest::new(4, SyscallArgs::from([raw, 130, 130, 0x1000, 0, 0]));
            if refuse_second {
                let wait = memory.refuse_after_prepares(1);
                assert_eq!(
                    dispatcher
                        .dispatch(&context, request, &mut memory, &CompatReporter::default())
                        .unwrap(),
                    DispatchOutcome::OwnerMemoryWait { wait, committed: 0 }
                );
                assert_eq!(mm.write_legacy_aio_contexts().get(&id).unwrap().len(), 130);
                assert_eq!(memory.inner.read_bytes(0x2000, 32).unwrap(), [0xa5; 32]);
            }
            assert_eq!(
                dispatcher
                    .dispatch(&context, request, &mut memory, &CompatReporter::default())
                    .unwrap(),
                DispatchOutcome::Returned { value: 130 }
            );
            assert_eq!(memory.prepares, if refuse_second { 4 } else { 2 });
            for index in 0..130 {
                assert_eq!(
                    memory.inner.read_bytes(0x1000 + index * 32, 32).unwrap(),
                    event.abi_bytes()
                );
            }
            assert!(mm.write_legacy_aio_contexts().get(&id).unwrap().is_empty());
        }
    }

    #[test]
    fn s1_aio_copyout_refusal_preserves_completion() {
        let mut dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let mm = context.shared().mm();
        let raw = mm.allocate_legacy_aio_context();
        let id = LegacyAioContextId::allocated_from(raw);
        let event = crate::linux_abi::LinuxIoEvent {
            data: 711,
            obj: 1,
            result: 8,
            result2: 0,
        };
        mm.write_legacy_aio_contexts()
            .insert(id, [event].into_iter().collect());
        let mut memory = OwnerRefusingMemory::new(0x1000, 0x1000, 0xa5);
        let wait = memory.refuse_next();
        let request = SyscallRequest::new(4, SyscallArgs::from([raw, 1, 1, 0x1000, 0, 0]));
        assert_eq!(
            dispatcher
                .dispatch(&context, request, &mut memory, &CompatReporter::default())
                .unwrap(),
            DispatchOutcome::OwnerMemoryWait { wait, committed: 0 }
        );
        assert_eq!(mm.write_legacy_aio_contexts().get(&id).unwrap().len(), 1);
        assert_eq!(
            dispatcher
                .dispatch(&context, request, &mut memory, &CompatReporter::default())
                .unwrap(),
            DispatchOutcome::Returned { value: 1 }
        );
        assert_eq!(
            memory.inner.read_bytes(0x1000, 32).unwrap(),
            event.abi_bytes()
        );
        assert!(mm.write_legacy_aio_contexts().get(&id).unwrap().is_empty());
    }
}
