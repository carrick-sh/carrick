//! VM-free bindings for kernel.el1.ipc-continuation: the host completing
//! operations EL1 owns, over real shared records and a guest-memory model.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::dispatch::LinearMemory;
use carrick_el1_abi::ipc::fd::{AccessMode, Description, Fd, StatusFlags, TableId};
use carrick_el1_abi::ipc::{
    End, Extent, IPC_POOL_ALIGN, IpcBacking, IpcDirectory, IpcPipeStorage, IpcTaskKey, IpcUserVa,
    WriteProgress,
};
use carrick_guest_mem::GuestMemory;
use std::alloc::Layout;
use std::cell::{Cell, RefCell};

const MM: IpcMmKey = IpcMmKey(7);
const BUF: u64 = 0x10_0000;

#[test]
fn serial_host_el1_ipc_finish_releases_host_forwarding_token() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Released(Arc<AtomicUsize>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    assert!(ZoneHostServices::new(context.kernel()).is_err());
    assert!(
        context.kernel().existing_ipc().is_none(),
        "owner lookup must not allocate"
    );
    let owner = context.kernel().ipc().unwrap();
    let released = Arc::new(AtomicUsize::new(0));
    let backing = owner
        .retain_host_resource(Box::new(Released(Arc::clone(&released))))
        .unwrap();
    let region = owner.region();
    let pin = region
        .fd(HostIpcWait)
        .create_pinned(Description::new(
            IpcBacking::Host(backing).encode(),
            AccessMode::ReadWrite,
            StatusFlags::default(),
        ))
        .unwrap();
    let token = region
        .begin_operation(IpcOperation {
            pin: pin.into_raw(),
            ..IpcOperation::EMPTY
        })
        .unwrap();
    let raw = token.into_raw();
    let foreign_dispatcher = crate::dispatch::SyscallDispatcher::new();
    let foreign_context = foreign_dispatcher.capture_one_task_context().unwrap();
    let foreign_owner = foreign_context.kernel().ipc().unwrap();
    let foreign_released = Arc::new(AtomicUsize::new(0));
    let foreign_backing = foreign_owner
        .retain_host_resource(Box::new(Released(Arc::clone(&foreign_released))))
        .unwrap();
    assert_eq!(
        backing.get(),
        foreign_backing.get(),
        "control uses colliding kernel-local token numbers"
    );
    assert!(matches!(
        finish(
            &region,
            IpcOpToken::from_raw(raw),
            &ZoneHostServices::for_dispatcher(&foreign_dispatcher).unwrap()
        ),
        Err(IpcError::BadRegion)
    ));
    assert!(
        region.operation(&IpcOpToken::from_raw(raw)).is_ok(),
        "foreign owner must not consume the operation"
    );
    let service = ZoneHostServices::for_dispatcher(&dispatcher).unwrap();
    finish(&region, IpcOpToken::from_raw(raw), &service).unwrap();
    assert_eq!(
        released.load(Ordering::Relaxed),
        1,
        "final handback must retire its host token"
    );
    assert!(matches!(
        finish(&region, IpcOpToken::from_raw(raw), &service),
        Err(IpcError::Stale)
    ));
    assert_eq!(released.load(Ordering::Relaxed), 1);
    assert_eq!(foreign_released.load(Ordering::Relaxed), 0);
    foreign_owner
        .release(IpcBacking::Host(foreign_backing).encode())
        .unwrap();
    assert_eq!(foreign_released.load(Ordering::Relaxed), 1);
}

#[test]
fn serial_host_el1_ipc_runtime_backing_retains_the_kernel_authority() {
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let owner = context.kernel().ipc().unwrap();
    let object = owner
        .create_eventfd(7, carrick_el1_abi::ipc::pipe::EventMode::Counter)
        .unwrap();
    let backing = host_window_backing(&dispatcher).expect("runtime IPC backing");
    assert_eq!(backing.directory_ptr(), owner.directory_ptr().cast());
    assert_eq!(backing.pool_ptr(), owner.pool_ptr());
    assert_eq!(backing.directory_len(), owner.directory_len());
    assert_eq!(backing.pool_len(), owner.pool_len());
    let weak = std::sync::Arc::downgrade(&owner);
    drop(owner);
    drop(context);
    drop(dispatcher);
    let retained = weak.upgrade().expect("mapping retains IPC authority");
    let region = retained.region();
    let mut guard = region.lock(object, &HostIpcWait).unwrap();
    assert_eq!(guard.eventfd().unwrap().try_read().result, Ok(7));
    drop(guard);
    retained
        .release(IpcBacking::EventFd { object }.encode())
        .unwrap();
    drop(retained);
    drop(backing);
    assert!(weak.upgrade().is_none());
}

struct World {
    region: &'static IpcRegion<'static>,
    next: Cell<u64>,
    table: TableId,
}

#[derive(Default)]
struct Wakes(RefCell<Vec<(IpcObjectHandle, WakeSet)>>);
impl IpcHostServices for Wakes {
    fn validate_region(&self, _region: &IpcRegion<'_>) -> Result<(), IpcError> {
        Ok(())
    }
    fn release_host(
        &self,
        _token: carrick_el1_abi::ipc::HostResourceToken,
    ) -> Result<(), IpcError> {
        Err(IpcError::Corrupt)
    }
    fn wake(&self, wake: carrick_el1_abi::ipc::IpcWake) {
        self.0.borrow_mut().push((
            wake.object,
            WakeSet {
                readers: wake.readers,
                writers: wake.writers,
            },
        ));
    }
}

fn world() -> World {
    let dir = unsafe {
        std::alloc::alloc_zeroed(
            Layout::from_size_align(carrick_el1_abi::ipc::IPC_DIRECTORY_BYTES, 4096).unwrap(),
        )
        .cast::<IpcDirectory>()
    };
    let pool_len = 4 << 20;
    let pool =
        unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
    let region = unsafe {
        IpcRegion::initialize(
            dir,
            carrick_el1_abi::ipc::IPC_DIRECTORY_BYTES,
            pool,
            pool_len,
            9,
        )
    }
    .unwrap();
    let region: &'static IpcRegion<'static> = Box::leak(Box::new(region));
    let w = World {
        region,
        next: Cell::new(0),
        table: TableId::from_raw(Default::default()),
    };
    let mut extent = Extent {
        token: carrick_el1_abi::ipc::ipc_descriptor_area(pool_len as u64).start,
        capacity: 64,
    };
    let table = region
        .fd(HostIpcWait)
        .create_table(1024, &mut extent)
        .unwrap();
    World { table, ..w }
}

impl World {
    fn bump(&self, bytes: u64) -> u64 {
        let at = self.next.get();
        self.next.set((at + bytes).next_multiple_of(IPC_POOL_ALIGN));
        at
    }
    fn pipe(&self) -> (Fd, Fd, IpcObjectHandle) {
        let mut retired = None;
        let object = self
            .region
            .create_pipe(65536, &mut retired, &HostIpcWait)
            .unwrap();
        // The ring the host's first write provides.
        let mut storage = IpcPipeStorage {
            offset: self.bump(65536 + 16 * 8),
            ring_bytes: 65536,
            pages: 16,
        };
        let mut guard = self.region.lock(object, &HostIpcWait).unwrap();
        assert_eq!(guard.provide_pipe_storage(&mut storage), Ok(true));
        drop(guard);
        let fd = self.region.fd(HostIpcWait);
        let open = |end, access| {
            fd.open(
                self.table,
                Fd(0),
                Description::new(
                    IpcBacking::Pipe { object, end }.encode(),
                    access,
                    StatusFlags::default(),
                ),
                false,
            )
            .unwrap()
        };
        (
            open(End::Reader, AccessMode::ReadOnly),
            open(End::Writer, AccessMode::WriteOnly),
            object,
        )
    }
    /// An operation as the EL1 adapter records it at admission.
    fn operation(&self, fd: Fd, kind: IpcOpKind, len: u64, nr: u32) -> IpcOpToken {
        let (pin, desc) = self.region.fd(HostIpcWait).pin(self.table, fd).unwrap();
        let Some(IpcBacking::Pipe { object, .. }) = IpcBacking::decode(desc.backing) else {
            panic!("pipe");
        };
        let op = IpcOperation {
            kind,
            pin: pin.into_raw(),
            object: object.to_raw(),
            task: IpcTaskKey(1),
            mm: MM,
            buf: IpcUserVa(BUF),
            progress: WriteProgress::new(len),
            orig_x0: fd.0 as u64,
            nr,
            ..IpcOperation::EMPTY
        };
        self.region.begin_operation(op).unwrap()
    }
    fn hand_back(&self, token: &IpcOpToken, what: IpcHandback, written: u64, result: i64) {
        let mut op = self.region.operation(token).unwrap();
        op.handback = what;
        op.progress.written = written;
        op.result = result;
        self.region.update_operation(token, op).unwrap();
    }
    fn holds(&self, fd: Fd) -> usize {
        self.region
            .fd(HostIpcWait)
            .refcount(self.table, fd)
            .unwrap()
    }
    fn unread(&self, object: IpcObjectHandle) -> usize {
        let mut g = self.region.lock(object, &HostIpcWait).unwrap();
        g.pipe().unwrap().unread_bytes()
    }
}

fn memory(bytes: &[u8]) -> LinearMemory {
    let mut m = LinearMemory::new(BUF, vec![0; 1 << 20]);
    m.write_bytes(BUF, bytes).unwrap();
    m
}

#[test]
fn el1_ipc_zero_progress_interruption_restarts_or_returns_eintr() {
    let w = world();
    let (r, _wfd, _) = w.pipe();
    for (cause, expected) in [
        (
            IpcCause::Signal { restart: true },
            IpcHostOutcome::Restart {
                x0: r.0 as u64,
                nr: 63,
                timeout_ms: None,
            },
        ),
        (
            IpcCause::Signal { restart: false },
            IpcHostOutcome::Complete {
                result: LINUX_EINTR.guest_retval(),
                sigpipe: false,
            },
        ),
        (
            IpcCause::Control,
            IpcHostOutcome::Restart {
                x0: r.0 as u64,
                nr: 63,
                timeout_ms: None,
            },
        ),
        // read(2) is not among the calls a stop interrupts (man 7 signal):
        // after SIGCONT it continues.
        (
            IpcCause::Stop,
            IpcHostOutcome::Restart {
                x0: r.0 as u64,
                nr: 63,
                timeout_ms: None,
            },
        ),
    ] {
        let token = w.operation(r, IpcOpKind::PipeRead, 16, 63);
        let wakes = Wakes::default();
        assert_eq!(interrupt(w.region, token, cause, &wakes).unwrap(), expected);
        assert!(wakes.0.borrow().is_empty());
    }
    // Every pin was released: only the descriptor's own reference remains.
    let (pin, _) = w.region.fd(HostIpcWait).pin(w.table, r).unwrap();
    assert_eq!(w.region.fd(HostIpcWait).holds(&pin), Ok((1, 1)));
    let _ = w.region.fd(HostIpcWait).unpin(pin);
}

/// A parked zone epoll wait owns no progress: a signal ends it with EINTR
/// even under SA_RESTART (epoll_wait(2) is never restarted), so does a stop
/// followed by SIGCONT with no handler (man 7 signal), a host-kept
/// deadline returns 0 events, a control stop and a host continuation re-run
/// the original call, and each drops its pin.
#[test]
fn el1_epoll_wait_interruption_is_eintr_and_continuation_restarts() {
    let w = world();
    let (r, _wfd, _) = w.pipe();
    let eintr = IpcHostOutcome::Complete {
        result: LINUX_EINTR.guest_retval(),
        sigpipe: false,
    };
    let restart = IpcHostOutcome::Restart {
        x0: r.0 as u64,
        nr: 22,
        timeout_ms: None,
    };
    let timed_out = IpcHostOutcome::Complete {
        result: 0,
        sigpipe: false,
    };
    for (cause, expected) in [
        (IpcCause::Signal { restart: true }, &eintr),
        (IpcCause::Signal { restart: false }, &eintr),
        // A stop then SIGCONT, no handler: EINTR (man 7 signal).
        (IpcCause::Stop, &eintr),
        (IpcCause::Control, &restart),
        (IpcCause::Timeout, &timed_out),
    ] {
        let token = w.operation(r, IpcOpKind::EpollWait, 0, 22);
        let wakes = Wakes::default();
        assert_eq!(
            &interrupt(w.region, token, cause, &wakes).unwrap(),
            expected
        );
    }
    let token = w.operation(r, IpcOpKind::EpollWait, 0, 22);
    w.hand_back(&token, IpcHandback::Continue, 0, 0);
    let wakes = Wakes::default();
    let mut mem = memory(&[0; 16]);
    let outcome = complete_handback(w.region, token, MM, &mut mem, None, &wakes).unwrap();
    assert_eq!(outcome, restart);
    let (pin, _) = w.region.fd(HostIpcWait).pin(w.table, r).unwrap();
    assert_eq!(w.region.fd(HostIpcWait).holds(&pin), Ok((1, 1)));
    let _ = w.region.fd(HostIpcWait).unpin(pin);
}

/// Host services reading a model counter (1 tick = 1 ns) instead of the
/// host's clock.
struct Clocked {
    wakes: Wakes,
    now: u64,
}
impl IpcHostServices for Clocked {
    fn validate_region(&self, region: &IpcRegion<'_>) -> Result<(), IpcError> {
        self.wakes.validate_region(region)
    }
    fn release_host(&self, token: carrick_el1_abi::ipc::HostResourceToken) -> Result<(), IpcError> {
        self.wakes.release_host(token)
    }
    fn wake(&self, wake: carrick_el1_abi::ipc::IpcWake) {
        self.wakes.wake(wake);
    }
    fn counter(&self) -> CounterClock {
        CounterClock {
            now: self.now,
            numer: 1,
            denom: 1,
        }
    }
}

/// A timed epoll wait the host wakes and re-runs never waits longer than
/// its timeout: the re-run gets what is left of the deadline (rounded up to
/// a whole millisecond), so the woken-but-empty wait plus the re-run's full
/// wait end within the timeout plus that rounding, and a wake after the
/// deadline re-runs with 0 (one harvest, then 0 events). Measured on a model
/// monotonic counter, not wall time.
#[test]
fn el1_epoll_timed_wait_host_rerun_waits_only_what_is_left() {
    const MS: u64 = 1_000_000;
    let start = 1_000 * MS;
    let timeout_ms = 100u64;
    let deadline = start + timeout_ms * MS;
    let w = world();
    let (r, _wfd, _) = w.pipe();
    let timed = |w: &World| {
        let token = w.operation(r, IpcOpKind::EpollWait, 0, 22);
        let mut op = w.region.operation(&token).unwrap();
        op.deadline = carrick_el1_abi::ipc::IpcCounterDeadline::at(deadline);
        op.handback = IpcHandback::Continue;
        w.region.update_operation(&token, op).unwrap();
        token
    };
    for woken_at in [
        start + 60 * MS,
        start + 60 * MS + MS / 2,
        start + 99 * MS + 1,
    ] {
        let services = Clocked {
            wakes: Wakes::default(),
            now: woken_at,
        };
        let mut mem = memory(&[0; 16]);
        let outcome =
            complete_handback(w.region, timed(&w), MM, &mut mem, None, &services).unwrap();
        let IpcHostOutcome::Restart {
            timeout_ms: Some(left),
            ..
        } = outcome
        else {
            panic!("a timed wait re-runs with its remaining time: {outcome:?}");
        };
        // The re-run waits `left` from the wake when nothing arrives.
        let expires = woken_at + u64::try_from(left).unwrap() * MS;
        assert!(expires >= deadline, "never before the timeout");
        assert!(
            expires - start <= timeout_ms * MS + MS,
            "total {} ns exceeds the timeout plus rounding",
            expires - start
        );
    }
    for (cause, at) in [
        (None, deadline + 5 * MS),
        (Some(IpcCause::Control), start + 30 * MS),
    ] {
        let services = Clocked {
            wakes: Wakes::default(),
            now: at,
        };
        let outcome = match cause {
            None => {
                let mut mem = memory(&[0; 16]);
                complete_handback(w.region, timed(&w), MM, &mut mem, None, &services).unwrap()
            }
            Some(cause) => interrupt(w.region, timed(&w), cause, &services).unwrap(),
        };
        let expected = if at > deadline { 0 } else { 70 };
        assert_eq!(
            outcome,
            IpcHostOutcome::Restart {
                x0: r.0 as u64,
                nr: 22,
                timeout_ms: Some(expected),
            }
        );
    }
    let (pin, _) = w.region.fd(HostIpcWait).pin(w.table, r).unwrap();
    assert_eq!(
        w.region.fd(HostIpcWait).holds(&pin),
        Ok((1, 1)),
        "every pin dropped"
    );
    let _ = w.region.fd(HostIpcWait).unpin(pin);
}

#[test]
fn el1_ipc_partial_progress_signal_returns_the_count() {
    let w = world();
    let (_r, wfd, _) = w.pipe();
    let token = w.operation(wfd, IpcOpKind::PipeWrite, 100_000, 64);
    w.hand_back(&token, IpcHandback::Continue, 65536, 0);
    let wakes = Wakes::default();
    let mut mem = memory(&[1; 100_000]);
    let outcome = complete_handback(
        w.region,
        token,
        MM,
        &mut mem,
        Some(IpcCause::Signal { restart: true }),
        &wakes,
    )
    .unwrap();
    assert_eq!(
        outcome,
        IpcHostOutcome::Complete {
            result: 65536,
            sigpipe: false
        },
        "SA_RESTART never restarts a call with progress"
    );
}

#[test]
fn el1_ipc_sigpipe_after_partial_write_completes_exactly_once() {
    let w = world();
    let (_r, wfd, _) = w.pipe();
    let token = w.operation(wfd, IpcOpKind::PipeWrite, 100_000, 64);
    let raw = token.into_raw();
    let token = IpcOpToken::from_raw(raw);
    let raw = raw.pack();
    w.hand_back(&token, IpcHandback::Sigpipe, 65536, 65536);
    let wakes = Wakes::default();
    let (token, op) = take_handback(w.region, raw).unwrap();
    assert_eq!((op.orig_x0, op.nr), (wfd.0 as u64, 64));
    let mut mem = memory(&[]);
    assert_eq!(
        complete_handback(w.region, token, MM, &mut mem, None, &wakes).unwrap(),
        IpcHostOutcome::Complete {
            result: 65536,
            sigpipe: true
        }
    );
    assert_eq!(
        take_handback(w.region, raw).err(),
        Some(IpcError::Stale),
        "completed exactly once"
    );
    assert_eq!(w.holds(wfd), 1, "no leaked pin");
}

#[test]
fn el1_ipc_continue_resumes_a_write_without_replay() {
    let w = world();
    let (r, wfd, object) = w.pipe();
    let source: Vec<u8> = (0..70_000u32).map(|n| (n % 251) as u8).collect();
    let token = w.operation(wfd, IpcOpKind::PipeWrite, source.len() as u64, 64);
    // EL1 wrote the first 1000 bytes, then handed the continuation back.
    {
        let mut g = w.region.lock(object, &HostIpcWait).unwrap();
        g.pipe().unwrap().try_write(&source[..1000]);
    }
    w.hand_back(&token, IpcHandback::Continue, 1000, 0);
    let wakes = Wakes::default();
    let mut mem = memory(&source);
    let outcome = complete_handback(w.region, token, MM, &mut mem, None, &wakes).unwrap();
    let IpcHostOutcome::Blocked {
        token,
        lane,
        x0,
        nr,
        ..
    } = outcome
    else {
        panic!("a full pipe blocks: {outcome:?}");
    };
    assert_eq!((lane, x0, nr), (WaitFor::Writable, wfd.0 as u64, 64));
    let progress = w.region.operation(&token).unwrap().progress.written;
    assert_eq!(
        w.unread(object) as u64,
        progress,
        "the record holds the exact offset"
    );
    assert!(wakes.0.borrow().iter().any(|(_, l)| l.readers));
    // The reader drains; the continuation completes from its offset.
    let mut out = vec![0; progress as usize];
    {
        let mut g = w.region.lock(object, &HostIpcWait).unwrap();
        g.pipe().unwrap().try_read(&mut out);
    }
    let outcome = complete_handback(w.region, token, MM, &mut mem, None, &wakes).unwrap();
    assert_eq!(
        outcome,
        IpcHostOutcome::Complete {
            result: source.len() as i64,
            sigpipe: false
        }
    );
    let mut rest = vec![0; source.len()];
    let n = {
        let mut g = w.region.lock(object, &HostIpcWait).unwrap();
        g.pipe().unwrap().try_read(&mut rest).result.unwrap()
    };
    out.extend_from_slice(&rest[..n]);
    assert_eq!(out, source, "every byte once, in order");
    assert_eq!(w.holds(wfd), 1);
    let _ = r;
}

#[test]
fn el1_ipc_continue_rejects_a_stale_address_space_before_copying() {
    let w = world();
    let (r, _wfd, object) = w.pipe();
    {
        let mut g = w.region.lock(object, &HostIpcWait).unwrap();
        g.pipe().unwrap().try_write(b"secret");
    }
    let token = w.operation(r, IpcOpKind::PipeRead, 16, 63);
    let raw = token.into_raw();
    let token = IpcOpToken::from_raw(raw);
    let raw = raw.pack();
    w.hand_back(&token, IpcHandback::Continue, 0, 0);
    let mut mem = memory(&[]);
    assert_eq!(
        complete_handback(
            w.region,
            token,
            IpcMmKey(8),
            &mut mem,
            None,
            &Wakes::default()
        )
        .err(),
        Some(IpcError::Stale)
    );
    assert_eq!(w.unread(object), 6, "no byte consumed for another mm");
    assert_eq!(mem.read_bytes(BUF, 6).unwrap(), vec![0; 6]);
    // The owner still holds the operation and can finish it.
    let (token, _) = take_handback(w.region, raw).unwrap();
    let outcome =
        complete_handback(w.region, token, MM, &mut mem, None, &Wakes::default()).unwrap();
    assert_eq!(
        outcome,
        IpcHostOutcome::Complete {
            result: 6,
            sigpipe: false
        }
    );
    assert_eq!(mem.read_bytes(BUF, 6).unwrap(), b"secret");
}

#[test]
fn el1_ipc_exit_cancellation_releases_the_last_pin_and_wakes_the_peer() {
    let w = world();
    let (r, wfd, object) = w.pipe();
    let token = w.operation(r, IpcOpKind::PipeRead, 16, 63);
    // The reader's descriptor closes while its read is parked (exit).
    assert_eq!(w.region.fd(HostIpcWait).close(w.table, r), Ok(None));
    let wakes = Wakes::default();
    assert_eq!(
        interrupt(w.region, token, IpcCause::Control, &wakes).unwrap(),
        IpcHostOutcome::Restart {
            x0: r.0 as u64,
            nr: 63,
            timeout_ms: None,
        }
    );
    // Final release: the writer lane learns the reader is gone (EPIPE).
    assert_eq!(
        wakes.0.borrow().as_slice(),
        &[(
            object,
            WakeSet {
                readers: false,
                writers: true
            }
        )]
    );
    let mut g = w.region.lock(object, &HostIpcWait).unwrap();
    assert_eq!(g.pipe().unwrap().references(End::Reader), 0);
    drop(g);
    let _ = wfd;
}

#[test]
fn serial_host_el1_ipc_guest_wake_delivered_at_its_kernel_boundary() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let other = crate::dispatch::SyscallDispatcher::new();
    let other_context = other.capture_one_task_context().unwrap();
    let owner = context.kernel().ipc().unwrap();
    let object = owner
        .create_eventfd(0, carrick_el1_abi::ipc::EventMode::Counter)
        .unwrap();
    let queue = owner.wait_queue(object);
    let wakes = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&wakes);
    let enrollment = queue.enroll_callback(move |_| {
        seen.fetch_add(1, Ordering::Relaxed);
    });
    // The guest updates the shared core and publishes under its object lock;
    // it cannot call the host subscription registry directly.
    {
        let region = owner.region();
        let mut guard = region.lock(object, &HostIpcWait).unwrap();
        let step = guard.eventfd().unwrap().try_write(7);
        assert!(guard.publish(step.wake).host_owed);
    }
    assert_eq!(wakes.load(Ordering::Relaxed), 0);
    deliver_owed_host_wakes(other_context.kernel());
    assert_eq!(
        wakes.load(Ordering::Relaxed),
        0,
        "another kernel cannot consume this wake"
    );
    deliver_owed_host_wakes(context.kernel());
    assert_eq!(
        wakes.load(Ordering::Relaxed),
        1,
        "host boundary must deliver the guest wake"
    );
    deliver_owed_host_wakes(context.kernel());
    assert_eq!(
        wakes.load(Ordering::Relaxed),
        1,
        "consume each owed notification once"
    );
    // Leave an indexed wake behind, then retire and reuse its object slot.
    {
        let region = owner.region();
        let mut guard = region.lock(object, &HostIpcWait).unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(guard.publish(step.wake).host_owed);
    }
    drop(enrollment);
    owner
        .release(IpcBacking::EventFd { object }.encode())
        .unwrap();
    let replacement = owner
        .create_eventfd(0, carrick_el1_abi::ipc::EventMode::Counter)
        .unwrap();
    assert_eq!(replacement.index(), object.index());
    assert_ne!(replacement, object);
    let queue = owner.wait_queue(replacement);
    let seen = Arc::clone(&wakes);
    let enrollment = queue.enroll_callback(move |_| {
        seen.fetch_add(1, Ordering::Relaxed);
    });
    deliver_owed_host_wakes(context.kernel());
    assert_eq!(
        wakes.load(Ordering::Relaxed),
        1,
        "retired notification cannot wake a reused object"
    );
    {
        let region = owner.region();
        let mut guard = region.lock(replacement, &HostIpcWait).unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(guard.publish(step.wake).host_owed);
    }
    deliver_owed_host_wakes(context.kernel());
    assert_eq!(
        wakes.load(Ordering::Relaxed),
        2,
        "successor keeps its own notification"
    );
    drop(enrollment);
    owner
        .release(
            IpcBacking::EventFd {
                object: replacement,
            }
            .encode(),
        )
        .unwrap();
}

/// A host-blocked eventfd reader (a host subscriber) is woken only through
/// the owed-wake index an EL1 write publishes; EL1 signals that index to
/// the host solely by marking its slot's pending host work. Every boundary
/// that consumes that flag must deliver the wake: a switched-in thread's
/// served-with-work exit and an idle exit alike, not only the host path of
/// the executor's own thread. Otherwise the reader sleeps until some
/// unrelated later boundary drains the index; with everyone else parked,
/// never (`el1_ipc_two_processes_blocking`, eventfd n=8).
#[test]
fn serial_host_el1_ipc_every_slot_boundary_delivers_owed_host_wakes() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    const SLOT: usize = 3;
    // A private, zeroed EL1 region (the host maps a fresh one per carrier).
    let region_bytes = vec![0u8; carrick_el1_abi::EL1_REGION_SIZE as usize];
    carrick_el1_abi::record_el1_region_host_ptr(region_bytes.as_ptr() as usize);
    let task = |slot: usize| {
        let at = region_bytes.as_ptr() as usize
            + carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
            + slot * std::mem::size_of::<carrick_el1_abi::CurrentTask>();
        // SAFETY: inside the zeroed region; all-zero is an empty task.
        unsafe { &*(at as *const carrick_el1_abi::CurrentTask) }
    };
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let owner = context.kernel().ipc().unwrap();
    let object = owner
        .create_eventfd(0, carrick_el1_abi::ipc::EventMode::Counter)
        .unwrap();
    let queue = owner.wait_queue(object);
    let wakes = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&wakes);
    let reader = queue.enroll_callback(move |_| {
        seen.fetch_add(1, Ordering::Relaxed);
    });
    // One EL1 eventfd write, as `personality::ipc::run` performs it: step and
    // publish under the object lock, then mark the slot's pending host work.
    let el1_write = || {
        let region = owner.region();
        let mut guard = region.lock(object, &HostIpcWait).unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(guard.publish(step.wake).host_owed);
        drop(guard);
        task(SLOT).mark_pending_host_work();
    };
    // A switched-in thread whose write was served with work owed exits;
    // the executor adopts it (the syscall is complete, not dispatched).
    el1_write();
    task(SLOT).served_with_work.store(1, Ordering::Release);
    assert!(crate::el1_delegation::settle_el1_boundary(SLOT, context.kernel()).is_some());
    let adopted = wakes.load(Ordering::Relaxed);
    // The writer then parks and the vCPU idles out for the pending work.
    el1_write();
    assert!(crate::el1_delegation::settle_el1_boundary(SLOT, context.kernel()).is_none());
    let idled = wakes.load(Ordering::Relaxed);
    assert!(!task(SLOT).has_pending_host_work());
    drop(reader);
    owner
        .release(IpcBacking::EventFd { object }.encode())
        .unwrap();
    carrick_el1_abi::record_el1_region_host_ptr(0);
    assert_eq!(
        (adopted, idled),
        (1, 2),
        "each boundary that consumes pending host work delivers the owed wake"
    );
}

/// An operation EL1 handed back and the host completes publishes its
/// change like any other: host subscribers of the object (a blocked host
/// reader, poll, epoll) are owed a wake and must receive it, not only the
/// object's EL1 waiters.
#[test]
fn serial_host_el1_ipc_host_completed_handback_wakes_host_subscribers() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let owner = context.kernel().ipc().unwrap();
    let object = owner
        .create_eventfd(0, carrick_el1_abi::ipc::EventMode::Counter)
        .unwrap();
    let queue = owner.wait_queue(object);
    let wakes = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&wakes);
    let subscriber = queue.enroll_callback(move |_| {
        seen.fetch_add(1, Ordering::Relaxed);
    });
    let region = owner.region();
    let pin = region
        .fd(HostIpcWait)
        .create_pinned(Description::new(
            IpcBacking::EventFd { object }.encode(),
            AccessMode::ReadWrite,
            StatusFlags::default(),
        ))
        .unwrap();
    // A descriptor keeps the eventfd alive past the operation's own pin.
    let table = owner.create_table(1024, 64).unwrap();
    owner
        .region()
        .fd(HostIpcWait)
        .install_pin(table, Fd(3), &pin, false)
        .unwrap();
    let token = region
        .begin_operation(IpcOperation {
            kind: IpcOpKind::EventFdWrite,
            pin: pin.into_raw(),
            object: object.to_raw(),
            task: IpcTaskKey(1),
            mm: MM,
            buf: IpcUserVa(BUF),
            progress: WriteProgress::new(8),
            value: carrick_el1_abi::ipc::IpcEventValue(5),
            orig_x0: 3,
            nr: 64,
            handback: IpcHandback::Continue,
            ..IpcOperation::EMPTY
        })
        .unwrap();
    let mut mem = memory(&[]);
    let service = ZoneHostServices::for_dispatcher(&dispatcher).unwrap();
    let outcome = complete_handback(&region, token, MM, &mut mem, None, &service).unwrap();
    assert_eq!(
        outcome,
        IpcHostOutcome::Complete {
            result: 8,
            sigpipe: false
        }
    );
    let delivered = wakes.load(Ordering::Relaxed);
    drop(subscriber);
    let mut guard = region.lock(object, &HostIpcWait).unwrap();
    assert_eq!(guard.eventfd().unwrap().value(), 5);
    drop(guard);
    let closed = region.fd(HostIpcWait).close(table, Fd(3)).unwrap().unwrap();
    owner.release(closed.backing).unwrap();
    assert_eq!(delivered, 1, "the host subscriber must be woken");
}

/// `el1_ipc_mixed_venue_roundtrips` on one object, in the host model: a
/// host-blocked `readv(2)` (the vector venue, a continuation on the eventfd's
/// wait queue with a host subscription) and an EL1-served `write(2)` (the
/// scalar venue: step and publish under the object lock, mark the slot's
/// pending host work, leave served-with-work). The write lands before the
/// reader's enrollment (it owes no host wake: the post-enrollment probe must
/// see it) or after (it owes one: the writer's exit boundary must deliver
/// it). Either way the reader wakes and its redispatched `readv` returns the
/// value.
fn mixed_venue_readv_wakes_on_el1_write(write_before_enroll: bool) {
    use crate::compat::{CompatReporter, SyscallArgs};
    use crate::dispatch::{DispatchOutcome, SyscallRequest};
    use crate::kernel::continuation::test_support::{capture, publish};
    use crate::kernel::continuation::{
        BlockedContinuation, CancellationCause, CarrierWaitService, ContinuationCompletion,
        ContinuationEvent,
    };
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};
    use zerocopy::IntoBytes;
    const SLOT: usize = 2;
    let region_bytes = vec![0u8; carrick_el1_abi::EL1_REGION_SIZE as usize];
    carrick_el1_abi::record_el1_region_host_ptr(region_bytes.as_ptr() as usize);
    let task = |slot: usize| {
        let at = region_bytes.as_ptr() as usize
            + carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
            + slot * std::mem::size_of::<carrick_el1_abi::CurrentTask>();
        // SAFETY: inside the zeroed region; all-zero is an empty task.
        unsafe { &*(at as *const carrick_el1_abi::CurrentTask) }
    };
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(context.kernel());
    let mut memory = LinearMemory::new(0x4000, vec![0u8; 4096]);
    let reporter = CompatReporter::default();
    let returned = |outcome: DispatchOutcome| match outcome {
        DispatchOutcome::Returned { value } => value,
        other => panic!("fixture syscall: {other:?}"),
    };
    let efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let object = dispatcher
        .open_file(efd as i32)
        .unwrap()
        .description
        .inspect_kind(|open| match open {
            crate::dispatch::fd_table::OpenDescription::EventFd { state, .. } => state.ipc_object(),
            other => panic!("eventfd description: {other:?}"),
        })
        .unwrap();
    memory
        .write_bytes(0x4200, carrick_abi::LinuxIovec::new(0x4000, 8).as_bytes())
        .unwrap();
    let readv = SyscallRequest::new(65, SyscallArgs([efd as u64, 0x4200, 1, 0, 0, 0]));
    let outcome = dispatcher
        .dispatch(&context, readv, &mut memory, &reporter)
        .unwrap();
    assert!(
        matches!(&outcome, DispatchOutcome::WaitOnFds { .. }),
        "empty blocking eventfd readv must park: {outcome:?}"
    );
    let generation = publish(&context, 0x3a5);
    let mut continuation =
        BlockedContinuation::from_dispatch_outcome(outcome, capture(&context, generation))
            .expect("eventfd readv continuation");
    let service =
        CarrierWaitService::new(Arc::new(crate::kernel::Scheduler::new(Arc::clone(&kernel))));
    let owner = kernel.ipc().unwrap();
    // As `personality::ipc::run` serves the scalar write in EL1, then the
    // writer's served-with-work exit at its slot's host boundary.
    let el1_write = || {
        let region = owner.region();
        let mut guard = region.lock(object, &HostIpcWait).unwrap();
        let step = guard.eventfd().unwrap().try_write(5);
        let published = guard.publish(step.wake);
        drop(guard);
        assert_eq!(
            published.host_owed, !write_before_enroll,
            "a wake is owed exactly when the host reader is subscribed"
        );
        if published.host_owed {
            task(SLOT).mark_pending_host_work();
        }
        task(SLOT).served_with_work.store(1, Ordering::Release);
        assert!(crate::el1_delegation::settle_el1_boundary(SLOT, &kernel).is_some());
    };
    if write_before_enroll {
        el1_write();
    }
    let mut registration = service.prepare_registration(&continuation);
    service.enroll(&mut registration).expect("enroll");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach");
    if !write_before_enroll {
        el1_write();
    }
    let mut future = std::pin::pin!(service.event(token));
    let deadline = Instant::now() + Duration::from_secs(5);
    let event = loop {
        if let Poll::Ready(event) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            break Some(event);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::yield_now();
    };
    let Some(event) = event else {
        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
        carrick_el1_abi::record_el1_region_host_ptr(0);
        panic!("host readv lost the EL1 write's wake (write_before_enroll={write_before_enroll})");
    };
    assert_eq!(event.expect("readv wake"), ContinuationEvent::Ready);
    assert_eq!(
        continuation
            .resume(ContinuationEvent::Ready, &context)
            .unwrap()
            .completion,
        ContinuationCompletion::Redispatch
    );
    assert_eq!(
        returned(
            dispatcher
                .dispatch(&context, readv, &mut memory, &reporter)
                .unwrap()
        ),
        8
    );
    let value = memory.read_bytes(0x4000, 8).unwrap();
    assert_eq!(u64::from_ne_bytes(value.try_into().unwrap()), 5);
    assert!(!task(SLOT).has_pending_host_work());
    carrick_el1_abi::record_el1_region_host_ptr(0);
}

#[test]
fn serial_host_el1_ipc_mixed_venue_readv_wakes_on_el1_write_after_enroll() {
    mixed_venue_readv_wakes_on_el1_write(false);
}

#[test]
fn serial_host_el1_ipc_mixed_venue_readv_wakes_on_el1_write_before_enroll() {
    mixed_venue_readv_wakes_on_el1_write(true);
}
