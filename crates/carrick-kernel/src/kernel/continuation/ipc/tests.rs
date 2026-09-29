//! VM-free bindings for kernel.el1.ipc-continuation: the host completing
//! operations EL1 owns, over real shared records and a guest-memory model.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::dispatch::LinearMemory;
use carrick_el1_abi::ipc::fd::{AccessMode, Description, Fd, StatusFlags, TableId};
use carrick_el1_abi::ipc::{
    End, Extent, IPC_POOL_ALIGN, IpcBacking, IpcDirectory, IpcPipeStorage, IpcTaskKey, IpcUserVa,
    WriteProgress, descriptor_extent_bytes,
};
use carrick_guest_mem::GuestMemory;
use std::alloc::Layout;
use std::cell::{Cell, RefCell};

const MM: IpcMmKey = IpcMmKey(7);
const BUF: u64 = 0x10_0000;

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
impl IpcHostWake for Wakes {
    fn wake(&self, object: IpcObjectHandle, lanes: WakeSet) {
        self.0.borrow_mut().push((object, lanes));
    }
}

fn world() -> World {
    let dir =
        unsafe { std::alloc::alloc_zeroed(Layout::new::<IpcDirectory>()).cast::<IpcDirectory>() };
    let pool_len = 4 << 20;
    let pool =
        unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
    let region = unsafe { IpcRegion::initialize(dir, pool, pool_len, 9) }.unwrap();
    let region: &'static IpcRegion<'static> = Box::leak(Box::new(region));
    let w = World {
        region,
        next: Cell::new(0),
        table: TableId::from_raw(Default::default()),
    };
    let mut extent = Extent {
        token: w.bump(descriptor_extent_bytes(64)),
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
        let storage = IpcPipeStorage {
            offset: self.bump(65536 + 16 * 8),
            ring_bytes: 65536,
            pages: 16,
        };
        let object = self
            .region
            .create_pipe(65536, &mut Some(storage), &HostIpcWait)
            .unwrap();
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
            nr: 63
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
