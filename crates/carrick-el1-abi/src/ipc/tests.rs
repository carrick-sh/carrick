//! VM-free bindings for kernel.el1.ipc-fd-authority and
//! kernel.el1.ipc-object-state over the shared region: two venue views
//! (host: waits; EL1: bounded spin) operating on one set of records.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

extern crate std;

use super::*;
use carrick_fd_core::{AccessMode, BoundedSpin, Description, Fd, StatusFlags, TableId};
use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};
use std::boxed::Box;
use std::collections::HashMap;
use std::vec::Vec;

// ---- allocation counter: transfers after admission must not allocate ----
struct Counting;
std::thread_local! {
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}
// SAFETY: forwards to the system allocator; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's. The system allocator keeps
        // a large zeroed reservation (the directory) lazily committed.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static COUNTING: Counting = Counting;
fn allocations() -> usize {
    ALLOCS.with(|n| n.get())
}

struct Spin;
impl LockWait for Spin {
    fn wait(&self, _attempt: u32) -> bool {
        core::hint::spin_loop();
        true
    }
}
const EL1: BoundedSpin = BoundedSpin(1024);

// ---- fixture: zeroed directory + pool, published by the "host" ----
struct Fixture {
    region: &'static IpcRegion<'static>,
    next: Cell<u64>,
    pool_len: u64,
}
static IDENTITY: AtomicU64 = AtomicU64::new(0x1_0000);

/// A zeroed directory mapping (lazily committed by the system allocator).
pub(super) fn zeroed_directory() -> *mut IpcDirectory {
    let layout = Layout::from_size_align(IPC_DIRECTORY_BYTES, 4096).unwrap();
    // SAFETY: nonzero layout; the leaked mapping outlives every view.
    unsafe { std::alloc::alloc_zeroed(layout) }.cast()
}

fn fixture(pool_len: usize) -> Fixture {
    let dir = zeroed_directory();
    let pool =
        unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
    let identity = IDENTITY.fetch_add(1, Ordering::Relaxed);
    let region =
        unsafe { IpcRegion::initialize(dir, IPC_DIRECTORY_BYTES, pool, pool_len, identity) }
            .unwrap();
    Fixture {
        region: Box::leak(Box::new(region)),
        next: Cell::new(0),
        pool_len: pool_len as u64,
    }
}
impl Fixture {
    fn bump(&self, bytes: u64) -> u64 {
        let at = self.next.get();
        let end = (at + bytes).next_multiple_of(IPC_POOL_ALIGN);
        assert!(end <= self.pool_len, "fixture pool exhausted");
        self.next.set(end);
        at
    }
    fn descriptors(&self, capacity: usize) -> Extent {
        Extent {
            token: self.bump(descriptor_extent_bytes(capacity)),
            capacity: capacity as u64,
        }
    }
    fn pipe_storage(&self) -> IpcPipeStorage {
        let pages = 16;
        let s = IpcPipeStorage {
            offset: 0,
            ring_bytes: (pages * IPC_PIPE_PAGE_SIZE) as u64,
            pages: pages as u64,
        };
        IpcPipeStorage {
            offset: self.bump(s.footprint()),
            ..s
        }
    }
    fn host(&self) -> IpcFdAuthority<'static, Spin> {
        self.region.fd(Spin)
    }
    fn el1(&self) -> IpcFdAuthority<'static, BoundedSpin> {
        self.region.fd(EL1)
    }
    fn table(&self) -> TableId {
        self.host()
            .create_table(1024, &mut self.descriptors(64))
            .unwrap()
    }
    /// What the host venue does for pipe(2): one object, two descriptions.
    fn pipe(&self, table: TableId) -> (Fd, Fd, IpcObjectHandle) {
        let object = self
            .region
            .create_pipe(65536, &mut Some(self.pipe_storage()), &Spin)
            .unwrap();
        let open = |end, access| {
            self.host()
                .open(
                    table,
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
    fn eventfd(&self, table: TableId, initial: u32, mode: EventMode) -> (Fd, IpcObjectHandle) {
        let object = self.region.create_eventfd(initial, mode, &Spin).unwrap();
        let fd = self
            .host()
            .open(
                table,
                Fd(0),
                Description::new(
                    IpcBacking::EventFd { object }.encode(),
                    AccessMode::ReadWrite,
                    StatusFlags::default(),
                ),
                false,
            )
            .unwrap();
        (fd, object)
    }
    /// A final description release, as either venue performs it.
    fn finish(&self, released: Option<Description>) -> Option<IpcReleased> {
        released.map(|d| self.region.release_backing(d.backing, &Spin).unwrap())
    }
}

#[derive(Debug, PartialEq)]
enum IoError {
    Ipc(IpcError),
    Obj(pipe::Error),
}

/// An EL1-style pipe transfer on one descriptor: pin (brief table lock),
/// one object lock, staged copy, publish, unlock, unpin.
fn el1_io(
    fx: &Fixture,
    table: TableId,
    fd: Fd,
    write: Option<&[u8]>,
    read: &mut [u8],
) -> Result<(usize, IpcWake), IoError> {
    let fda = fx.el1();
    let (pin, desc) = fda
        .pin(table, fd)
        .map_err(|e| IoError::Ipc(IpcError::Fd(e)))?;
    let Some(IpcBacking::Pipe { object, end }) = IpcBacking::decode(desc.backing) else {
        panic!("not a pipe");
    };
    let mut guard = fx.region.lock(object, &EL1).map_err(IoError::Ipc)?;
    let step = {
        let mut p = guard.pipe().map_err(IoError::Ipc)?;
        match (end, write) {
            (End::Writer, Some(src)) => p.try_write(src),
            (End::Reader, None) => p.try_read(read),
            _ => panic!("wrong end"),
        }
    };
    let wake = guard.publish(step.wake);
    drop(guard);
    assert_eq!(fx.finish(fda.unpin(pin).unwrap()), None);
    step.result.map(|n| (n, wake)).map_err(IoError::Obj)
}

#[test]
fn el1_ipc_backing_tokens_roundtrip_and_reject_unknown_tags() {
    let object = IpcObjectHandle::from_raw(RawIpcObject {
        index: 1023,
        generation: u32::MAX,
    });
    for backing in [
        IpcBacking::Pipe {
            object,
            end: End::Reader,
        },
        IpcBacking::Pipe {
            object,
            end: End::Writer,
        },
        IpcBacking::EventFd { object },
        IpcBacking::Host(HostResourceToken::new(HostResourceToken::MAX).unwrap()),
        IpcBacking::Host(HostResourceToken::new(1).unwrap()),
    ] {
        assert_eq!(IpcBacking::decode(backing.encode()), Some(backing));
    }
    for bad in [0, 4 << 61, 7 << 61, (3 << 61) | (1 << 60), 1 << 61] {
        assert_eq!(IpcBacking::decode(BackingToken(bad)), None, "{bad:#x}");
    }
    assert_eq!(HostResourceToken::new(0), None);
    assert_eq!(HostResourceToken::new(HostResourceToken::MAX + 1), None);
}

#[test]
fn el1_ipc_layout_is_frozen_and_fits_one_metadata_extent() {
    assert_ne!(IPC_LAYOUT_HASH, 0);
    assert_eq!(core::mem::size_of::<IpcObjectRecord>() % 64, 0);
    assert_eq!(core::mem::size_of::<IpcOperation>(), 120);
    assert_eq!(core::mem::size_of::<IpcPipeStorage>(), 24);
    assert!(
        core::mem::size_of::<IpcDirectory>() <= crate::EL1_DYNAMIC_METADATA_EXTENT_SIZE,
        "directory head {} bytes",
        core::mem::size_of::<IpcDirectory>()
    );
    // The elastic stores' reservations fit the directory span, in order.
    assert!(IPC_OBJECTS_OFFSET >= core::mem::size_of::<IpcDirectory>());
    assert!(IPC_OFDS_OFFSET >= IPC_OBJECTS_OFFSET + IPC_MAX_OBJECTS * 64);
    assert!(IPC_WAKE_LEAVES_OFFSET >= IPC_OFDS_OFFSET + IPC_MAX_OFDS * 64);
    assert!(IPC_DIRECTORY_BYTES as u64 <= crate::EL1_IPC_DIRECTORY_SPAN);
}

#[test]
fn el1_ipc_region_attach_authenticates_the_header() {
    let len = 1 << 20;
    let dir = zeroed_directory();
    let dl = IPC_DIRECTORY_BYTES;
    let pool = unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(len, 4096).unwrap()) };
    // Unpublished: zeroed memory never attaches.
    assert_eq!(
        unsafe { IpcRegion::attach(dir, dl, pool, len) }.err(),
        Some(IpcError::BadRegion)
    );
    assert_eq!(
        unsafe { IpcRegion::initialize(dir, dl - 1, pool, len, 77) }.err(),
        Some(IpcError::BadRegion),
        "a directory mapping shorter than the stores' reservation"
    );
    let host = unsafe { IpcRegion::initialize(dir, dl, pool, len, 77) }.unwrap();
    assert_eq!(
        unsafe { IpcRegion::initialize(dir, dl, pool, len, 78) }.err(),
        Some(IpcError::BadRegion)
    );
    assert_eq!(
        unsafe { IpcRegion::attach(dir, dl, pool, len - 4096) }.err(),
        Some(IpcError::BadRegion)
    );
    assert_eq!(
        unsafe { IpcRegion::attach(dir.cast::<u8>().add(64).cast(), dl, pool, len) }.err(),
        Some(IpcError::BadRegion),
        "misaligned directory"
    );
    assert_eq!(
        unsafe { IpcRegion::attach(dir, dl - 1, pool, len) }.err(),
        Some(IpcError::BadRegion)
    );
    let el1 = unsafe { IpcRegion::attach(dir, dl, pool, len) }.unwrap();
    // The two views share one authority: a table the host creates is the
    // table EL1 resolves.
    let h: &'static IpcRegion<'static> = Box::leak(Box::new(host));
    let e: &'static IpcRegion<'static> = Box::leak(Box::new(el1));
    let t = h
        .fd(Spin)
        .create_table(
            8,
            &mut Extent {
                token: 0,
                capacity: 8,
            },
        )
        .unwrap();
    let object = h.create_eventfd(3, EventMode::Counter, &Spin).unwrap();
    let token = IpcBacking::EventFd { object }.encode();
    let fd = h
        .fd(Spin)
        .open(
            t,
            Fd(0),
            Description::new(token, AccessMode::ReadWrite, StatusFlags::default()),
            true,
        )
        .unwrap();
    assert_eq!(e.fd(EL1).get(t, fd).unwrap().backing, token);
    assert_eq!(e.lock(object, &EL1).unwrap().eventfd().unwrap().value(), 3);
    // A corrupted layout hash is refused.
    unsafe { (*dir).header.layout_hash.store(1, Ordering::Relaxed) };
    assert_eq!(
        unsafe { IpcRegion::attach(dir, dl, pool, len) }.err(),
        Some(IpcError::BadRegion)
    );
}

#[test]
fn el1_ipc_pipe_roundtrip_eof_and_epipe_across_venues() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (r, w, object) = fx.pipe(t);
    let (n, wake) = el1_io(&fx, t, w, Some(b"ping"), &mut []).unwrap();
    assert_eq!(n, 4);
    assert!(wake.readers && !wake.host_owed);
    assert_eq!(fx.region.observe(object).unwrap(), wake.seqs);
    // The host reads the byte EL1 wrote: one storage authority.
    let mut out = [0; 8];
    let mut g = fx.region.lock(object, &Spin).unwrap();
    assert_eq!(g.pipe().unwrap().try_read(&mut out).result, Ok(4));
    drop(g);
    assert_eq!(&out[..4], b"ping");
    assert_eq!(
        el1_io(&fx, t, r, None, &mut out),
        Err(IoError::Obj(pipe::Error::WouldBlock(
            pipe::WaitFor::Readable
        )))
    );
    // Final close of the write end: EOF on the read end.
    assert!(matches!(
        fx.finish(fx.host().close(t, w).unwrap()),
        Some(IpcReleased::Object { freed: false, wake }) if wake.readers
    ));
    assert_eq!(el1_io(&fx, t, r, None, &mut out).map(|x| x.0), Ok(0));
    let (_r2, w2, _) = fx.pipe(t);
    assert!(matches!(
        fx.finish(fx.host().close(t, _r2).unwrap()),
        Some(IpcReleased::Object { freed: false, .. })
    ));
    assert_eq!(
        el1_io(&fx, t, w2, Some(b"x"), &mut []),
        Err(IoError::Obj(pipe::Error::BrokenPipe))
    );
    // Last endpoint of the first pipe: the object is freed exactly once.
    assert!(matches!(
        fx.finish(fx.host().close(t, r).unwrap()),
        Some(IpcReleased::Object { freed: true, .. })
    ));
    assert_eq!(fx.region.observe(object), Err(IpcError::Stale));
}

#[test]
fn el1_ipc_fd_reuse_during_blocked_read_keeps_the_endpoint() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (r, w, object) = fx.pipe(t);
    // A reader blocks: its owned continuation holds the pin, not the number.
    let (pin, desc) = fx.el1().pin(t, r).unwrap();
    let mut op = IpcOperation::EMPTY;
    op.kind = IpcOpKind::PipeRead;
    op.object = object.to_raw();
    op.progress = WriteProgress::new(16);
    op.park_seq = fx.region.observe(object).unwrap().read;
    op.pin = pin.into_raw();
    // Another thread closes the fd and the number is reused by an eventfd.
    assert_eq!(fx.host().close(t, r), Ok(None));
    let (reused, _) = fx.eventfd(t, 0, EventMode::Counter);
    assert_eq!(reused, r);
    // The pipe still has a reader: writes succeed, no EPIPE.
    let (n, wake) = el1_io(&fx, t, w, Some(b"data"), &mut []).unwrap();
    assert_eq!(n, 4);
    assert!(
        wake.seqs.read > op.park_seq,
        "the waiter's recheck sees a change"
    );
    // Resume through the pinned description, not through fd `r`.
    let pin = OfdPin::from_raw(op.pin);
    let fda = fx.el1();
    let current = fda.pinned(&pin).unwrap();
    assert_eq!(current.backing, desc.backing);
    let mut g = fx.region.lock(object, &EL1).unwrap();
    let mut out = [0; 16];
    assert_eq!(g.pipe().unwrap().try_read(&mut out).result, Ok(4));
    drop(g);
    assert_eq!(&out[..4], b"data");
    // Completion releases the last hold: the reader endpoint goes away once.
    let released = fx.finish(fda.unpin(pin).unwrap());
    assert!(matches!(released, Some(IpcReleased::Object { freed: false, wake }) if wake.writers));
    assert_eq!(
        el1_io(&fx, t, w, Some(b"x"), &mut []),
        Err(IoError::Obj(pipe::Error::BrokenPipe))
    );
}

#[test]
fn el1_ipc_eventfd_counter_semaphore_overflow_and_fault_in_place() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (fd, counter) = fx.eventfd(t, 0, EventMode::Counter);
    let (_, sem) = fx.eventfd(t, 2, EventMode::Semaphore);
    let mut g = fx.region.lock(counter, &EL1).unwrap();
    assert_eq!(g.pipe().err(), Some(IpcError::WrongKind));
    let e = g.eventfd().unwrap();
    assert_eq!(e.try_write(7).result, Ok(()));
    assert_eq!(e.read_with(|_| false).result, Err(pipe::Error::Fault));
    assert_eq!(e.value(), 7, "failed copyout drains nothing");
    assert_eq!(e.try_write(pipe::EVENTFD_MAX - 7).result, Ok(()));
    assert_eq!(
        e.try_write(1).result,
        Err(pipe::Error::WouldBlock(pipe::WaitFor::Writable))
    );
    assert_eq!(e.try_read().result, Ok(pipe::EVENTFD_MAX));
    let wake = g.publish(WakeSet {
        readers: false,
        writers: true,
    });
    drop(g);
    assert_eq!(fx.region.observe(counter).unwrap(), wake.seqs);
    let mut g = fx.region.lock(sem, &Spin).unwrap();
    assert_eq!(g.eventfd().unwrap().try_read().result, Ok(1));
    assert_eq!(g.eventfd().unwrap().value(), 1);
    drop(g);
    assert!(matches!(
        fx.finish(fx.host().close(t, fd).unwrap()),
        Some(IpcReleased::Object { freed: true, .. })
    ));
}

#[test]
fn el1_ipc_stale_object_generations_are_rejected() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (fd, old) = fx.eventfd(t, 1, EventMode::Counter);
    let old_token = fx.host().get(t, fd).unwrap().backing;
    fx.finish(fx.host().close(t, fd).unwrap());
    let (_, new) = fx.eventfd(t, 5, EventMode::Counter);
    assert_eq!(new.index(), old.index(), "the record is reused");
    assert_ne!(new.generation(), old.generation());
    assert_eq!(fx.region.lock(old, &Spin).err(), Some(IpcError::Stale));
    assert_eq!(fx.region.observe(old), Err(IpcError::Stale));
    assert_eq!(
        fx.region.release_backing(old_token, &Spin),
        Err(IpcError::Stale),
        "a stale description cannot release the new object"
    );
    assert!(!fx.region.take_host_wake(old));
    assert_eq!(
        fx.region
            .lock(new, &Spin)
            .unwrap()
            .eventfd()
            .unwrap()
            .value(),
        5
    );
}

#[test]
fn el1_ipc_host_notification_is_owed_only_to_subscribers() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (_r, w, object) = fx.pipe(t);
    let (_, wake) = el1_io(&fx, t, w, Some(b"a"), &mut []).unwrap();
    assert!(!wake.host_owed);
    assert!(!fx.region.take_host_wake(object));
    let before = fx.region.observe(object).unwrap();
    // Zero-length writes change nothing and owe nothing.
    let (_, wake) = el1_io(&fx, t, w, Some(b""), &mut []).unwrap();
    assert_eq!(wake.seqs, before);
    fx.region.subscribe_host(object, &Spin).unwrap();
    let (_, wake) = el1_io(&fx, t, w, Some(b"b"), &mut []).unwrap();
    assert!(wake.host_owed);
    assert!(fx.region.take_host_wake(object));
    assert!(!fx.region.take_host_wake(object), "delivered once");
    let (_, wake) = el1_io(&fx, t, w, Some(b"pending"), &mut []).unwrap();
    assert!(wake.host_owed);
    fx.region.unsubscribe_host(object, &Spin).unwrap();
    assert!(
        !fx.region.take_host_wake(object),
        "last subscriber cancels an undelivered wake"
    );
    assert_eq!(
        fx.region.unsubscribe_host(object, &Spin),
        Err(IpcError::Corrupt)
    );
    let (_, wake) = el1_io(&fx, t, w, Some(b"c"), &mut []).unwrap();
    assert!(!wake.host_owed);
}

#[test]
fn el1_ipc_storage_refusals_roll_back_and_free_records_keep_storage() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    // No storage supplied for a fresh record: refused, nothing consumed.
    let mut none = None;
    assert_eq!(
        fx.region.create_pipe(65536, &mut none, &Spin),
        Err(IpcError::NeedsStorage {
            ring_bytes: 65536,
            pages: 16
        })
    );
    // Out-of-pool storage fails closed and leaves the record reusable.
    let mut bad = Some(IpcPipeStorage {
        offset: fx.pool_len,
        ring_bytes: 65536,
        pages: 16,
    });
    assert_eq!(
        fx.region.create_pipe(65536, &mut bad, &Spin),
        Err(IpcError::BadStorage)
    );
    let (r, w, object) = fx.pipe(t);
    // F_SETPIPE_SZ beyond the reserve: Storage, capacity and bytes kept.
    el1_io(&fx, t, w, Some(b"kept"), &mut []).unwrap();
    let mut g = fx.region.lock(object, &Spin).unwrap();
    let mut p = g.pipe().unwrap();
    assert_eq!(
        p.set_capacity(1 << 20, usize::MAX).result,
        Err(pipe::Error::Storage)
    );
    assert_eq!((p.capacity(), p.unread_bytes()), (65536, 4));
    drop(g);
    fx.finish(fx.host().close(t, r).unwrap());
    fx.finish(fx.host().close(t, w).unwrap());
    // The freed record kept its storage: a new pipe needs none supplied.
    let mut none = None;
    let reused = fx.region.create_pipe(65536, &mut none, &Spin).unwrap();
    assert_eq!(reused.index(), object.index());
    assert_eq!(none, None);
    let mut g = fx.region.lock(reused, &Spin).unwrap();
    assert_eq!(
        g.pipe().unwrap().unread_bytes(),
        0,
        "fresh state, reused bytes"
    );
}

#[test]
fn el1_ipc_contended_object_lock_refuses_before_effects() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (r, w, object) = fx.pipe(t);
    let record = fx.region.record(object.index()).unwrap();
    record.lock.store(1, Ordering::Release);
    assert_eq!(
        el1_io(&fx, t, w, Some(b"x"), &mut []),
        Err(IoError::Ipc(IpcError::Contended))
    );
    let released = fx.host().close(t, r).unwrap().unwrap();
    assert_eq!(
        fx.region.release_backing(released.backing, &EL1),
        Err(IpcError::Contended),
        "an EL1 final release that cannot lock hands off, changing nothing"
    );
    record.lock.store(0, Ordering::Release);
    assert!(fx.region.release_backing(released.backing, &Spin).is_ok());
    assert_eq!(
        el1_io(&fx, t, w, Some(b"x"), &mut []),
        Err(IoError::Obj(pipe::Error::BrokenPipe))
    );
}

#[test]
fn el1_ipc_blocked_write_resumes_from_its_continuation_without_replay() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (r, w, object) = fx.pipe(t);
    let source: Vec<u8> = (0..65536 * 2 + 100).map(|n| (n % 251) as u8).collect();
    let (pin, _) = fx.el1().pin(t, w).unwrap();
    let mut op = IpcOperation::EMPTY;
    op.kind = IpcOpKind::PipeWrite;
    op.progress = WriteProgress::new(source.len() as u64);
    op.pin = pin.into_raw();
    let mut received = Vec::new();
    let copy_in = |at: usize, dst: &mut [u8]| {
        dst.copy_from_slice(&source[at..at + dst.len()]);
        dst.len()
    };
    while !op.progress.is_complete() {
        let mut g = fx.region.lock(object, &EL1).unwrap();
        let step = g.pipe().unwrap().write_progress(&mut op.progress, copy_in);
        g.publish(step.wake);
        drop(g);
        assert!(step.result.is_ok());
        // The operation parks; the reader drains on another task.
        let mut out = [0; 65536];
        let (n, _) = el1_io(&fx, t, r, None, &mut out).unwrap();
        received.extend_from_slice(&out[..n]);
    }
    assert_eq!(received, source, "no byte replayed or lost");
    assert_eq!(fx.el1().unpin(OfdPin::from_raw(op.pin)), Ok(None));
}

/// A user-memory model keyed by exact address space: two processes use the
/// same user VA for different buffers.
struct UserMemory(HashMap<(IpcMmKey, IpcUserVa), Vec<u8>>);

#[test]
fn el1_ipc_two_processes_with_overlapping_user_vas_complete_their_own_reads() {
    let fx = fixture(1 << 20);
    let parent = fx.table();
    let (r, w, object) = fx.pipe(parent);
    let child = fx.host().fork(parent, &mut fx.descriptors(64)).unwrap();
    let va = IpcUserVa(0x7fff_0000);
    let mut memory = UserMemory(HashMap::new());
    let mut ops = Vec::new();
    for (table, mm) in [(parent, IpcMmKey(1)), (child, IpcMmKey(2))] {
        memory.0.insert((mm, va), std::vec![0; 3]);
        let (pin, _) = fx.el1().pin(table, r).unwrap();
        let mut op = IpcOperation::EMPTY;
        op.kind = IpcOpKind::PipeRead;
        op.mm = mm;
        op.buf = va;
        op.progress = WriteProgress::new(3);
        op.pin = pin.into_raw();
        ops.push(op);
    }
    // Both descriptors of the forked read end close; the pins keep it.
    assert_eq!(fx.host().close(parent, r), Ok(None));
    assert_eq!(fx.host().close(child, r), Ok(None));
    el1_io(&fx, parent, w, Some(b"abcdef"), &mut []).unwrap();
    for op in &mut ops {
        let mut g = fx.region.lock(object, &EL1).unwrap();
        let buf = memory.0.get_mut(&(op.mm, op.buf)).unwrap();
        let mut at = 0;
        let step = g
            .pipe()
            .unwrap()
            .read_with(op.progress.remaining(), |chunk| {
                buf[at..at + chunk.len()].copy_from_slice(chunk);
                at += chunk.len();
                chunk.len()
            });
        op.progress.written += step.result.unwrap() as u64;
        g.publish(step.wake);
    }
    assert_eq!(memory.0[&(IpcMmKey(1), va)], b"abc");
    assert_eq!(memory.0[&(IpcMmKey(2), va)], b"def");
    let fda = fx.el1();
    assert_eq!(
        fx.finish(fda.unpin(OfdPin::from_raw(ops[0].pin)).unwrap()),
        None
    );
    assert!(matches!(
        fx.finish(fda.unpin(OfdPin::from_raw(ops[1].pin)).unwrap()),
        Some(IpcReleased::Object { freed: false, .. })
    ));
}

/// N communicating pairs, each pair two processes (tables) joined by two
/// pipes (one per direction) and an eventfd. After setup, `rounds`
/// bidirectional round trips. Returns (bytes copied, allocations).
fn pairs_steady_state(fx: &Fixture, pairs: usize, rounds: usize) -> (usize, usize) {
    const MSG: usize = 64;
    struct Pair {
        a: TableId,
        b: TableId,
        a_to_b: (Fd, Fd),
        b_to_a: (Fd, Fd),
        event: (Fd, IpcObjectHandle),
    }
    let mut all = Vec::new();
    for _ in 0..pairs {
        let a = fx.table();
        let (r1, w1, _) = fx.pipe(a);
        let (r2, w2, _) = fx.pipe(a);
        let event = fx.eventfd(a, 0, EventMode::Semaphore);
        let b = fx.host().fork(a, &mut fx.descriptors(64)).unwrap();
        all.push(Pair {
            a,
            b,
            a_to_b: (r1, w1),
            b_to_a: (r2, w2),
            event,
        });
    }
    let message = [0x5a_u8; MSG];
    let mut inbox = [0_u8; MSG];
    let mut copied = 0;
    let before = allocations();
    for _ in 0..rounds {
        for p in &all {
            let (n, _) = el1_io(fx, p.a, p.a_to_b.1, Some(&message), &mut []).unwrap();
            let (m, _) = el1_io(fx, p.b, p.a_to_b.0, None, &mut inbox).unwrap();
            copied += n + m;
            let (n, _) = el1_io(fx, p.b, p.b_to_a.1, Some(&inbox), &mut []).unwrap();
            let (m, _) = el1_io(fx, p.a, p.b_to_a.0, None, &mut inbox).unwrap();
            copied += n + m;
            assert_eq!(inbox, message);
            // Eventfd handoff: post from b, consume in a (semaphore mode).
            for (table, write) in [(p.b, true), (p.a, false)] {
                let fda = fx.el1();
                let (pin, desc) = fda.pin(table, p.event.0).unwrap();
                let Some(IpcBacking::EventFd { object }) = IpcBacking::decode(desc.backing) else {
                    panic!("eventfd");
                };
                assert_eq!(object, p.event.1);
                let mut g = fx.region.lock(object, &EL1).unwrap();
                let e = g.eventfd().unwrap();
                let step = if write {
                    e.try_write(1).wake
                } else {
                    let s = e.try_read();
                    assert_eq!(s.result, Ok(1));
                    s.wake
                };
                g.publish(step);
                drop(g);
                assert_eq!(fda.unpin(pin), Ok(None));
            }
        }
    }
    let allocated = allocations() - before;
    (copied, allocated)
}

#[test]
fn el1_ipc_steady_state_transfers_scale_linearly_without_allocation() {
    // Positive control: the counter sees this thread's allocations.
    let before = allocations();
    let probe = std::hint::black_box(Vec::<u8>::with_capacity(16));
    assert!(allocations() > before);
    drop(probe);
    for pairs in [1, 8, 64] {
        let fx = fixture(16 << 20);
        let (bytes, allocs) = pairs_steady_state(&fx, pairs, 16);
        assert_eq!(bytes, pairs * 16 * 4 * 64, "exact payload at N={pairs}");
        assert_eq!(allocs, 0, "zero allocations per transfer at N={pairs}");
        // Round-count scaling: twice the rounds, exactly twice the work,
        // so a fixed setup boundary cannot hide per-round fallback.
        let fx = fixture(16 << 20);
        let (bytes2, allocs2) = pairs_steady_state(&fx, pairs, 32);
        assert_eq!(bytes2, 2 * bytes);
        assert_eq!(allocs2, 0);
    }
}

#[test]
fn el1_ipc_operation_tokens_own_their_record_and_reject_stale_copies() {
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (r, _w, object) = fx.pipe(t);
    let (pin, _) = fx.el1().pin(t, r).unwrap();
    let mut op = IpcOperation::EMPTY;
    op.kind = IpcOpKind::PipeRead;
    op.object = object.to_raw();
    op.progress = WriteProgress::new(10);
    op.pin = pin.into_raw();
    let token = fx.region.begin_operation(op).unwrap();
    // Parked: the scheduler keeps only the raw token.
    let raw = token.into_raw();
    let token = IpcOpToken::from_raw(raw);
    let mut current = fx.region.operation(&token).unwrap();
    current.progress.written = 4;
    fx.region.update_operation(&token, current).unwrap();
    let done = fx.region.finish_operation(token).unwrap();
    assert_eq!(done.progress.written, 4);
    assert_eq!(fx.el1().unpin(OfdPin::from_raw(done.pin)), Ok(None));
    // A copied raw token is not a second owner.
    let stale = IpcOpToken::from_raw(raw);
    assert_eq!(fx.region.operation(&stale), Err(IpcError::Stale));
    assert_eq!(fx.region.finish_operation(stale), Err(IpcError::Stale));
    let reused = fx.region.begin_operation(IpcOperation::EMPTY).unwrap();
    assert_eq!(
        fx.region.operation(&IpcOpToken::from_raw(raw)),
        Err(IpcError::Stale),
        "a reused record never answers to the old generation"
    );
    assert_eq!(reused.into_raw().index, raw.index);
    // Exhaustion refuses before effects.
    let mut held = Vec::new();
    while let Ok(t) = fx.region.begin_operation(IpcOperation::EMPTY) {
        held.push(t);
    }
    assert_eq!(held.len(), IPC_OPERATIONS - 1);
    assert_eq!(
        fx.region.begin_operation(IpcOperation::EMPTY),
        Err(IpcError::NoOperations)
    );
    for t in held {
        fx.region.finish_operation(t).unwrap();
    }
}

#[test]
fn el1_ipc_live_pipe_storage_replacement_preserves_both_venues() {
    let fx = fixture(256 * 1024);
    let table = fx.table();
    let (_, _, object) = fx.pipe(table);
    let old = {
        let mut guard = fx.region.lock(object, &Spin).unwrap();
        let step = guard.pipe().unwrap().try_write(b"one authority");
        assert_eq!(step.result, Ok(13));
        guard.publish(step.wake);
        guard.storage()
    };
    let mut next = IpcPipeStorage {
        offset: 0,
        ring_bytes: 131072,
        pages: 32,
    };
    next.offset = fx.bump(next.footprint());
    let supplied = next;
    {
        let mut host = fx.region.lock(object, &Spin).unwrap();
        host.replace_pipe_storage(&mut next).unwrap();
        assert_eq!(next, old);
        assert_eq!(host.storage(), supplied);
        assert_eq!(
            host.pipe().unwrap().set_capacity(131072, 131072).result,
            Ok(131072)
        );
    }
    let mut guest = fx.region.lock(object, &EL1).unwrap();
    let mut output = [0; 13];
    assert_eq!(guest.pipe().unwrap().try_read(&mut output).result, Ok(13));
    assert_eq!(&output, b"one authority");
}

#[test]
fn el1_ipc_live_pipe_storage_replacement_refuses_overlap_and_bounds() {
    let fx = fixture(256 * 1024);
    let table = fx.table();
    let (_, _, object) = fx.pipe(table);
    let mut guard = fx.region.lock(object, &Spin).unwrap();
    let old = guard.storage();
    for mut invalid in [
        old,
        IpcPipeStorage {
            offset: old.offset + 4096,
            ..old
        },
        IpcPipeStorage {
            offset: fx.pool_len,
            ..old
        },
        IpcPipeStorage { offset: 1, ..old },
        IpcPipeStorage {
            pages: u64::MAX,
            ..old
        },
    ] {
        let before = invalid;
        assert_eq!(
            guard.replace_pipe_storage(&mut invalid),
            Err(IpcError::BadStorage)
        );
        assert_eq!(invalid, before);
        assert_eq!(guard.storage(), old);
    }
}

#[test]
fn el1_ipc_host_wake_index_coalesces_without_scanning_live_objects() {
    let fx = fixture(1 << 20);
    let objects: Vec<_> = (0..128)
        .map(|_| {
            fx.region
                .create_eventfd(0, EventMode::Counter, &Spin)
                .unwrap()
        })
        .collect();
    let object = objects[73];
    fx.region.subscribe_host(object, &Spin).unwrap();
    for _ in 0..8 {
        let mut guard = fx.region.lock(object, &Spin).unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(guard.publish(step.wake).host_owed);
    }
    let mut delivered = Vec::new();
    let visits = fx
        .region
        .drain_host_wake_candidates(|candidate| delivered.push(candidate));
    assert_eq!(visits, 1, "one indexed candidate despite 128 live objects");
    assert_eq!(delivered, [object]);
    assert!(fx.region.take_host_wake(object));
    assert_eq!(
        fx.region
            .drain_host_wake_candidates(|_| panic!("duplicate candidate")),
        0
    );
    // Publication during delivery stays indexed for the next bounded batch.
    let mut guard = fx.region.lock(object, &Spin).unwrap();
    let step = guard.eventfd().unwrap().try_write(1);
    guard.publish(step.wake);
    drop(guard);
    assert_eq!(
        fx.region.drain_host_wake_candidates(|candidate| {
            assert!(fx.region.take_host_wake(candidate));
            let mut guard = fx.region.lock(candidate, &Spin).unwrap();
            let step = guard.eventfd().unwrap().try_write(1);
            guard.publish(step.wake);
        }),
        1
    );
    assert_eq!(
        fx.region.drain_host_wake_candidates(|candidate| {
            assert_eq!(candidate, object);
            assert!(fx.region.take_host_wake(candidate));
        }),
        1
    );
}

/// The wedge census names, for every parked record, the object queue it is
/// linked on and that object's readiness: the discriminator between a lost
/// write (object empty) and a lost wake (readable, waiter still linked).
#[test]
fn el1_ipc_wait_census_names_each_waiter_object_and_its_readiness() {
    use carrick_sched_core::object_wait::OperationToken;
    use carrick_sched_core::{ThreadIdentity, ZoneTables};
    use std::string::String;
    let fx = fixture(1 << 20);
    let t = fx.table();
    let (_r, _w, pipe_object) = fx.pipe(t);
    let (_e, event_object) = fx.eventfd(t, 3, EventMode::Counter);
    {
        let mut g = fx.region.lock(pipe_object, &Spin).unwrap();
        assert_eq!(g.pipe().unwrap().try_write(b"hello").result, Ok(5));
    }
    let zone: Box<ZoneTables> = unsafe { Box::new_zeroed().assume_init() };
    let park = |object, tid| {
        let key = object_wait_key(object, pipe::WaitFor::Readable).unwrap();
        zone.bind_object_wait(key, &Spin).unwrap();
        let record = zone
            .alloc_record(ThreadIdentity {
                tid,
                serial: tid,
                mm: 7,
                file_table: 1,
                generation: 1,
                affinity: 0,
            })
            .unwrap();
        let guard = zone.object_wait(key, &Spin).unwrap();
        guard
            .park(
                guard.snapshot(),
                record,
                OperationToken::new(tid, 1).unwrap(),
            )
            .unwrap();
        key.index()
    };
    let pipe_queue = park(pipe_object, 11);
    let event_queue = park(event_object, 12);
    let mut zone_census = String::new();
    zone.write_census(&mut zone_census).unwrap();
    assert!(
        zone_census.contains(&std::format!(
            "zone object queue {pipe_queue}: generation=1 epoch=1 "
        )) && zone_census.contains("waiters=1 locked=false"),
        "{zone_census}"
    );
    assert!(
        zone_census.contains(&std::format!(
            "object wait: queue={event_queue} generation=1"
        )),
        "{zone_census}"
    );
    let mut census = String::new();
    write_ipc_wait_census(&zone, fx.region, &mut census).unwrap();
    assert!(
        census.contains(&std::format!(
            "ipc object {} (queue {pipe_queue} Readable): kind=pipe generation=0",
            pipe_object.index()
        )) && census.contains("unread=5 capacity=65536 readers=1 writers=1"),
        "{census}"
    );
    assert!(
        census.contains(&std::format!(
            "ipc object {} (queue {event_queue} Readable): kind=eventfd",
            event_object.index()
        )) && census.contains("counter=3 mode=Counter"),
        "{census}"
    );
    // A held object lock is reported, never waited for.
    let held = fx.region.lock(event_object, &Spin).unwrap();
    let mut busy = String::new();
    write_ipc_wait_census(&zone, fx.region, &mut busy).unwrap();
    assert!(busy.contains("state=<locked>"), "{busy}");
    drop(held);
}

/// The object and description stores are elastic: a region starts with one
/// published segment of each, an exhausted free list asks the growth venue
/// for more (`NoObjects` / `NeedsOfds`, never an errno by themselves), a
/// grown segment is resolved identically by both venues, and only the
/// zone-wide ceiling refuses (`ZoneLimit`, ENFILE).
#[test]
fn el1_ipc_object_and_description_stores_grow_by_segment() {
    let fx = fixture(1 << 20);
    assert_eq!(fx.region.object_count(), IPC_OBJECT_SEGMENT);
    assert_eq!(fx.region.ofd_count(), IPC_OFD_SEGMENT);
    let first: Vec<_> = (0..IPC_OBJECT_SEGMENT)
        .map(|_| {
            fx.region
                .create_eventfd(0, EventMode::Counter, &Spin)
                .unwrap()
        })
        .collect();
    assert_eq!(
        fx.region.create_eventfd(0, EventMode::Counter, &Spin),
        Err(IpcError::NoObjects)
    );
    assert_eq!(fx.region.grow_objects(), Ok(IPC_OBJECT_SEGMENT));
    let grown = fx
        .region
        .create_eventfd(9, EventMode::Counter, &Spin)
        .unwrap();
    assert_eq!(
        grown.index() as usize,
        IPC_OBJECT_SEGMENT,
        "lowest new record first"
    );
    // The other venue resolves the grown segment through the same mapping.
    let el1 = unsafe {
        IpcRegion::attach(
            (fx.region.dir as *const IpcDirectory).cast_mut(),
            IPC_DIRECTORY_BYTES,
            fx.region.pool,
            fx.pool_len as usize,
        )
    }
    .unwrap();
    assert_eq!(el1.lock(grown, &EL1).unwrap().eventfd().unwrap().value(), 9);
    assert_eq!(el1.object_count(), 2 * IPC_OBJECT_SEGMENT);
    // Descriptions: the first segment is exhausted, then grown.
    let t = fx
        .host()
        .create_table(1 << 16, &mut fx.descriptors(4096))
        .unwrap();
    let desc = |object| {
        Description::new(
            IpcBacking::EventFd { object }.encode(),
            AccessMode::ReadWrite,
            StatusFlags::default(),
        )
    };
    for (n, object) in first.iter().cycle().take(IPC_OFD_SEGMENT).enumerate() {
        assert_eq!(
            fx.host().open(t, Fd(0), desc(*object), false),
            Ok(Fd(n as i32))
        );
    }
    assert_eq!(
        fx.host().open(t, Fd(0), desc(grown), false),
        Err(fd::Error::NeedsOfds)
    );
    assert_eq!(fx.region.grow_ofds(), Ok(IPC_OFD_SEGMENT));
    let fd = fx.host().open(t, Fd(0), desc(grown), false).unwrap();
    assert_eq!(el1.fd(EL1).get(t, fd).unwrap().backing, desc(grown).backing);
    // Only the zone-wide ceiling refuses.
    while fx.region.object_count() < IPC_MAX_OBJECTS {
        assert_eq!(fx.region.grow_objects(), Ok(IPC_OBJECT_SEGMENT));
    }
    assert_eq!(fx.region.grow_objects(), Err(IpcError::ZoneLimit));
    while fx.region.ofd_count() < IPC_MAX_OFDS {
        assert_eq!(fx.region.grow_ofds(), Ok(IPC_OFD_SEGMENT));
    }
    assert_eq!(fx.region.grow_ofds(), Err(IpcError::ZoneLimit));
    // The last record of the zone is an ordinary record.
    let objects: Vec<_> =
        core::iter::from_fn(|| fx.region.create_eventfd(0, EventMode::Counter, &Spin).ok())
            .collect();
    assert_eq!(
        (
            objects.len(),
            fx.region.create_eventfd(0, EventMode::Counter, &Spin)
        ),
        (
            IPC_MAX_OBJECTS - IPC_OBJECT_SEGMENT - 1,
            Err(IpcError::NoObjects)
        )
    );
    let last = *objects.iter().max_by_key(|o| o.index()).unwrap();
    assert_eq!(last.index() as usize, IPC_MAX_OBJECTS - 1);
    assert!(el1.lock(last, &EL1).is_ok());
}

/// The owed-host-wake index scales with the object store: objects in any
/// segment (past the old 4096-object index) are indexed with three word
/// updates, and a boundary visits exactly the pending objects whatever the
/// live population.
#[test]
fn el1_ipc_host_wake_index_spans_every_segment_without_scanning() {
    let fx = fixture(1 << 20);
    while fx.region.object_count() < 5 * IPC_OBJECT_SEGMENT {
        fx.region.grow_objects().unwrap();
    }
    let objects: Vec<_> = (0..5 * IPC_OBJECT_SEGMENT)
        .map(|_| {
            fx.region
                .create_eventfd(0, EventMode::Counter, &Spin)
                .unwrap()
        })
        .collect();
    let pending = [objects[5], objects[4100], objects[3000], objects[4095]];
    for object in pending {
        fx.region.subscribe_host(object, &Spin).unwrap();
        let mut guard = fx.region.lock(object, &Spin).unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(guard.publish(step.wake).host_owed);
    }
    let mut delivered = Vec::new();
    let visits = fx
        .region
        .drain_host_wake_candidates(|candidate| delivered.push(candidate));
    assert_eq!(visits, pending.len(), "5120 live objects, 4 visited");
    delivered.sort_by_key(|o| o.index());
    let mut expected = pending.to_vec();
    expected.sort_by_key(|o| o.index());
    assert_eq!(delivered, expected);
    for object in pending {
        assert!(fx.region.take_host_wake(object));
    }
    assert_eq!(
        fx.region.drain_host_wake_candidates(|_| panic!("drained")),
        0
    );
}
