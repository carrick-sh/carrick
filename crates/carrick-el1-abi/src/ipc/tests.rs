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

fn fixture(pool_len: usize) -> Fixture {
    let dir: Box<core::mem::MaybeUninit<IpcDirectory>> = Box::new_zeroed();
    let dir = Box::into_raw(dir) as *mut IpcDirectory;
    let pool =
        unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
    let identity = IDENTITY.fetch_add(1, Ordering::Relaxed);
    let region = unsafe { IpcRegion::initialize(dir, pool, pool_len, identity) }.unwrap();
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
        "directory {} bytes",
        core::mem::size_of::<IpcDirectory>()
    );
}

#[test]
fn el1_ipc_region_attach_authenticates_the_header() {
    let len = 1 << 20;
    let dir = Box::into_raw(Box::<core::mem::MaybeUninit<IpcDirectory>>::new_zeroed())
        as *mut IpcDirectory;
    let pool = unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(len, 4096).unwrap()) };
    // Unpublished: zeroed memory never attaches.
    assert_eq!(
        unsafe { IpcRegion::attach(dir, pool, len) }.err(),
        Some(IpcError::BadRegion)
    );
    let host = unsafe { IpcRegion::initialize(dir, pool, len, 77) }.unwrap();
    assert_eq!(
        unsafe { IpcRegion::initialize(dir, pool, len, 78) }.err(),
        Some(IpcError::BadRegion)
    );
    assert_eq!(
        unsafe { IpcRegion::attach(dir, pool, len - 4096) }.err(),
        Some(IpcError::BadRegion)
    );
    assert_eq!(
        unsafe { IpcRegion::attach(dir.cast::<u8>().add(64).cast(), pool, len) }.err(),
        Some(IpcError::BadRegion),
        "misaligned directory"
    );
    let el1 = unsafe { IpcRegion::attach(dir, pool, len) }.unwrap();
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
        unsafe { IpcRegion::attach(dir, pool, len) }.err(),
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
    fx.region.unsubscribe_host(object, &Spin).unwrap();
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
    let record = &fx.region.dir.objects[object.index() as usize];
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
