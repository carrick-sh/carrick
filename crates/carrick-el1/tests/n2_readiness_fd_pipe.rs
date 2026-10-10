//! N2 L2, row 9: red ownership witnesses, not N2 acceptance.
//!
//! Contracts: kernel.el1.fd-single-owner and kernel.el1.ipc-lifecycle;
//! kernel.el1.creation-native-path registration remains driver-owned.
//! Linux authority: pipe(2), pipe(7), fork(2), clone(2), execve(2), close(2).
//! Two live task/MM identities share one production IPC region. Setup uses
//! the existing fd authority; operations under test use the real dispatcher,
//! or serve_ipc where the public dispatcher cannot inject UserCopy refusal.
//! No host syscall fallback is executed. A substrate suspension is not a
//! delivered Linux signal; N1 permits, signal delivery and executor progress
//! require driver bindings. See the accompanying L2 handoff.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_el1::file::UserCopy;
use carrick_el1::personality::ipc::{IpcServed, IpcVenue, MapTables, serve_ipc};
use carrick_el1::sched::{HardwareUserWord, Sched, ThreadCpu};
use carrick_el1::substrate::ipc::{PrefixCopy, StepStatus, transfer};
use carrick_el1::{Zone, dispatch_syscall_with_ipc};
use carrick_el1_abi::ipc::fd::{
    AccessMode, Description, Error as FdError, Fd, StatusFlags, TableId,
};
use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{
    End, Extent, HostResourceToken, IPC_DIRECTORY_BYTES, IPC_POOL_ALIGN, IpcBacking, IpcDirectory,
    IpcMmKey, IpcObjectHandle, IpcOpKind, IpcOperation, IpcPipeStorage, IpcRegion, IpcReleased,
    IpcTaskKey, IpcUserVa, WriteProgress, descriptor_extent_bytes, ipc_descriptor_area,
};
use carrick_el1_abi::ipc_tables::IpcTableMap;
use carrick_el1_abi::{
    Action, Counters, CurrentTask, El1TaskId, InotifyNameCache, SlotId, ThreadCtx, TrapFrame,
    ZoneTables,
};
use carrick_sched_core::BoundedSpin;
use std::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use std::cell::Cell;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;

const WAIT: BoundedSpin = BoundedSpin(64);
const PAGE: usize = 4096;
const VA: u64 = 0x4000_1000;
const PAIR_VA: u64 = VA + PAGE as u64 - 4;

// Only valid host buffers reach dispatch. Synthetic/faulting VAs are used
// exclusively with the injected copier at serve_ipc/transfer.
struct Arena {
    ptr: NonNull<u8>,
    layout: Layout,
}
impl Arena {
    fn new(bytes: usize) -> Self {
        let layout = Layout::from_size_align(bytes, 4096).unwrap();
        // SAFETY: valid nonzero layout, paired with dealloc in Drop.
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })
            .unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr, layout }
    }
}
impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: the arena owns this allocation; all region views borrow it.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

struct Fixture {
    directory: Arena,
    pool: Arena,
    next_ring: Cell<u64>,
    next_descriptors: Cell<u64>,
    map: Box<IpcTableMap>,
    zone: Box<ZoneTables>,
    tasks: [CurrentTask; 2],
    counters: Counters,
}
impl Fixture {
    fn new() -> Self {
        let directory = Arena::new(IPC_DIRECTORY_BYTES);
        let pool = Arena::new(32 << 20);
        // SAFETY: private, aligned zeroed allocations live for the whole
        // initialization; subsequent borrowed views use attach, never init.
        unsafe {
            IpcRegion::initialize(
                directory.ptr.as_ptr().cast(),
                directory.layout.size(),
                pool.ptr.as_ptr(),
                pool.layout.size(),
                42,
            )
            .unwrap();
        }
        // SAFETY: these ABI records specify all-zero empty representations.
        let zone = unsafe { Box::<ZoneTables>::new_zeroed().assume_init() };
        // SAFETY: all-zero is the empty IPC table map.
        let map = unsafe { Box::<IpcTableMap>::new_zeroed().assume_init() };
        let tasks = std::array::from_fn(|i| {
            let mm = [71, 83][i];
            let space = zone.spaces.publish_closed(mm, mm << 12, mm << 12).unwrap();
            zone.spaces.open(space);
            let slot = SlotId::from_index(i).unwrap();
            zone.drive(slot, i as u64 + 1);
            zone.publish_slot(slot, mm, None, 0);
            let task = CurrentTask::new();
            task.set(El1TaskId::from_linux_tid(101 + i as i32), 1, 501 + i as u64);
            task.zone_mm.store(mm, Ordering::Release);
            task.thread_serial.store(1101 + i as u64, Ordering::Release);
            task
        });
        let next_descriptors = Cell::new(ipc_descriptor_area(pool.layout.size() as u64).start);
        Self {
            directory,
            pool,
            next_ring: Cell::new(0),
            next_descriptors,
            map,
            zone,
            tasks,
            counters: Counters::default(),
        }
    }
    fn region(&self) -> IpcRegion<'_> {
        // SAFETY: matching initialized mappings; the returned view is bounded
        // by &self and cannot outlive either owned allocation.
        unsafe {
            IpcRegion::attach(
                self.directory.ptr.as_ptr().cast::<IpcDirectory>(),
                self.directory.layout.size(),
                self.pool.ptr.as_ptr(),
                self.pool.layout.size(),
            )
            .unwrap()
        }
    }
    fn extent(&self) -> Extent {
        let token = self.next_descriptors.get();
        self.next_descriptors
            .set((token + descriptor_extent_bytes(512)).next_multiple_of(IPC_POOL_ALIGN));
        Extent {
            token,
            capacity: 512,
        }
    }
    fn publish(&self, who: usize, table: TableId) {
        self.map
            .publish(
                self.tasks[who].file_table.load(Ordering::Acquire),
                table.to_raw(),
            )
            .unwrap();
    }
    fn table(&self, who: usize) -> TableId {
        let table = self
            .region()
            .fd(WAIT)
            .create_table(512, &mut self.extent())
            .unwrap();
        self.publish(who, table);
        table
    }
    fn pipe(&self, table: TableId, cloexec: bool) -> ([Fd; 2], IpcObjectHandle) {
        let region = self.region();
        let mut retired = None;
        let object = region.create_pipe(PAGE, &mut retired, &WAIT).unwrap();
        assert_eq!(retired, None);
        let offset = self.next_ring.get();
        self.next_ring
            .set((offset + PAGE as u64 + 8).next_multiple_of(IPC_POOL_ALIGN));
        region
            .lock(object, &WAIT)
            .unwrap()
            .provide_pipe_storage(&mut IpcPipeStorage {
                offset,
                ring_bytes: PAGE as u64,
                pages: 1,
            })
            .unwrap();
        let fd = region.fd(WAIT);
        let reader = fd
            .create_pinned(Description::new(
                IpcBacking::Pipe {
                    object,
                    end: End::Reader,
                }
                .encode(),
                AccessMode::ReadOnly,
                StatusFlags::default(),
            ))
            .unwrap();
        let writer = fd
            .create_pinned(Description::new(
                IpcBacking::Pipe {
                    object,
                    end: End::Writer,
                }
                .encode(),
                AccessMode::WriteOnly,
                StatusFlags::default(),
            ))
            .unwrap();
        let pair = fd
            .transaction(table)
            .unwrap()
            .install_pair(Fd(0), [&reader, &writer], cloexec)
            .unwrap();
        assert_eq!(fd.unpin(reader), Ok(None));
        assert_eq!(fd.unpin(writer), Ok(None));
        (pair, object)
    }
    fn dispatch(&self, who: usize, nr: u64, args: [u64; 3]) -> (Action, TrapFrame) {
        let region = self.region().for_el1_slot(who as u32);
        let tables = MapTables(&self.map);
        let venue = IpcVenue {
            region,
            tables: &tables,
        };
        let mut cpu = NoSwitch;
        let mut frame = frame(who, nr, args);
        let action = dispatch_syscall_with_ipc(
            &mut frame,
            &self.counters,
            &self.tasks,
            &[],
            &[],
            &[],
            &[],
            &InotifyNameCache::new(),
            Some(Zone {
                tables: &self.zone,
                cpu: &mut cpu,
                user: &HardwareUserWord,
            }),
            Some(&venue),
            |_| core::ptr::null_mut(),
        );
        (action, frame)
    }
    fn forwarded(&self, nr: usize) -> u64 {
        self.counters.forwarded[nr].load(Ordering::Relaxed)
    }
}

fn frame(who: usize, nr: u64, args: [u64; 3]) -> TrapFrame {
    let mut frame = TrapFrame {
        slot: who as u64,
        elr: 0x8004,
        ..TrapFrame::default()
    };
    frame.x[..3].copy_from_slice(&args);
    frame.x[8] = nr;
    frame
}

/// No test waits or switches: accidental scheduling fails rather than hanging.
struct NoSwitch;
impl ThreadCpu for NoSwitch {
    fn save(&mut self, _: &TrapFrame, _: &mut ThreadCtx) {
        panic!("unexpected save")
    }
    fn load(&mut self, _: &mut TrapFrame, _: &ThreadCtx) {
        panic!("unexpected load")
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        panic!("unexpected translation")
    }
    fn invalidate_asid(&mut self, _: u64) {
        panic!("unexpected invalidation")
    }
    fn now(&self) -> u64 {
        1
    }
    fn freq(&self) -> u64 {
        24_000_000
    }
    fn set_timer(&mut self, _: Option<u64>) {}
    fn send_sgi(&mut self, _: u64) {
        panic!("unexpected wake")
    }
    fn ack_irq(&mut self) -> u32 {
        panic!("unexpected IRQ")
    }
    fn end_irq(&mut self, _: u32) {
        panic!("unexpected IRQ")
    }
    fn wait_for_interrupt(&mut self) {
        panic!("unexpected wait")
    }
    fn spin(&mut self) {
        panic!("unexpected spin")
    }
    fn own_sgi_target(&self) -> u64 {
        1
    }
}

#[test]
#[ignore = "N2 red witness: row 9: pipe2 pair creation still forwards"]
fn pipe2_owns_pair_publication_at_1_8_64() {
    let mut observed = Vec::new();
    for n in [1, 8, 64] {
        let f = Fixture::new();
        let tables = [f.table(0), f.table(1)];
        let mut results = Vec::new();
        for (who, table) in tables.into_iter().enumerate() {
            // Stdio occupies the same authority, so pipe2 must choose 3,4...
            for fd in 0..3 {
                let backing = IpcBacking::Host(HostResourceToken::new(1 + fd).unwrap());
                assert_eq!(
                    f.region()
                        .fd(WAIT)
                        .open(
                            table,
                            Fd(0),
                            Description::new(
                                backing.encode(),
                                AccessMode::ReadWrite,
                                StatusFlags::default()
                            ),
                            false
                        )
                        .unwrap(),
                    Fd(fd as i32)
                );
            }
            for _ in 0..n {
                let mut out = [-1i32; 2];
                let (action, frame) = f.dispatch(who, 59, [out.as_mut_ptr() as u64, 0x80000, 0]);
                results.push((who, action, frame.x[0], out));
            }
        }
        observed.push(f.forwarded(59));
        println!("pair n={n}: pipe2_forwards={}", f.forwarded(59));
        // Check successful publications too; these assertions remain after
        // the missing route is implemented, without accepting a bare Served.
        for (index, (who, action, result, pair)) in results.into_iter().enumerate() {
            if action == Action::Served {
                assert_eq!(result, 0);
                assert_eq!(
                    pair,
                    [3 + 2 * (index % n) as i32, 4 + 2 * (index % n) as i32]
                );
                let region = f.region();
                let fd = region.fd(WAIT);
                for number in pair {
                    assert_eq!(fd.getfd(tables[who], Fd(number)), Ok(true));
                }
                let reader = IpcBacking::decode(fd.get(tables[who], Fd(pair[0])).unwrap().backing);
                let writer = IpcBacking::decode(fd.get(tables[who], Fd(pair[1])).unwrap().backing);
                let Some(IpcBacking::Pipe {
                    object,
                    end: End::Reader,
                }) = reader
                else {
                    panic!("reader")
                };
                assert_eq!(
                    writer,
                    Some(IpcBacking::Pipe {
                        object,
                        end: End::Writer
                    })
                );
            } else {
                assert_eq!(action, Action::Forward);
            }
        }
    }
    assert_eq!(
        observed,
        [0, 0, 0],
        "row 9: EL1 must own pipe2, including stdio-aware slot selection"
    );
}

/// First fd fits, second does not. Exact copy refuses the whole pair without
/// touching the sentinel. No inaccessible host address is dereferenced.
struct RefusePair {
    word: [u8; 4],
    attempts: usize,
}
impl UserCopy for RefusePair {
    fn copy_out(&mut self, va: u64, src: &[u8]) -> bool {
        self.attempts += 1;
        if va != PAIR_VA || src.len() > self.word.len() {
            return false;
        }
        self.word[..src.len()].copy_from_slice(src);
        true
    }
    fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
        panic!("pipe2 must not read user bytes")
    }
}

#[test]
#[ignore = "N2 red witness: row 9: pipe2 copyout refusal has no EL1 owner"]
fn pair_copyout_refusal_preserves_both_tables_at_1_8_64() {
    let mut forwards = Vec::new();
    for n in [1usize, 8, 64] {
        let f = Fixture::new();
        let tables = [f.table(0), f.table(1)];
        for table in tables {
            for _ in 0..n {
                f.pipe(table, false);
            }
        }
        let region = f.region();
        let map = MapTables(&f.map);
        let venue = IpcVenue {
            region,
            tables: &map,
        };
        let mut forwarded = 0;
        for (who, table) in tables.into_iter().enumerate() {
            let before: Vec<_> = (0..2 * n)
                .map(|i| region.fd(WAIT).get(table, Fd(i as i32)).unwrap())
                .collect();
            let mut copy = RefusePair {
                word: [0xa5; 4],
                attempts: 0,
            };
            let mut frame = frame(who, 59, [PAIR_VA, 0, 0]);
            let mut cpu = NoSwitch;
            let mut sched = Sched {
                zone: &f.zone,
                slot: SlotId::from_index(who).unwrap(),
                task: &f.tasks[who],
                cpu: &mut cpu,
                user: &HardwareUserWord,
                counters: &f.counters,
            };
            let action = serve_ipc(&mut sched, &mut frame, &venue, &mut copy);
            forwarded += usize::from(action == IpcServed::Forward);
            assert_eq!(
                copy.word, [0xa5; 4],
                "first fd must not leak on second-fd refusal"
            );
            for (i, description) in before.into_iter().enumerate() {
                assert_eq!(region.fd(WAIT).get(table, Fd(i as i32)), Ok(description));
            }
            assert_eq!(
                region.fd(WAIT).get(table, Fd((2 * n) as i32)),
                Err(FdError::BadFd)
            );
            assert_eq!(
                region.fd(WAIT).get(table, Fd((2 * n + 1) as i32)),
                Err(FdError::BadFd)
            );
            if action != IpcServed::Forward {
                assert_eq!(action, IpcServed::Returned { switched: false });
                assert_eq!(frame.x[0] as i64, -14, "EFAULT = 14");
                assert!(copy.attempts > 0, "exercise the refused copy");
            }
        }
        println!("copyout n={n}: semantic_forwards={forwarded}");
        forwards.push(forwarded);
    }
    assert_eq!(
        forwards,
        [0, 0, 0],
        "row 9: refusal must complete at the admitted owner"
    );
}

#[test]
#[ignore = "N2 red witness: row 9: final close still needs host descriptor edits"]
fn close_after_fork_and_exec_keeps_pins_and_releases_once_at_1_8_64() {
    let mut forwards = Vec::new();
    for n in [1, 8, 64] {
        let f = Fixture::new();
        let a = f.table(0);
        let pairs: Vec<_> = (0..n).map(|_| f.pipe(a, false)).collect();
        let region = f.region();
        let fd = region.fd(WAIT);
        // CLONE_FILES shares the table. Exec must first unshare, then remove
        // CLOEXEC in its private copy. These public-core calls are setup,
        // not a claim that clone/exec are routed to EL1 today.
        f.publish(1, a);
        for (pair, _) in &pairs {
            fd.setfd(a, pair[0], true).unwrap();
        }
        let b = fd.fork(a, &mut f.extent()).unwrap();
        f.publish(1, b);
        fd.exec(b, |_| panic!("A still owns each CLOEXEC reader"))
            .unwrap();
        let mut pins = Vec::new();
        for (pair, object) in &pairs {
            assert!(fd.get(a, pair[0]).is_ok());
            assert_eq!(fd.get(b, pair[0]), Err(FdError::BadFd));
            let (pin, description) = fd.pin(a, pair[1]).unwrap();
            assert_eq!(fd.get(b, pair[1]), Ok(description));
            assert_eq!(fd.holds(&pin), Ok((2, 1)));
            // Positive dispatcher admission control on both live MM slots.
            let mut byte = [0x5a];
            for who in 0..2 {
                let (action, result) =
                    f.dispatch(who, 64, [pair[1].0 as u64, byte.as_mut_ptr() as u64, 1]);
                assert_eq!((action, result.x[0]), (Action::Served, 1));
            }
            for who in 0..2 {
                f.dispatch(who, 57, [pair[1].0 as u64, 0, 0]);
            }
            pins.push((pin, *object));
        }
        println!("close n={n}: close_forwards={}", f.forwarded(57));
        forwards.push(f.forwarded(57));
        if f.forwarded(57) == 0 {
            for (pin, object) in pins {
                assert_eq!(fd.holds(&pin), Ok((0, 1)), "only the continuation remains");
                let description = fd.unpin(pin).unwrap().expect("one final writer release");
                assert!(matches!(
                    region.release_backing(description.backing, &WAIT),
                    Ok(IpcReleased::Object { freed: false, .. })
                ));
                let mut guard = region.lock(object, &WAIT).unwrap();
                let mut pipe = guard.pipe().unwrap();
                assert_eq!(pipe.references(End::Writer), 0);
                assert_eq!(
                    pipe.read_with(2, |bytes| {
                        assert_eq!(bytes, [0x5a; 2]);
                        2
                    })
                    .result,
                    Ok(2)
                );
                assert_eq!(
                    pipe.read_with(1, |_| panic!("EOF copies nothing")).result,
                    Ok(0)
                );
            }
        }
    }
    assert_eq!(
        forwards,
        [0, 0, 0],
        "row 9: close must remove both owners' slots without host edits"
    );
}

struct Bytes {
    source: Vec<u8>,
    visits: Vec<u8>,
}
impl UserCopy for Bytes {
    fn copy_in(&mut self, dst: &mut [u8], va: u64) -> bool {
        let at = usize::try_from(va - VA).unwrap();
        dst.copy_from_slice(&self.source[at..at + dst.len()]);
        for count in &mut self.visits[at..at + dst.len()] {
            *count += 1;
        }
        true
    }
    fn copy_out(&mut self, _: u64, _: &[u8]) -> bool {
        panic!("writer only")
    }
}

#[test]
#[ignore = "N2 red witness: row 9: final reader close is not owned after partial-write resume"]
fn three_page_resume_survives_close_reuse_then_requires_final_close_at_1_8_64() {
    let mut forwards = Vec::new();
    for n in [1, 8, 64] {
        let f = Fixture::new();
        let a = f.table(0);
        let pairs: Vec<_> = (0..n).map(|_| f.pipe(a, false)).collect();
        let region = f.region();
        let fd = region.fd(WAIT);
        let b = fd.fork(a, &mut f.extent()).unwrap();
        f.publish(1, b);
        let mut copied = 0;
        for (pair, object) in pairs {
            let (pin, _) = fd.pin(a, pair[1]).unwrap();
            let mut operation = IpcOperation {
                kind: IpcOpKind::PipeWrite,
                pin: pin.into_raw(),
                object: object.to_raw(),
                task: IpcTaskKey(101),
                mm: IpcMmKey(71),
                buf: IpcUserVa(VA),
                progress: WriteProgress::new((3 * PAGE) as u64),
                ..IpcOperation::EMPTY
            };
            let token = region.begin_operation(operation).unwrap();
            let source: Vec<_> = (0..3 * PAGE)
                .map(|i| (i / PAGE * 37 + i % 251) as u8)
                .collect();
            let mut bytes = Bytes {
                visits: vec![0; source.len()],
                source,
            };
            let mut received = Vec::new();
            for page in 0..3 {
                let mut guard = region.lock(object, &WAIT).unwrap();
                let mut copy = PrefixCopy::new(&mut bytes);
                let (status, _) = transfer(&mut guard, &mut operation, &mut copy).unwrap();
                copied += copy.copied;
                assert_eq!(
                    status,
                    if page == 2 {
                        StepStatus::Complete
                    } else {
                        StepStatus::Blocked(WaitFor::Writable)
                    }
                );
                assert_eq!(operation.progress.written, ((page + 1) * PAGE) as u64);
                drop(guard);
                region.update_operation(&token, operation).unwrap();
                if page == 0 {
                    // Numeric close/reuse is an existing-core control. The
                    // token alone keeps the old writer, never the new fd.
                    assert_eq!(fd.close(a, pair[1]), Ok(None));
                    assert_eq!(fd.close(b, pair[1]), Ok(None));
                    let (replacement, new_object) = f.pipe(a, false);
                    assert_eq!(replacement[0], pair[1]);
                    assert_ne!(new_object, object);
                }
                let mut guard = region.lock(object, &WAIT).unwrap();
                assert_eq!(
                    guard
                        .pipe()
                        .unwrap()
                        .read_with(PAGE, |chunk| {
                            received.extend_from_slice(chunk);
                            chunk.len()
                        })
                        .result,
                    Ok(PAGE)
                );
                operation = region.operation(&token).unwrap();
            }
            assert_eq!(received, bytes.source);
            assert!(
                bytes.visits.iter().all(|n| *n == 1),
                "no source byte copied twice"
            );
            let operation = region.finish_operation(token).unwrap();
            let description = fd
                .unpin(carrick_el1_abi::ipc::OfdPin::from_raw(operation.pin))
                .unwrap()
                .unwrap();
            region.release_backing(description.backing, &WAIT).unwrap();
            assert_eq!(
                region
                    .lock(object, &WAIT)
                    .unwrap()
                    .pipe()
                    .unwrap()
                    .read_with(1, |_| panic!("EOF must not copy"))
                    .result,
                Ok(0)
            );
            for who in 0..2 {
                f.dispatch(who, 57, [pair[0].0 as u64, 0, 0]);
            }
            if f.forwarded(57) == 0 {
                assert!(
                    region.lock(object, &WAIT).is_err(),
                    "last close retires object"
                );
            }
        }
        assert_eq!(copied, n * 3 * PAGE, "exact linear byte budget");
        println!(
            "resume n={n}: copied={copied}, final_close_forwards={}",
            f.forwarded(57)
        );
        forwards.push(f.forwarded(57));
    }
    assert_eq!(
        forwards,
        [0, 0, 0],
        "row 9: resumed pipe lifetime must end in EL1"
    );
}

#[test]
#[ignore = "N2 red witness: row 9/10: EPIPE and SIGPIPE still require host semantic forwarding"]
fn broken_pipe_requires_owner_completion_at_1_8_64() {
    let mut forwards = Vec::new();
    for n in [1, 8, 64] {
        let f = Fixture::new();
        let tables = [f.table(0), f.table(1)];
        for (who, table) in tables.into_iter().enumerate() {
            for _ in 0..n {
                let (pair, object) = f.pipe(table, false);
                let region = f.region();
                // Three-page writer has already delivered one page when
                // its final reader disappears. Preserve that prefix and the
                // personality's SIGPIPE decision; no remaining byte is read.
                let mut progress = WriteProgress::new((3 * PAGE) as u64);
                assert_eq!(
                    region
                        .lock(object, &WAIT)
                        .unwrap()
                        .pipe()
                        .unwrap()
                        .write_progress(&mut progress, |at, bytes| {
                            assert_eq!(at, 0);
                            bytes.fill(0x5a);
                            bytes.len()
                        })
                        .result,
                    Ok(PAGE)
                );
                let release = region.fd(WAIT).close(table, pair[0]).unwrap().unwrap();
                region.release_backing(release.backing, &WAIT).unwrap();
                let step = region
                    .lock(object, &WAIT)
                    .unwrap()
                    .pipe()
                    .unwrap()
                    .write_progress(&mut progress, |_, _| {
                        panic!("broken pipe must not consume source")
                    });
                assert_eq!(progress.written, PAGE as u64);
                assert!(
                    step.broken_pipe_signal(),
                    "substrate must request personality SIGPIPE policy"
                );
                let mut byte = [0x5a];
                let (action, result) =
                    f.dispatch(who, 64, [pair[1].0 as u64, byte.as_mut_ptr() as u64, 1]);
                if action != Action::Forward {
                    assert!(matches!(action, Action::Served | Action::ServedWithWork));
                    assert_eq!(result.x[0] as i64, -32, "EPIPE = 32");
                }
            }
        }
        println!("broken n={n}: write_forwards={}", f.forwarded(64));
        forwards.push(f.forwarded(64));
    }
    assert_eq!(
        forwards,
        [0, 0, 0],
        "row 9/10: broken pipe policy must not forward"
    );
}

#[test]
#[ignore = "N2 red witness: row 9: close does not own all backing kinds including stdio"]
fn close_owns_one_namespace_for_all_backings_at_1_8_64() {
    let mut forwards = Vec::new();
    for n in [1, 8, 64] {
        let f = Fixture::new();
        let tables = [f.table(0), f.table(1)];
        let region = f.region();
        let fd = region.fd(WAIT);
        for (who, table) in tables.into_iter().enumerate() {
            let mut numbers = Vec::new();
            for stdio in 0..3 {
                let number = fd
                    .open(
                        table,
                        Fd(0),
                        Description::new(
                            IpcBacking::Host(HostResourceToken::new(1 + stdio).unwrap()).encode(),
                            AccessMode::ReadWrite,
                            StatusFlags::default(),
                        ),
                        false,
                    )
                    .unwrap();
                assert_eq!(number, Fd(stdio as i32));
                numbers.push(number);
            }
            for _ in 0..n {
                let (pair, _) = f.pipe(table, false);
                numbers.extend(pair);
                let event = region
                    .create_eventfd(0, carrick_el1_abi::ipc::EventMode::Counter, &WAIT)
                    .unwrap();
                let epoll = region.create_epoll(&WAIT).unwrap();
                for backing in [
                    IpcBacking::EventFd { object: event },
                    IpcBacking::Epoll { object: epoll },
                ] {
                    numbers.push(
                        fd.open(
                            table,
                            Fd(0),
                            Description::new(
                                backing.encode(),
                                AccessMode::ReadWrite,
                                StatusFlags::default(),
                            ),
                            false,
                        )
                        .unwrap(),
                    );
                }
            }
            for number in numbers {
                // A retained pin lets physical host-resource release remain
                // separate from Linux descriptor selection/removal. EL1 can
                // close even stdio without executing a real host close here.
                let (pin, original) = fd.pin(table, number).unwrap();
                let (action, result) = f.dispatch(who, 57, [number.0 as u64, 0, 0]);
                assert_eq!(fd.pinned(&pin), Ok(original));
                if action != Action::Forward {
                    assert_eq!((action, result.x[0]), (Action::Served, 0));
                    assert_eq!(fd.get(table, number), Err(FdError::BadFd));
                    assert_eq!(fd.holds(&pin), Ok((0, 1)));
                    let release = fd.unpin(pin).unwrap().unwrap();
                    // Fixture consumes the one physical-release obligation.
                    region.release_backing(release.backing, &WAIT).unwrap();
                } else {
                    assert_eq!(fd.unpin(pin), Ok(None));
                }
            }
        }
        println!("backings n={n}: close_forwards={}", f.forwarded(57));
        forwards.push(f.forwarded(57));
    }
    assert_eq!(
        forwards,
        [0, 0, 0],
        "row 9: one close owner for stdio, pipes, eventfd and epoll"
    );
}
