//! Native fork children's `ppoll` through the production dispatch entry
//! (#894 slice 1): in-zone sets are served in ring; a set that would block
//! or names a host-backed description keeps its route before any effect.
//!
//! Child lifecycle pages sit in the EL1 metadata window (0x2D_0800_0000),
//! which macOS 27 refuses to map, so these run on Linux hosts (`just test`
//! and the Linux CI lanes), like `native_ipc_wake_tests`.
use super::*;
use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
use carrick_personality_linux::dispatch::CompletionRoute;
use std::cell::Cell;
use std::sync::Arc;

const SYS_PPOLL: u64 = 73;
const SYS_READ: u64 = 63;
const SYS_WRITE: u64 = 64;
const SYS_CLOSE: u64 = 57;
const SYS_DUP3: u64 = 24;
const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;
/// A `revents` value no Linux result produces: proves nothing was written.
const UNTOUCHED: i16 = 0x7777;

/// Linux `struct pollfd`, as the guest lays it out.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GuestPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

fn set(entries: &[(i32, i16)]) -> Vec<GuestPollFd> {
    entries
        .iter()
        .map(|&(fd, events)| GuestPollFd {
            fd,
            events,
            revents: UNTOUCHED,
        })
        .collect()
}

/// Guest memory for one call's timespec and mask.
struct Args {
    timespec: Box<[i64; 2]>,
    mask: Box<u64>,
}
impl Args {
    fn timeout(seconds: i64, nanoseconds: i64) -> Self {
        Self {
            timespec: Box::new([seconds, nanoseconds]),
            mask: Box::new(0),
        }
    }
    fn timespec(&self) -> u64 {
        self.timespec.as_ptr() as u64
    }
}

/// What a test body may do: run a call in one live native child and switch
/// the slot between the two children.
struct Children<'a> {
    run: &'a dyn Fn(usize, u64, [u64; 5]) -> (CompletionRoute, i64),
    switch: &'a dyn Fn(usize),
    counters: &'a carrick_el1_abi::Counters,
}
impl Children<'_> {
    fn ppoll(
        &self,
        child: usize,
        fds: &mut [GuestPollFd],
        timespec: u64,
        mask: u64,
        sigsetsize: u64,
    ) -> (CompletionRoute, i64) {
        (self.switch)(child);
        (self.run)(
            child,
            SYS_PPOLL,
            [
                fds.as_mut_ptr() as u64,
                fds.len() as u64,
                timespec,
                mask,
                sigsetsize,
            ],
        )
    }
    fn call(&self, child: usize, nr: u64, args: [u64; 3]) -> i64 {
        (self.switch)(child);
        let (route, result) = (self.run)(child, nr, [args[0], args[1], args[2], 0, 0]);
        assert!(
            matches!(route, CompletionRoute::Served | CompletionRoute::WithWork),
            "nr {nr} must complete in ring, got {route:?}"
        );
        result
    }
    fn forwarded(&self) -> u64 {
        self.counters.forwarded[SYS_PPOLL as usize].load(Ordering::Relaxed)
    }
    fn served(&self) -> u64 {
        self.counters.served[SYS_PPOLL as usize].load(Ordering::Relaxed)
    }
}

/// The root holds pipe A (reader 3, writer 4), pipe B (reader 6, writer 7)
/// and a host-backed file at 5, all inherited by two production forks; the
/// root then closes its own copies of the pipe ends, so the two children
/// hold the only references.
fn with_native_children(body: impl FnOnce(&Children<'_>)) {
    let fixture = Fixture::new(0x10000, asid(1));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let task = CurrentTask::new();
    let runtime = NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
        source,
        &fixture.task,
        fixture.page,
        fixture.control,
        fixture.address,
        fixture.address,
        parked,
    )
    .unwrap();
    let owner = Arc::new(
        HostIpc::with_limits(
            1 << 20,
            IpcLimits {
                descriptions: carrick_el1_abi::ipc::IPC_OFD_SEGMENT,
                ..IpcLimits::ZONE
            },
        )
        .unwrap(),
    );
    let table = HostTable::create(Arc::clone(&owner), 64, 16).unwrap();
    let nonblock = fd::StatusFlags {
        nonblock: true,
        ..fd::StatusFlags::default()
    };
    let mut ends = Vec::new();
    for (read_fd, write_fd) in [(3, 4), (6, 7)] {
        let object = owner.create_pipe(65536).unwrap();
        for (end, access, number) in [
            (End::Reader, fd::AccessMode::ReadOnly, read_fd),
            (End::Writer, fd::AccessMode::WriteOnly, write_fd),
        ] {
            let description = owner
                .admit_description(fd::Description::new(
                    IpcBacking::Pipe { object, end }.encode(),
                    access,
                    nonblock,
                ))
                .unwrap();
            description
                .install(table.id(), fd::Fd(number), false)
                .unwrap();
            ends.push(description);
        }
    }
    let host_file = carrick_kernel::dispatch::NativeFileWitness::new(&table, fd::Fd(5)).unwrap();

    let region = Box::leak(carrick_test_support::TestEl1Region::zeroed());
    // SAFETY: aligned ABI storage retained for all inherited table bindings.
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish(5, table.id().to_raw()).unwrap();
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.ipc = Some((Arc::clone(&owner), map));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_bindings: [_; 2] = core::array::from_fn(|_| {
        let mut entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("native fork must return");
        };
        assert!(result.raw() > 0, "fork errno number: {}", -result.raw());
        let child = runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap();
        runtime.task_binding(child).unwrap()
    });
    drop(ends);
    for number in [3, 4, 6, 7] {
        table.close(fd::Fd(number)).unwrap();
    }
    let parent_binding = runtime.task_binding(parent).unwrap();
    fixture
        .zone
        .requeue_preempted(fixture.slot, parent_binding.record.id);

    let tables = crate::ipc::MapTables(map);
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let run = |idx: usize, nr: u64, args: [u64; 5]| -> (CompletionRoute, i64) {
        let mut cpu = crate::sched::FakeCpu::default();
        let mut svc = Aarch64NativeProcessService::with_crossing(
            &task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            &crossing,
        )
        .with_words(&words);
        let child_ctx =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, child_bindings[idx].address);
        let mut entry = runtime.enter(source, &task, child_ctx, &mut svc).unwrap();
        let mut frame = carrick_el1_abi::TrapFrame {
            slot: fixture.slot.index() as u64,
            elr: 0x4004,
            esr: 0x15 << 26,
            ..Default::default()
        };
        frame.x[8] = nr;
        frame.x[..5].copy_from_slice(&args);
        let route = super::super::dispatch::dispatch_syscall_with_native(
            &mut frame,
            &counters,
            core::slice::from_ref(&task),
            crossing.fd_map(),
            &[],
            crossing.open_table(),
            &[],
            &names,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            Some(&venue),
            Some(&fixture),
            Some(&mut entry),
            Some(source),
            None,
            |_| core::ptr::null_mut(),
        );
        (route, frame.x[0] as i64)
    };
    let current = Cell::new(None::<usize>);
    let switch = |to: usize| {
        if current.get() == Some(to) {
            return;
        }
        if let Some(from) = current.get() {
            fixture
                .zone
                .requeue_preempted(fixture.slot, child_bindings[from].record.id);
        }
        activate_target(source, &task, &child_bindings[to]);
        current.set(Some(to));
    };
    body(&Children {
        run: &run,
        switch: &switch,
        counters: &counters,
    });
    drop(host_file);
}

#[test]
fn serial_host_native_child_ppoll_empty_pipe_zero_timeout_is_served_in_ring() {
    with_native_children(|children| {
        let args = Args::timeout(0, 0);
        let mut fds = set(&[(3, POLLIN)]);
        let (route, result) = children.ppoll(0, &mut fds, args.timespec(), 0, 0);
        assert_eq!(
            (route, result, children.forwarded()),
            (CompletionRoute::Served, 0, 0),
            "an empty pipe with a zero timeout is ready-count 0 in ring"
        );
        assert_eq!(fds[0].revents, 0);
        assert_eq!(children.served(), 1);
    });
}

#[test]
fn serial_host_native_child_ppoll_rust_std_stdio_shape_and_closed_fd() {
    with_native_children(|children| {
        // Rust std's startup probe: fds 0-2 with events 0 and timeout 0.
        assert_eq!(children.call(0, SYS_DUP3, [3, 0, 0]), 0);
        assert_eq!(children.call(0, SYS_DUP3, [4, 1, 0]), 1);
        assert_eq!(children.call(0, SYS_DUP3, [4, 2, 0]), 2);
        let args = Args::timeout(0, 0);
        let mut fds = set(&[(0, 0), (1, 0), (2, 0)]);
        assert_eq!(
            children.ppoll(0, &mut fds, args.timespec(), 0, 0),
            (CompletionRoute::Served, 0)
        );
        assert!(fds.iter().all(|entry| entry.revents == 0));
        // A closed stdio descriptor is POLLNVAL and counts as ready.
        assert_eq!(children.call(0, SYS_CLOSE, [2, 0, 0]), 0);
        let mut fds = set(&[(0, 0), (1, 0), (2, 0)]);
        assert_eq!(
            children.ppoll(0, &mut fds, args.timespec(), 0, 0),
            (CompletionRoute::Served, 1)
        );
        assert_eq!(
            fds.iter().map(|entry| entry.revents).collect::<Vec<_>>(),
            [0, 0, POLLNVAL]
        );
    });
}

#[test]
fn serial_host_native_child_ppoll_reports_written_byte_and_writable_end() {
    with_native_children(|children| {
        let byte = Box::new(*b"x");
        assert_eq!(children.call(0, SYS_WRITE, [4, byte.as_ptr() as u64, 1]), 1);
        let args = Args::timeout(0, 0);
        let mut fds = set(&[(3, POLLIN), (4, POLLOUT), (3, POLLOUT)]);
        assert_eq!(
            children.ppoll(1, &mut fds, args.timespec(), 0, 0),
            (CompletionRoute::Served, 2),
            "the sibling child sees the byte; a reader reports no POLLOUT"
        );
        assert_eq!(
            fds.iter().map(|entry| entry.revents).collect::<Vec<_>>(),
            [POLLIN, POLLOUT, 0]
        );
        // A finite timeout with a ready entry completes at once too.
        let finite = Args::timeout(5, 0);
        let mut fds = set(&[(3, POLLIN)]);
        assert_eq!(
            children.ppoll(1, &mut fds, finite.timespec(), 0, 0),
            (CompletionRoute::Served, 1)
        );
        let sink = Box::new([0u8; 8]);
        assert_eq!(children.call(1, SYS_READ, [3, sink.as_ptr() as u64, 8]), 1);
    });
}

#[test]
fn serial_host_native_child_ppoll_hangup_and_error_after_the_peer_closes() {
    with_native_children(|children| {
        // Every writer of pipe A and every reader of pipe B closes.
        assert_eq!(children.call(0, SYS_CLOSE, [4, 0, 0]), 0);
        assert_eq!(children.call(1, SYS_CLOSE, [4, 0, 0]), 0);
        assert_eq!(children.call(0, SYS_CLOSE, [6, 0, 0]), 0);
        assert_eq!(children.call(1, SYS_CLOSE, [6, 0, 0]), 0);
        let args = Args::timeout(0, 0);
        let mut fds = set(&[(3, 0), (3, POLLIN), (7, 0), (7, POLLOUT)]);
        assert_eq!(
            children.ppoll(0, &mut fds, args.timespec(), 0, 0),
            (CompletionRoute::Served, 4)
        );
        assert_eq!(
            fds.iter().map(|entry| entry.revents).collect::<Vec<_>>(),
            [POLLHUP, POLLHUP, POLLERR, POLLOUT | POLLERR],
            "HUP and ERR are reported even when not requested"
        );
    });
}

#[test]
fn serial_host_native_child_ppoll_that_would_block_keeps_its_route_before_any_effect() {
    with_native_children(|children| {
        let finite = Args::timeout(1, 0);
        for (timespec, label) in [(finite.timespec(), "finite"), (0, "NULL")] {
            let before = children.forwarded();
            let mut fds = set(&[(3, POLLIN), (7, 0)]);
            let (route, _) = children.ppoll(0, &mut fds, timespec, 0, 0);
            assert_eq!(route, CompletionRoute::Forward, "{label} timeout");
            assert_eq!(children.forwarded(), before + 1, "{label} timeout");
            assert!(
                fds.iter().all(|entry| entry.revents == UNTOUCHED),
                "{label} timeout wrote revents: {fds:?}"
            );
        }
        // An empty set is a pure sleep: the same route.
        let mut fds = set(&[]);
        assert_eq!(
            children.ppoll(0, &mut fds, finite.timespec(), 0, 0).0,
            CompletionRoute::Forward
        );
        // Under a replaced signal mask an empty zero-timeout result also
        // keeps its route: no mask change happens in ring.
        let zero = Args::timeout(0, 0);
        let mut fds = set(&[(3, POLLIN)]);
        let (route, _) = children.ppoll(
            0,
            &mut fds,
            zero.timespec(),
            &*zero.mask as *const u64 as u64,
            8,
        );
        assert_eq!(route, CompletionRoute::Forward);
        assert_eq!(fds[0].revents, UNTOUCHED);
        assert_eq!(children.served(), 0);
    });
}

#[test]
fn serial_host_native_child_ppoll_mixed_host_set_is_refused_whole() {
    with_native_children(|children| {
        let zero = Args::timeout(0, 0);
        let mut fds = set(&[(3, POLLIN), (5, POLLIN)]);
        let (route, _) = children.ppoll(0, &mut fds, zero.timespec(), 0, 0);
        assert_eq!(route, CompletionRoute::Forward);
        assert_eq!(children.forwarded(), 1);
        assert!(fds.iter().all(|entry| entry.revents == UNTOUCHED));
        // Control: negative and absent descriptors stay in ring.
        let mut fds = set(&[(3, POLLIN), (-1, POLLIN), (9, POLLIN)]);
        assert_eq!(
            children.ppoll(0, &mut fds, zero.timespec(), 0, 0),
            (CompletionRoute::Served, 1)
        );
        assert_eq!(
            fds.iter().map(|entry| entry.revents).collect::<Vec<_>>(),
            [0, 0, POLLNVAL]
        );
    });
}

#[test]
fn serial_host_native_child_ppoll_invalid_arguments_are_einval() {
    const EINVAL: i64 = -22;
    with_native_children(|children| {
        let zero = Args::timeout(0, 0);
        let mask = &*zero.mask as *const u64 as u64;
        let mut fds = set(&[(3, POLLIN)]);
        assert_eq!(
            children.ppoll(0, &mut fds, zero.timespec(), mask, 4),
            (CompletionRoute::Served, EINVAL),
            "sigsetsize other than 8"
        );
        let bad = Args::timeout(0, 1_000_000_000);
        assert_eq!(
            children.ppoll(0, &mut fds, bad.timespec(), 0, 0),
            (CompletionRoute::Served, EINVAL),
            "nanoseconds out of range"
        );
        let negative = Args::timeout(-1, 0);
        assert_eq!(
            children.ppoll(0, &mut fds, negative.timespec(), 0, 0),
            (CompletionRoute::Served, EINVAL),
            "negative seconds"
        );
        // The children inherit the root's soft RLIMIT_NOFILE of 64.
        let mut many = set(&[(-1, POLLIN); 65]);
        assert_eq!(
            children.ppoll(0, &mut many, zero.timespec(), 0, 0),
            (CompletionRoute::Served, EINVAL),
            "nfds above RLIMIT_NOFILE"
        );
        let mut at_limit = set(&[(-1, POLLIN); 64]);
        assert_eq!(
            children.ppoll(0, &mut at_limit, zero.timespec(), 0, 0),
            (CompletionRoute::Served, 0),
            "nfds equal to RLIMIT_NOFILE"
        );
        assert_eq!(fds[0].revents, UNTOUCHED);
        assert_eq!(children.forwarded(), 0);
    });
}
