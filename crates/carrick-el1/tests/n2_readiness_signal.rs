//! N2 L4 red-first route witnesses for kernel.el1.signal-delivery-owner and
//! the driver's pending kernel.el1.creation-native-path binding (rows 10/12).
//!
//! Linux authorities: signal(7), sigaction(2), tgkill(2), setitimer(2).
//! These call the production region/lifecycle dispatcher, not its host stub.
//! No host syscall dispatcher runs. The real forward counters must be zero;
//! returning Served alone is insufficient: results and owner state matter.
//!
//! Each population has N live target process identities plus a live guard,
//! distinct open MMs, and the same child stack VA. They are shared-ABI fixture
//! processes, not executing EL0 or host kernel-graph processes. Birth uses the
//! production thread-clone route without host settlement. There is no owner
//! signal API yet: frame delivery, expiry injection, exec and wait interruption
//! are explicitly unbound, not simulated here. See the L4 handoff document.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_el1::personality::lifecycle::{LifecycleThread, LifecycleVenue};
use carrick_el1::{Zone, dispatch_syscall_with_lifecycle, sched};
use carrick_el1_abi::{
    Action, BlockedMask, Counters, CurrentTask, El1TaskId, EntryIdentity, EntryRef, EntryState,
    InotifyNameCache, SlotId, THREAD_POOL_ENTRIES, ThreadControlSlot, ThreadCtx,
    ThreadLifecyclePage, TrapFrame, ZoneTables,
};
use core::sync::atomic::Ordering;

const SAME_STACK: u64 = 0x4000_1000;
const THREAD_FLAGS: u64 = 0x0005_0f00;
const USR1: u64 = 10;
const CHLD: u64 = 17;

struct Process {
    tid: u32,
    page: ThreadLifecyclePage,
    leader: ThreadControlSlot,
    children: [ThreadControlSlot; THREAD_POOL_ENTRIES],
}

impl Process {
    fn new(tid: u32) -> Self {
        let page = ThreadLifecyclePage::new();
        page.stock(
            0,
            EntryIdentity {
                tid: tid + 10_000,
                visible_tid: tid + 10_000,
                thread_serial: u64::from(tid) + 10_000,
                uid_credit: 1,
            },
        )
        .unwrap();
        let leader = ThreadControlSlot::new();
        assert!(leader.publish_visible_tid(tid));
        leader.init_blocked(BlockedMask((1 << (USR1 - 1)) | (1 << (CHLD - 1))));
        Self {
            tid,
            page,
            leader,
            children: core::array::from_fn(|_| ThreadControlSlot::new()),
        }
    }
}

struct Fixture {
    zone: Box<ZoneTables>,
    counters: Counters,
    tasks: Vec<CurrentTask>,
    processes: Vec<Process>,
}

impl Fixture {
    fn new(targets: usize) -> Self {
        // SAFETY: the shared ZoneTables ABI has an all-zero empty state. Heap
        // allocation avoids placing the large table on the test thread stack.
        let zone = unsafe { Box::<ZoneTables>::new_zeroed().assume_init() };
        let processes: Vec<_> = (0..=targets)
            .map(|index| Process::new(100 + index as u32))
            .collect();
        let tasks = processes
            .iter()
            .enumerate()
            .map(|(index, process)| {
                let mm = 71 + index as u64;
                let space = zone.spaces.publish_closed(mm, mm << 12, mm << 12).unwrap();
                zone.spaces.open(space);
                let task = CurrentTask::new();
                task.set(El1TaskId::from_linux_tid(process.tid as i32), 1, mm);
                task.zone_mm.store(mm, Ordering::Release);
                task.thread_serial
                    .store(u64::from(process.tid), Ordering::Release);
                let slot = SlotId::from_index(index).unwrap();
                zone.drive(slot, index as u64 + 1);
                zone.publish_slot(slot, mm, None, 0);
                task
            })
            .collect();
        Self {
            zone,
            counters: Counters::default(),
            tasks,
            processes,
        }
    }

    fn call(&self, slot: usize, nr: usize, args: [u64; 6]) -> (Action, u64) {
        let mut frame = TrapFrame {
            slot: slot as u64,
            elr: 0x4000,
            ..TrapFrame::default()
        };
        frame.x[..6].copy_from_slice(&args);
        frame.x[8] = nr as u64;
        let mut cpu = SaveCpu::default();
        let action = dispatch_syscall_with_lifecycle(
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
                user: &sched::HardwareUserWord,
            }),
            None,
            Some(self),
            |_| panic!("signal fixture must not access a delegated file"),
        );
        (action, frame.x[0])
    }

    fn birth(&self, slot: usize) -> u64 {
        let process = &self.processes[slot];
        let tid = u64::from(process.tid + 10_000);
        assert_eq!(
            self.call(slot, 220, [THREAD_FLAGS, SAME_STACK, 0, 0, 0, 0]),
            (Action::Served, tid),
            "positive control: actual EL1 thread birth"
        );
        assert_eq!(process.page.live(), 2);
        assert_eq!(process.page.state(0).unwrap().1, EntryState::Born);
        assert_eq!(process.children[0].blocked(), process.leader.blocked());
        assert_eq!(
            self.zone.slot(SlotId::from_index(slot).unwrap()).queued(),
            1
        );
        tid
    }

    fn census(&self, nr: usize) -> (u64, u64) {
        (
            self.counters.forwarded[nr].load(Ordering::Relaxed),
            self.counters.served[nr].load(Ordering::Relaxed),
        )
    }
}

impl LifecycleVenue for Fixture {
    fn thread(&self, task: &CurrentTask) -> Option<LifecycleThread<'_>> {
        self.processes.iter().find_map(|process| {
            (task.task_id.load(Ordering::Acquire) == u64::from(process.tid)).then_some(
                LifecycleThread {
                    page: &process.page,
                    slot: &process.leader,
                },
            )
        })
    }

    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot> {
        self.processes.iter().find_map(|process| {
            core::ptr::eq(page, &process.page)
                .then(|| process.children.get(entry.index()))
                .flatten()
        })
    }
}

// Birth arms a preemption timer. Record that physical effect without running
// time forward; it is not a Linux interval-timer expiration or signal model.
// Fail closed if these nonblocking operations require a switch or guest wait.
#[derive(Default)]
struct SaveCpu {
    timer: Option<u64>,
}
impl sched::ThreadCpu for SaveCpu {
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx) {
        ctx.x = frame.x;
        ctx.pc = frame.elr;
        ctx.pstate = frame.spsr;
    }
    fn load(&mut self, _: &mut TrapFrame, _: &ThreadCtx) {
        panic!("unexpected context switch")
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        panic!("unexpected root install")
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
    fn set_timer(&mut self, deadline: Option<u64>) {
        self.timer = deadline;
    }
    fn send_sgi(&mut self, _: u64) {
        panic!("unexpected remote wake of blocked signal target")
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
#[ignore = "N2 red witness: row 10: rt_sigaction still forwards with live lifecycle admission"]
fn sigaction_keeps_live_process_actions_separate_at_1_8_32() {
    let mut deficits = Vec::new();
    for n in [1, 8, 32] {
        let fixture = Fixture::new(n);
        let mut results = Vec::new();
        // Kernel arm64 sigaction: handler, flags, restorer, mask. Backed host
        // arrays remain alive through each synchronous public dispatcher call.
        // SA_RESTART is retained as action data, not a restart execution proof.
        for slot in 0..=n {
            let action = [0x4000 + 16 * slot as u64, 0x1000_0000, 0, 1 << 11];
            results.push(fixture.call(slot, 134, [USR1, action.as_ptr() as u64, 0, 8, 0, 0]));
        }
        let mut separate = true;
        for slot in 0..=n {
            let mut action = [u64::MAX; 4];
            results.push(fixture.call(slot, 134, [USR1, 0, action.as_mut_ptr() as u64, 8, 0, 0]));
            separate &= action == [0x4000 + 16 * slot as u64, 0x1000_0000, 0, 1 << 11];
        }
        let census = fixture.census(134);
        println!(
            "sigaction n={n}: forwarded={} served={} separate={separate}",
            census.0, census.1
        );
        if census != (0, 2 * (n + 1) as u64)
            || !separate
            || results.iter().any(|result| *result != (Action::Served, 0))
        {
            deficits.push((n, census, separate));
        }
    }
    assert!(
        deficits.is_empty(),
        "row 10: missing sigaction owner: {deficits:?}"
    );
}

#[test]
#[ignore = "N2 red witness: row 10: immediate post-birth tgkill requires host semantic routing"]
fn tgkill_reaches_exact_born_target_before_host_settlement_at_1_8_32() {
    let mut deficits = Vec::new();
    for n in [1, 8, 32] {
        let fixture = Fixture::new(n);
        let mut exact = true;
        for slot in 0..n {
            let tid = fixture.birth(slot);
            let tgid = u64::from(fixture.processes[slot].tid);
            let result = fixture.call(slot, 131, [tgid, tid, USR1, 0, 0, 0]);
            exact &= result == (Action::Served, 0);
            exact &= fixture.processes[slot].children[0].pending().load().0 == 1 << (USR1 - 1);
            exact &= fixture.processes[slot].leader.pending().load().0 == 0;
            // A valid tid in the wrong thread group must be ESRCH (3), and
            // must not enqueue anything in the unrelated live guard process.
            let wrong_group = u64::from(fixture.processes[n].tid);
            exact &= fixture.call(slot, 131, [wrong_group, tid, USR1, 0, 0, 0])
                == (Action::Served, (-3i64) as u64);
        }
        assert_eq!(fixture.processes[n].page.live(), 1);
        assert_eq!(fixture.processes[n].leader.pending().load().0, 0);
        assert_eq!(fixture.census(220), (0, n as u64));
        let census = fixture.census(131);
        println!(
            "tgkill n={n}: births={n} forwarded={} served={} exact={exact}",
            census.0, census.1
        );
        if census != (0, 2 * n as u64) || !exact {
            deficits.push((n, census, exact));
        }
    }
    assert!(
        deficits.is_empty(),
        "row 10: missing born-target signal owner: {deficits:?}"
    );
}

#[test]
#[ignore = "N2 red witness: row 10: blocked SIGCHLD pending query has no EL1 owner"]
fn blocked_sigchld_is_observable_only_in_its_live_owner_at_1_8_32() {
    let mut deficits = Vec::new();
    for n in [1, 8, 32] {
        let fixture = Fixture::new(n);
        let mut exact = true;
        for slot in 0..n {
            let tgid = u64::from(fixture.processes[slot].tid);
            exact &= fixture.call(slot, 131, [tgid, tgid, CHLD, 0, 0, 0]) == (Action::Served, 0);
            let mut pending = 0u64;
            exact &= fixture.call(
                slot,
                136,
                [(&mut pending as *mut u64) as u64, 8, 0, 0, 0, 0],
            ) == (Action::Served, 0);
            exact &= pending == 1 << (CHLD - 1);
        }
        let mut guard_pending = u64::MAX;
        exact &= fixture.call(
            n,
            136,
            [(&mut guard_pending as *mut u64) as u64, 8, 0, 0, 0, 0],
        ) == (Action::Served, 0);
        exact &= guard_pending == 0;
        let send = fixture.census(131);
        let query = fixture.census(136);
        println!("sigchld n={n}: send={send:?} query={query:?} exact={exact}");
        if send != (0, n as u64) || query != (0, (n + 1) as u64) || !exact {
            deficits.push((n, send, query, exact));
        }
    }
    assert!(
        deficits.is_empty(),
        "row 10: missing blocked-pending owner: {deficits:?}"
    );
}

#[test]
#[ignore = "N2 red witness: row 12: setitimer/getitimer still use host semantic routes"]
fn disarming_one_process_timer_preserves_the_live_guard_timer_at_1_8_32() {
    let mut deficits = Vec::new();
    for n in [1, 8, 32] {
        let fixture = Fixture::new(n);
        // ITIMER_REAL, itimerval = interval(sec,usec), value(sec,usec).
        let guard = [0u64, 0, 2, 0];
        let armed = [0u64, 0, 1, 0];
        let disarmed = [0u64; 4];
        let mut exact =
            fixture.call(n, 103, [0, guard.as_ptr() as u64, 0, 0, 0, 0]) == (Action::Served, 0);
        for slot in 0..n {
            exact &= fixture.call(slot, 103, [0, armed.as_ptr() as u64, 0, 0, 0, 0])
                == (Action::Served, 0);
            let mut old = [u64::MAX; 4];
            exact &= fixture.call(
                slot,
                103,
                [
                    0,
                    disarmed.as_ptr() as u64,
                    old.as_mut_ptr() as u64,
                    0,
                    0,
                    0,
                ],
            ) == (Action::Served, 0);
            exact &= old == armed;
            let mut remaining = [u64::MAX; 4];
            exact &= fixture.call(slot, 102, [0, remaining.as_mut_ptr() as u64, 0, 0, 0, 0])
                == (Action::Served, 0);
            exact &= remaining == disarmed;
        }
        let mut remaining = [u64::MAX; 4];
        exact &= fixture.call(n, 102, [0, remaining.as_mut_ptr() as u64, 0, 0, 0, 0])
            == (Action::Served, 0);
        exact &= remaining == guard; // injected CPU clock never advanced
        let set = fixture.census(103);
        let get = fixture.census(102);
        println!("timer n={n}: set={set:?} get={get:?} exact={exact}");
        if set != (0, (2 * n + 1) as u64) || get != (0, (n + 1) as u64) || !exact {
            deficits.push((n, set, get, exact));
        }
    }
    assert!(
        deficits.is_empty(),
        "row 12: missing interval-timer owner: {deficits:?}"
    );
}
