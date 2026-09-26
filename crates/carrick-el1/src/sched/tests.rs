#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate std;

use super::*;
use carrick_el1_abi::{
    Claim, Counters, DelegatedFile, DelegatedInotify, DelegatedOpenFile, El1TaskId, FdMapSlot,
    Handback, InotifyNameCache, RecordId,
};
use carrick_sched_core::LockWait;
use core::sync::atomic::AtomicU32;
use std::boxed::Box;

const MM: u64 = 7;
const SLOT: SlotId = SlotId::new(3);

struct HostWait;

impl LockWait for HostWait {
    fn wait(&self, _attempt: u32) -> bool {
        core::hint::spin_loop();
        true
    }
}

fn zone() -> Box<ZoneTables> {
    let layout = std::alloc::Layout::new::<ZoneTables>();
    // SAFETY: all-zero is the valid empty zone.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    }
}

fn identity(tid: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid,
        serial: tid + 1000,
        mm: MM,
        file_table: 5,
        generation: 1,
        affinity: 0,
    }
}

/// What the host publishes when it loads a thread of `mm` on `slot`: the
/// slot's scheduling facts and its occupancy word (the executor installs the
/// loaded task's address space before it runs the vCPU).
fn host_publish(zone: &ZoneTables, slot: SlotId, mm: u64, cpu: Option<u32>, affinity: u64) {
    zone.publish_slot(slot, mm, cpu, affinity);
    let here = carrick_sched_core::ExecutionSlot::zone(slot);
    zone.occupancy.vacate_any(here);
    if mm != 0 {
        assert!(zone.occupancy.replace(here, 0, mm));
    }
}

fn counters() -> &'static Counters {
    Box::leak(Box::new(Counters::default()))
}

/// Serve a futex syscall on `slot` the way the dispatcher does.
fn serve_on(
    slot: SlotId,
    frame: &mut TrapFrame,
    task: &CurrentTask,
    zone: &ZoneTables,
    cpu: &mut FakeCpu,
    counters: &Counters,
) -> Option<Served> {
    // The host publishes the loaded thread's address space on the slot at
    // every load; EL1 places woken threads by it.
    if zone.slot(slot).mm() == 0 {
        host_publish(zone, slot, task.zone_mm.load(Ordering::Relaxed), None, 0);
    }
    Sched {
        zone,
        slot,
        task,
        cpu,
        user: &HardwareUserWord,
        counters,
    }
    .serve_futex(frame)
}

fn serve(
    frame: &mut TrapFrame,
    task: &CurrentTask,
    zone: &ZoneTables,
    cpu: &mut FakeCpu,
) -> Option<Served> {
    serve_on(SLOT, frame, task, zone, cpu, counters())
}

const RETURNED: Option<Served> = Some(Served::Returned { switched: false });
const SWITCHED: Option<Served> = Some(Served::Returned { switched: true });

/// The slot's task record naming the host-loaded thread `tid`.
fn task_for(tid: u64) -> CurrentTask {
    let task = CurrentTask::new();
    task.set(El1TaskId::from_linux_tid(tid as i32), 1, 5);
    task.zone_mm.store(MM, Ordering::Relaxed);
    task.thread_serial.store(tid + 1000, Ordering::Relaxed);
    task
}

/// Park `tid` the way the host parks a forwarded wait: context first, then
/// queue and publish under the bucket lock.
fn host_park(zone: &ZoneTables, tid: u64, uaddr: u64, ctx: ThreadCtx) -> RecordId {
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let record = zone.alloc_record(identity(tid)).unwrap();
    // SAFETY: freshly allocated and unpublished.
    unsafe { *zone.record(record).ctx_mut() = ctx };
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, MM, uaddr, u32::MAX, 0)
        .unwrap();
    zone.publish_park(record, seq);
    record
}

fn thread_ctx(tag: u64, uaddr: u64) -> ThreadCtx {
    let mut ctx = ThreadCtx::ZERO;
    for (i, x) in ctx.x.iter_mut().enumerate() {
        *x = tag << 8 | i as u64;
    }
    ctx.x[0] = uaddr;
    ctx.x[8] = SYS_FUTEX as u64;
    ctx.pc = tag << 12;
    ctx.pstate = 0x3c0;
    ctx.sp_el0 = tag << 16;
    ctx.tpidr_el0 = tag << 20;
    ctx.tpidrro_el0 = tag << 24;
    ctx.contextidr_el1 = tag;
    for (i, v) in ctx.v.iter_mut().enumerate() {
        *v = (u128::from(tag) << 64) | i as u128;
    }
    ctx.fpsr = tag;
    ctx.fpcr = tag << 1;
    ctx
}

/// `thread`'s live state: the frame of its futex syscall and its CPU.
fn live(tag: u64, uaddr: u64, op: u64, value: u64) -> (TrapFrame, FakeCpu) {
    let ctx = thread_ctx(tag, uaddr);
    let mut frame = TrapFrame {
        x: ctx.x,
        elr: ctx.pc,
        spsr: ctx.pstate,
        slot: u64::from(SLOT.raw()),
        ..TrapFrame::default()
    };
    frame.x[1] = op;
    frame.x[2] = value;
    frame.x[3] = 0;
    let cpu = FakeCpu {
        regs: FakeRegs {
            sp_el0: ctx.sp_el0,
            tpidr_el0: ctx.tpidr_el0,
            tpidrro_el0: ctx.tpidrro_el0,
            contextidr_el1: ctx.contextidr_el1,
            v: ctx.v,
            fpsr: ctx.fpsr,
            fpcr: ctx.fpcr,
        },
        ..FakeCpu::default()
    };
    (frame, cpu)
}

fn set_op(frame: &mut TrapFrame, uaddr: u64, op: u64, value: u64) {
    frame.x[0] = uaddr;
    frame.x[1] = op;
    frame.x[2] = value;
    frame.x[3] = 0;
    frame.x[8] = SYS_FUTEX as u64;
}

/// The ping-pong the design exists for: A wakes B and waits, B runs, wakes A
/// and waits, A runs again with exactly its registers, all in-guest.
fn ping_pong(skip_fpsimd: bool) -> (TrapFrame, FakeCpu, TrapFrame, FakeCpu) {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));

    let (a_frame, a_cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    let (mut frame, mut cpu) = (a_frame, a_cpu.clone());
    cpu.skip_fpsimd = skip_fpsimd;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), RETURNED);
    assert_eq!(frame.x[0], 1, "one waiter woken");
    assert_eq!(zone.record(b).claim(), Claim::Queued { slot: SLOT, seq: 1 });

    // A waits: it parks and the vCPU switches to B.
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    let a_before_wait = (frame, cpu.clone());
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(frame.x[0], 0, "B's wait returns 0");
    assert_eq!(frame.elr, 0xB << 12);
    assert_eq!(task.task_id.load(Ordering::Relaxed), 202);
    assert_eq!(task.thread_serial.load(Ordering::Relaxed), 1202);
    let a = zone.slot(SLOT).current();
    assert_eq!(a, Some(b), "B is the switched-in record");

    // B runs and uses its FP/SIMD registers.
    cpu.regs.v[0] ^= 0xdead;
    cpu.regs.fpcr ^= 1;

    // B wakes A and waits; A comes back.
    set_op(&mut frame, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), RETURNED);
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(task.task_id.load(Ordering::Relaxed), 101);
    (a_before_wait.0, a_before_wait.1, frame, cpu)
}

#[test]
fn a_futex_handoff_switches_threads_in_guest_and_preserves_state() {
    let (mut before, before_cpu, after, after_cpu) = ping_pong(false);
    before.x[0] = 0; // the wait's return value
    assert_eq!(after, before, "A resumes with exactly its registers");
    assert_eq!(
        after_cpu.regs, before_cpu.regs,
        "and its SP_EL0, TLS, CONTEXTIDR, FP/SIMD"
    );
}

/// Negative control: a switch that does not save FP/SIMD is caught.
#[test]
fn a_switch_without_fpsimd_save_is_detected() {
    let (_, before_cpu, _, after_cpu) = ping_pong(true);
    assert_ne!(after_cpu.regs.v, before_cpu.regs.v);
    assert_ne!(after_cpu.regs.fpcr, before_cpu.regs.fpcr);
}

/// A wait with nothing runnable parks the thread and idles the vCPU in EL1
/// (polling, then WFI); a host kick (the kick SGI) sends the idle vCPU to the
/// host with the thread parked in its home record.
#[test]
fn a_wait_with_nothing_runnable_idles_until_host_work() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let counters = counters();
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    // The kick arrives while the vCPU is parked in WFI.
    cpu.pending.push_back(GIC_KICK_INTID);
    assert_eq!(
        serve_on(SLOT, &mut frame, &task, &zone, &mut cpu, counters),
        Some(Served::Idle)
    );
    assert!(task.has_pending_host_work());
    assert_eq!(
        counters.irq_taken[GIC_KICK_INTID as usize].load(Ordering::Relaxed),
        1
    );
    assert_eq!(zone.counters.el1_idle_entries.load(Ordering::Relaxed), 1);
    assert_eq!(zone.counters.el1_idle_exits.load(Ordering::Relaxed), 1);
    let home = zone
        .slot(SLOT)
        .host_record()
        .expect("the thread parked in its home record");
    assert_eq!(zone.record(home).home(), Some(SLOT));
    assert!(matches!(zone.record(home).claim(), Claim::Parked { .. }));
    assert_eq!(zone.slot(SLOT).current(), None);
    assert_eq!(zone.slot(SLOT).state(), carrick_el1_abi::SlotState::Running);
    assert_eq!(zone.slot(SLOT).sgi_target(), sgi_target_of(cpu.mpidr));
}

/// With nothing to end it, an idle vCPU polls for its spin budget and then
/// parks in WFI (the fake CPU fails the test on a WFI nothing can end, so
/// arm a timer to observe the park).
#[test]
fn an_idle_vcpu_parks_in_wfi_after_its_spin() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    let ts = libc_timespec(0, 5_000_000);
    frame.x[3] = &ts as *const [u64; 2] as u64;
    let start = cpu.now;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert!(cpu.wfis >= 1, "the idle vCPU parked in WFI");
    assert!(
        cpu.now - start >= cpu.freq / 1000 * 5,
        "it slept until the 5 ms deadline"
    );
    assert_eq!(
        zone.counters.el1_wfi_entries.load(Ordering::Relaxed),
        cpu.wfis
    );
}

fn libc_timespec(secs: u64, nanos: u64) -> [u64; 2] {
    [secs, nanos]
}

/// A 1 ms FUTEX_WAIT_PRIVATE timeout of the host-loaded thread ends in EL1:
/// the vCPU idles, its virtual timer ends the park, and the same thread
/// resumes with ETIMEDOUT and exactly its registers; its home record is
/// freed, so the host never learns of the wait.
#[test]
fn a_timed_wait_ends_in_guest_with_etimedout() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    let ts = libc_timespec(0, 1_000_000);
    frame.x[3] = &ts as *const [u64; 2] as u64;
    let before = (frame, cpu.regs.clone());
    let start = cpu.now;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(frame.x[0] as i64, -110, "ETIMEDOUT");
    let mut expected = before.0;
    expected.x[0] = (-110_i64) as u64;
    assert_eq!(frame, expected, "the thread resumes where it waited");
    assert_eq!(cpu.regs, before.1);
    assert!(
        cpu.now - start >= cpu.freq / 1000,
        "not before its deadline"
    );
    assert_eq!(zone.counters.el1_timeouts.load(Ordering::Relaxed), 1);
    let home = zone
        .slot(SLOT)
        .host_record()
        .expect("the loaded thread's record");
    assert_eq!(
        zone.slot(SLOT).current(),
        Some(home),
        "it runs again, as the host believes"
    );
    assert_eq!(cpu.timer, None, "the timer is disarmed once the park ended");
    // Its next timed wait parks into the same record and ends the same way.
    let ts = libc_timespec(0, 1_000_000);
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    frame.x[3] = &ts as *const [u64; 2] as u64;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(frame.x[0] as i64, -110);
    assert_eq!(zone.slot(SLOT).host_record(), Some(home));
    assert_eq!(zone.counters.el1_timeouts.load(Ordering::Relaxed), 2);
    assert_eq!(task.task_id.load(Ordering::Relaxed), 101);
}

/// A switched-in thread's timed wait is forwarded (its deadline would
/// outlive this vCPU's hold on it); so is an invalid timespec.
#[test]
fn timed_waits_this_vcpu_cannot_keep_forward() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let bad = libc_timespec(0, 1_000_000_000);
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    frame.x[3] = &bad as *const [u64; 2] as u64;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), None);
    // Switch B in (A wakes B, then A waits untimed).
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    set_op(&mut frame, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), RETURNED);
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(zone.slot(SLOT).current(), Some(b));
    let ts = libc_timespec(0, 1_000_000);
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    frame.x[3] = &ts as *const [u64; 2] as u64;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), None);
}

/// A handoff across vCPUs: the woken thread is the other vCPU's home
/// record, so it is queued there, with a reschedule SGI to its published
/// routing because that vCPU parked in WFI; the other vCPU's idle loop then
/// switches it in with its wait's result, and frees the home record.
#[test]
fn a_wake_hands_a_thread_to_the_idle_vcpu_it_belongs_to() {
    const OTHER: SlotId = SlotId::new(4);
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let counters = counters();
    for slot in [SLOT, OTHER] {
        assert!(zone.reset_slot(slot));
        host_publish(&zone, slot, MM, None, 0);
        zone.enter_guest(slot);
    }
    // B, the thread the host loaded on OTHER, waits with nothing runnable:
    // OTHER idles; a host kick is the only way this test gets it back.
    let task_b = task_for(202);
    let (mut frame_b, mut cpu_b) = live(0xB, uaddr, FUTEX_WAIT_PRIVATE, 0);
    frame_b.slot = u64::from(OTHER.raw());
    cpu_b.mpidr = 0x8000_0104;
    let b_before = frame_b;
    cpu_b.pending.push_back(GIC_KICK_INTID);
    assert_eq!(
        serve_on(OTHER, &mut frame_b, &task_b, &zone, &mut cpu_b, counters),
        Some(Served::Idle)
    );
    task_b.clear_pending_host_work();
    // Pretend the kick never happened: OTHER is parked in WFI.
    assert!(!zone.enter_idle(OTHER, false));
    assert!(zone.enter_idle(OTHER, true));
    let rb = zone.slot(OTHER).host_record().unwrap();

    // A on SLOT wakes B.
    let task_a = task_for(101);
    let (mut frame_a, mut cpu_a) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(
        serve_on(SLOT, &mut frame_a, &task_a, &zone, &mut cpu_a, counters),
        RETURNED
    );
    assert_eq!(frame_a.x[0], 1);
    assert_eq!(
        zone.record(rb).claim(),
        Claim::Queued {
            slot: OTHER,
            seq: 1
        }
    );
    assert_eq!(
        cpu_a.sgis,
        [sgi_target_of(0x8000_0104) | (u64::from(GIC_RESCHED_INTID) << 24)]
    );
    assert_eq!(sgi_target_of(0x8000_0104), (1 << 4) | (1 << 16));
    assert_eq!(zone.counters.el1_cross_wakes.load(Ordering::Relaxed), 1);
    assert_eq!(zone.slot(SLOT).queued(), 0, "nothing queued on the waker");

    // OTHER's idle loop takes the SGI and runs B.
    cpu_b.pending.push_back(GIC_RESCHED_INTID);
    let served = Sched {
        zone: &zone,
        slot: OTHER,
        task: &task_b,
        cpu: &mut cpu_b,
        user: &HardwareUserWord,
        counters,
    }
    .idle(&mut frame_b);
    assert_eq!(served, Served::Returned { switched: true });
    let mut expected = b_before;
    expected.x[0] = 0;
    assert_eq!(frame_b, expected, "B resumes from its wait with 0");
    assert_eq!(
        zone.slot(OTHER).current(),
        Some(rb),
        "B, the loaded thread, runs again"
    );
    assert_eq!(
        zone.record(rb).claim(),
        Claim::OnCpu {
            slot: OTHER,
            seq: 1
        }
    );
}

/// Timer preemption at EL0: a thread queued behind a compute loop runs once
/// its slice has passed, and the preempted loop later resumes with exactly
/// its registers (no syscall result applied); neither ever left the guest.
#[test]
fn the_virtual_timer_preempts_a_compute_loop() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let counters = counters();
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(
        serve_on(SLOT, &mut frame, &task, &zone, &mut cpu, counters),
        RETURNED
    );
    let slice = cpu.freq / 1000 * 2;
    assert_eq!(cpu.timer, Some(cpu.now + slice), "the slice timer is armed");
    // A computes at EL0: its registers change, no syscall.
    frame.x[5] = 0x5555;
    frame.elr += 0x40;
    let a_running = (frame, cpu.regs.clone());
    let irq = |frame: &mut TrapFrame, cpu: &mut FakeCpu| {
        Sched {
            zone: &zone,
            slot: SLOT,
            task: &task,
            cpu,
            user: &HardwareUserWord,
            counters,
        }
        .serve_irq(frame)
    };
    // Before the slice ends nothing changes (a stray reschedule SGI).
    cpu.pending.push_back(GIC_RESCHED_INTID);
    assert_eq!(irq(&mut frame, &mut cpu), carrick_el1_abi::Action::Served);
    assert_eq!(frame, a_running.0);
    // The slice ends: B runs.
    cpu.now += slice;
    assert_eq!(irq(&mut frame, &mut cpu), carrick_el1_abi::Action::Served);
    assert_eq!(frame.elr, 0xB << 12, "B runs");
    assert_eq!(frame.x[0], 0, "B's wait returns 0");
    assert_eq!(zone.slot(SLOT).current(), Some(b));
    assert_eq!(task.task_id.load(Ordering::Relaxed), 202);
    // B computes; the next slice end brings A back, untouched.
    cpu.regs.v[3] ^= 7;
    cpu.now += slice;
    assert_eq!(irq(&mut frame, &mut cpu), carrick_el1_abi::Action::Served);
    assert_eq!(
        frame, a_running.0,
        "A resumes exactly where it was preempted"
    );
    assert_eq!(cpu.regs, a_running.1);
    assert_eq!(task.task_id.load(Ordering::Relaxed), 101);
    assert_eq!(zone.slot(SLOT).current(), zone.slot(SLOT).host_record());
    assert_eq!(zone.counters.el1_preemptions.load(Ordering::Relaxed), 2);
    assert_eq!(
        counters.irq_taken[GIC_VTIMER_INTID as usize].load(Ordering::Relaxed),
        2
    );
}

/// A host kick taken at EL0 sends the vCPU to the host at that boundary.
#[test]
fn a_kick_taken_at_el0_forwards() {
    let zone = zone();
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, 0x1000, FUTEX_WAKE_PRIVATE, 1);
    cpu.pending.push_back(GIC_KICK_INTID);
    let copy = frame;
    let action = Sched {
        zone: &zone,
        slot: SLOT,
        task: &task,
        cpu: &mut cpu,
        user: &HardwareUserWord,
        counters: counters(),
    }
    .serve_irq(&mut frame);
    assert_eq!(action, carrick_el1_abi::Action::Forward);
    assert!(task.has_pending_host_work());
    assert_eq!(frame, copy);
}

#[test]
fn a_wait_on_a_changed_word_returns_eagain_without_parking() {
    let zone = zone();
    let word = AtomicU32::new(5);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert!(serve(&mut frame, &task, &zone, &mut cpu).is_some());
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 4);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), RETURNED);
    assert_eq!(frame.x[0] as i64, EAGAIN);
    assert_eq!(zone.record(b).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    assert_eq!(zone.slot(SLOT).current(), None);
}

#[test]
fn unserved_futex_operations_forward() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    for (op, timeout, count, bitset) in [
        (0u64, 0u64, 0u64, 0u64),                  // non-private wait
        (1, 0, 1, 0),                              // non-private wake
        (FUTEX_WAIT_BITSET_PRIVATE, 0x1000, 0, 1), // absolute timeout
        (FUTEX_WAKE_PRIVATE, 0, 0, 0),             // wake 0 (the host decides)
        (FUTEX_WAIT_BITSET_PRIVATE, 0, 0, 0),      // bitset 0 is EINVAL
        (128 | 3, 0, 1, 0),                        // requeue
        (128 | 4, 0, 1, 0),                        // cmp_requeue
        (256 | FUTEX_WAIT_PRIVATE, 0, 0, 0),       // clock-realtime flag
    ] {
        let (mut frame, mut cpu) = live(0xA, uaddr, op, count);
        frame.x[3] = timeout;
        frame.x[5] = bitset;
        assert_eq!(
            serve(&mut frame, &task, &zone, &mut cpu),
            None,
            "op {op:#x}"
        );
    }
    let (mut frame, mut cpu) = live(0xA, uaddr + 1, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), None, "unaligned");
    let off = CurrentTask::new();
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(
        serve(&mut frame, &off, &zone, &mut cpu),
        None,
        "zone off for the task (zone_mm 0)"
    );
}

#[test]
fn threads_of_another_process_are_not_woken() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    task.zone_mm.store(MM + 1, Ordering::Relaxed);
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), RETURNED);
    assert_eq!(frame.x[0], 0);
    assert!(matches!(zone.record(b).claim(), Claim::Parked { .. }));
}

/// A woken thread waiting on the run queue no longer sends the running
/// thread's other syscalls to the host (EL1 plan 1d; 1b-1c forwarded them so
/// the host could take the queued thread): a servable one is served.
#[test]
fn queued_threads_do_not_send_other_syscalls_to_the_host() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let tasks = [
        CurrentTask::new(),
        CurrentTask::new(),
        CurrentTask::new(),
        task_for(101),
    ];
    host_publish(&zone, SLOT, MM, None, 0);
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let counters = Counters::default();
    // fd 3 of the task's file table is a delegated file EL1 serves lseek on.
    let fd_map = [FdMapSlot::new()];
    fd_map[0].set(5, 3, 1, 42);
    let objects = [DelegatedFile::new()];
    let opens = [DelegatedOpenFile::new()];
    opens[0]
        .state
        .store(carrick_el1_abi::DELEGATED_STATE_GUEST, Ordering::Relaxed);
    opens[0].inode_handle.store(1, Ordering::Relaxed);
    objects[0]
        .state
        .store(carrick_el1_abi::DELEGATED_STATE_GUEST, Ordering::Relaxed);
    objects[0].generation.store(42, Ordering::Relaxed);
    opens[0].generation.store(42, Ordering::Relaxed);
    opens[0].inode_generation.store(42, Ordering::Relaxed);
    objects[0].size.store(100, Ordering::Relaxed);
    opens[0]
        .flags
        .store(carrick_el1_abi::DELEGATED_FLAG_READABLE, Ordering::Relaxed);
    let inotify = [DelegatedInotify::new()];
    let names = InotifyNameCache::new();
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    let run = |frame: &mut TrapFrame, cpu: &mut FakeCpu| {
        crate::dispatch_syscall_with_regions(
            frame,
            &counters,
            &tasks,
            &fd_map,
            &objects,
            &opens,
            &inotify,
            &names,
            Some(crate::Zone {
                tables: &zone,
                cpu,
                user: &HardwareUserWord,
            }),
            |_| core::ptr::null_mut(),
        )
    };
    assert_eq!(run(&mut frame, &mut cpu), carrick_el1_abi::Action::Served);
    assert_eq!(counters.served[SYS_FUTEX].load(Ordering::Relaxed), 1);
    assert_eq!(zone.record(b).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    frame.x[0] = 3;
    frame.x[1] = 50;
    frame.x[2] = 0;
    frame.x[8] = 62; // lseek
    assert_eq!(run(&mut frame, &mut cpu), carrick_el1_abi::Action::Served);
    assert_eq!(frame.x[0], 50);
    assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 0);
    // A pending host kick forwards even a servable futex call.
    tasks[3].mark_pending_host_work();
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(run(&mut frame, &mut cpu), carrick_el1_abi::Action::Forward);
}

// ---------------------------------------------------------------------------
// EL1 plan 1d: host-runnable threads, the idle entry and stealing.

/// A thread the host made runnable (a completed host wait): host-owned with
/// `Service`, queued on `slot` by host placement.
fn host_runnable(zone: &ZoneTables, slot: SlotId, tid: u64) -> RecordId {
    let record = zone.alloc_record(identity(tid)).unwrap();
    let seq = zone.next_seq(record);
    zone.publish_park(record, seq);
    assert_eq!(
        zone.claim_for_host(zone.record_ref(record), None, Handback::Service, &HostWait),
        carrick_el1_abi::HostClaim::Claimed
    );
    assert_eq!(zone.place_from_host(record).map(|p| p.slot), Some(slot));
    record
}

/// A wait with a host-runnable thread at the head of the run queue parks
/// the waiter and leaves for the host with no thread on the vCPU: EL1 never
/// runs that thread at EL0.
#[test]
fn a_park_before_a_host_runnable_thread_leaves_for_the_host() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    host_publish(&zone, SLOT, MM, Some(0), 0);
    zone.enter_guest(SLOT);
    let service = host_runnable(&zone, SLOT, 303);
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(
        serve(&mut frame, &task, &zone, &mut cpu),
        Some(Served::Idle)
    );
    assert_eq!(zone.slot(SLOT).current(), None);
    let own = zone.slot(SLOT).host_record().unwrap();
    assert!(matches!(zone.record(own).claim(), Claim::Parked { .. }));
    assert!(zone.head_needs_host(SLOT));
    assert_eq!(zone.runnable_head(SLOT), Some(service));
    assert_eq!(zone.counters.el1_service_exits.load(Ordering::Relaxed), 1);
    assert_eq!(cpu.wfis, 0, "it did not idle");
}

/// The slice of a running thread ends with a host-runnable thread queued:
/// the running thread goes to the tail with its registers (as preempted)
/// and the vCPU leaves through the idle exit.
#[test]
fn a_slice_ending_before_a_host_runnable_thread_leaves_for_the_host() {
    let zone = zone();
    let task = task_for(101);
    let counters = counters();
    host_publish(&zone, SLOT, MM, Some(0), 0);
    zone.enter_guest(SLOT);
    let service = host_runnable(&zone, SLOT, 303);
    let (mut frame, mut cpu) = live(0xA, 0x1000, FUTEX_WAKE_PRIVATE, 1);
    frame.x[5] = 0x5555;
    let running = (frame, cpu.regs.clone());
    let slice = cpu.freq / 1000 * 2;
    let irq = |frame: &mut TrapFrame, cpu: &mut FakeCpu| {
        Sched {
            zone: &zone,
            slot: SLOT,
            task: &task,
            cpu,
            user: &HardwareUserWord,
            counters,
        }
        .serve_irq(frame)
    };
    // The reschedule SGI the host placement owed starts the slice.
    cpu.pending.push_back(GIC_RESCHED_INTID);
    assert_eq!(irq(&mut frame, &mut cpu), carrick_el1_abi::Action::Served);
    assert_eq!(cpu.timer, Some(cpu.now + slice), "the slice timer is armed");
    cpu.now += slice;
    assert_eq!(irq(&mut frame, &mut cpu), carrick_el1_abi::Action::Idle);
    let own = zone.slot(SLOT).host_record().unwrap();
    assert_eq!(zone.runnable_head(SLOT), Some(service));
    assert!(matches!(zone.record(own).claim(), Claim::Queued { .. }));
    assert_eq!(zone.record(own).handback(), Some(Handback::Resumed));
    // SAFETY: the record is queued on this slot, which the test owns.
    let saved = unsafe { *zone.record(own).ctx_mut() };
    assert_eq!(saved.x, running.0.x);
    assert_eq!(saved.pc, running.0.elr);
    assert_eq!(saved.v, running.1.v);
}

/// The idle entry: an executor with no thread starts its vCPU in the
/// scheduler. With a woken thread queued it runs that thread (the frame
/// becomes its registers); with a host-runnable one it leaves at once; with
/// nothing it idles until host work arrives.
#[test]
fn the_idle_entry_runs_a_queued_thread_or_leaves_for_the_host() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let counters = counters();
    let waker = task_for(101);
    // A thread of MM parked; the slot the waker runs on wakes it.
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(serve(&mut frame, &waker, &zone, &mut cpu), RETURNED);
    assert_eq!(zone.record(b).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    // The executor of SLOT has no thread: it enters idle (same address
    // space still installed).
    let idle_task = CurrentTask::new();
    idle_task.zone_mm.store(MM, Ordering::Relaxed);
    let entry = |frame: &mut TrapFrame, cpu: &mut FakeCpu, task: &CurrentTask| {
        Sched {
            zone: &zone,
            slot: SLOT,
            task,
            cpu,
            user: &HardwareUserWord,
            counters,
        }
        .serve_idle_entry(frame)
    };
    let mut idle_frame = TrapFrame {
        slot: u64::from(SLOT.raw()),
        ..TrapFrame::default()
    };
    let mut idle_cpu = FakeCpu::default();
    assert_eq!(
        entry(&mut idle_frame, &mut idle_cpu, &idle_task),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(idle_frame.elr, 0xB << 12, "B runs from the idle entry");
    assert_eq!(idle_frame.x[0], 0, "its wait returns 0");
    assert_eq!(zone.slot(SLOT).current(), Some(b));
    // Later, with a host-runnable thread queued and nothing else, the idle
    // entry leaves at once.
    zone.clear_current(SLOT);
    let service = host_runnable(&zone, SLOT, 303);
    let mut idle_frame = TrapFrame {
        slot: u64::from(SLOT.raw()),
        ..TrapFrame::default()
    };
    assert_eq!(
        entry(&mut idle_frame, &mut idle_cpu, &idle_task),
        carrick_el1_abi::Action::Idle
    );
    assert_eq!(zone.runnable_head(SLOT), Some(service));
    // Host work pending: it leaves without looking.
    idle_task.mark_pending_host_work();
    assert_eq!(
        entry(&mut idle_frame, &mut idle_cpu, &idle_task),
        carrick_el1_abi::Action::Idle
    );
}

/// An idle vCPU takes a queued thread of its address space from another
/// vCPU's run queue instead of waiting in WFI.
#[test]
fn an_idle_vcpu_steals_a_queued_thread() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let counters = counters();
    let task = task_for(101);
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), RETURNED);
    assert_eq!(zone.record(b).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    // Another slot of the same address space enters idle.
    let other = SlotId::new(6);
    host_publish(&zone, other, MM, Some(1), 0);
    zone.enter_guest(other);
    let idle_task = CurrentTask::new();
    idle_task.zone_mm.store(MM, Ordering::Relaxed);
    let mut idle_frame = TrapFrame {
        slot: u64::from(other.raw()),
        ..TrapFrame::default()
    };
    let mut idle_cpu = FakeCpu::default();
    let action = Sched {
        zone: &zone,
        slot: other,
        task: &idle_task,
        cpu: &mut idle_cpu,
        user: &HardwareUserWord,
        counters,
    }
    .serve_idle_entry(&mut idle_frame);
    assert_eq!(action, carrick_el1_abi::Action::Served);
    assert_eq!(idle_frame.elr, 0xB << 12);
    assert_eq!(zone.slot(other).current(), Some(b));
    assert_eq!(zone.slot(SLOT).queued(), 0);
    assert_eq!(zone.counters.el1_steals.load(Ordering::Relaxed), 1);
    assert_eq!(idle_cpu.wfis, 0);
}

// ---------------------------------------------------------------------------
// EL1 increment 2, step 2: switching address spaces in the guest
// (contract `kernel.el1.address-space-switch`).

/// The other process of the two-process cases.
const OTHER_MM: u64 = 9;
const IDLE_TTBR: u64 = 0x0000_0000_4000_0000;
const TTBR_MM: u64 = (7 << 48) | 0x7000_0000;
const TTBR_OTHER: u64 = (9 << 48) | 0x9000_0000;

/// Publish `mm` (open) with `ttbr` the way the host does at its first load.
fn publish_space(zone: &ZoneTables, mm: u64, ttbr: u64) -> carrick_sched_core::SpaceIndex {
    zone.spaces.set_idle_ttbr(IDLE_TTBR);
    let index = zone.spaces.publish_closed(mm, ttbr, ttbr).unwrap();
    zone.spaces.open(index);
    index
}

/// Park thread `tid` of `mm` on `uaddr`, then wake it from the host into the
/// guest: it is queued, ready at EL0, on a slot in the guest that may run it
/// (here the only one, `SLOT`).
fn queue_foreign(zone: &ZoneTables, tid: u64, mm: u64, uaddr: u64, ctx: ThreadCtx) -> RecordId {
    let guard = zone
        .lock(ZoneTables::bucket_of(mm, uaddr), &HostWait)
        .unwrap();
    let record = zone
        .alloc_record(ThreadIdentity {
            mm,
            ..identity(tid)
        })
        .unwrap();
    // SAFETY: freshly allocated and unpublished.
    unsafe { *zone.record(record).ctx_mut() = ctx };
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, mm, uaddr, u32::MAX, 0)
        .unwrap();
    zone.publish_park(record, seq);
    let mut placed = 0;
    let woken = zone.wake_host(
        &guard,
        mm,
        uaddr,
        u32::MAX,
        1,
        true,
        &mut |_| panic!("no slot could run the woken thread"),
        &mut |_| placed += 1,
    );
    drop(guard);
    assert_eq!((woken, placed), (1, 1));
    record
}

/// The loaded thread A (address space 7) waits while a thread B of another
/// process (address space 9) is queued on its vCPU: EL1 parks A and runs B
/// in B's address space, with no host exit. The vCPU goes to the maintenance
/// root, publishes 9 in its occupancy slot, reads 9's gate, then installs 9's
/// roots. B's wait then hands the vCPU back to A in 7 the same way.
#[test]
fn a_futex_wait_switches_the_vcpu_to_another_process_in_guest() {
    let zone = zone();
    publish_space(&zone, MM, TTBR_MM);
    publish_space(&zone, OTHER_MM, TTBR_OTHER);
    host_publish(&zone, SLOT, MM, None, 0);
    zone.enter_guest(SLOT);
    let a_word = AtomicU32::new(0);
    let b_word = AtomicU32::new(0);
    let (a_addr, b_addr) = (a_word.as_ptr() as u64, b_word.as_ptr() as u64);
    let b = queue_foreign(&zone, 202, OTHER_MM, b_addr, thread_ctx(0xB, b_addr));
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, a_addr, FUTEX_WAIT_PRIVATE, 0);
    cpu.ttbr = (TTBR_MM, TTBR_MM);

    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(frame.elr, 0xB << 12, "B runs");
    assert_eq!(zone.slot(SLOT).current(), Some(b));
    assert_eq!(
        cpu.translations,
        [(IDLE_TTBR, IDLE_TTBR), (TTBR_OTHER, TTBR_OTHER)],
        "maintenance root, then B's roots"
    );
    assert_eq!(zone.installed_space(SLOT), OTHER_MM);
    assert_eq!(zone.slot(SLOT).mm(), MM, "the executor still has A loaded");
    assert_eq!(task.zone_mm.load(Ordering::Relaxed), OTHER_MM);
    assert_eq!(task.task_id.load(Ordering::Relaxed), 202);
    assert_eq!(zone.counters.el1_space_switches.load(Ordering::Relaxed), 1);

    // A is woken from another vCPU of its process (here the host) onto its
    // home slot; B waits and the vCPU goes back to A in address space 7.
    {
        let guard = zone
            .lock(ZoneTables::bucket_of(MM, a_addr), &HostWait)
            .unwrap();
        let woken = zone.wake_host(
            &guard,
            MM,
            a_addr,
            u32::MAX,
            1,
            true,
            &mut |_| panic!("A's home slot is in the guest"),
            &mut |_| {},
        );
        assert_eq!(woken, 1);
    }
    set_op(&mut frame, b_addr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(frame.elr, 0xA << 12, "A runs again");
    assert_eq!(cpu.ttbr, (TTBR_MM, TTBR_MM));
    assert_eq!(zone.installed_space(SLOT), MM);
    assert_eq!(task.zone_mm.load(Ordering::Relaxed), MM);
    assert_eq!(zone.counters.el1_space_switches.load(Ordering::Relaxed), 2);
    assert!(
        cpu.asid_invalidations.is_empty(),
        "no TLB flush on a switch"
    );
}

/// A raised gate (a page-table pause of B's address space, or its ASID
/// retiring) refuses the install: B goes back to the head of the run queue,
/// the vCPU holds no address space and leaves for its executor, which takes
/// B ([`ZoneTables::take_service_head`]) and loads it through the host.
#[test]
fn a_raised_gate_sends_the_thread_to_its_executor() {
    let zone = zone();
    publish_space(&zone, MM, TTBR_MM);
    let other = publish_space(&zone, OTHER_MM, TTBR_OTHER);
    host_publish(&zone, SLOT, MM, None, 0);
    zone.enter_guest(SLOT);
    let a_word = AtomicU32::new(0);
    let b_word = AtomicU32::new(0);
    let (a_addr, b_addr) = (a_word.as_ptr() as u64, b_word.as_ptr() as u64);
    let b = queue_foreign(&zone, 202, OTHER_MM, b_addr, thread_ctx(0xB, b_addr));
    zone.spaces.raise(other);
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, a_addr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(
        serve(&mut frame, &task, &zone, &mut cpu),
        Some(Served::Idle)
    );
    assert!(matches!(
        zone.record(b).claim(),
        Claim::Queued { slot, .. } if slot == SLOT
    ));
    assert_eq!(zone.slot(SLOT).current(), None);
    // The placement hint already saw the gate raised, so EL1 never left A's
    // space: the vCPU still holds exactly the space its root translates.
    assert_eq!(zone.installed_space(SLOT), MM);
    assert!(cpu.translations.is_empty());
    assert_eq!(
        zone.take_service_head(SLOT),
        Some(b),
        "the executor takes B"
    );

    // The gate raised between the hint and the install (the Dekker case):
    // the install is refused after the slot was published, and the slot is
    // emptied again (the vCPU is on the maintenance root by then).
    zone.spaces.lower(other);
    assert!(zone.spaces.is_open(OTHER_MM));
    let here = carrick_sched_core::ExecutionSlot::zone(SLOT);
    zone.occupancy.vacate_any(here);
    let index = zone.spaces.find(OTHER_MM).unwrap();
    zone.spaces.raise(index);
    assert_eq!(zone.install_space(SLOT, OTHER_MM), None);
    assert_eq!(zone.installed_space(SLOT), 0, "nothing installed");
    assert_eq!(zone.slot(SLOT).mm(), MM, "the executor still has A loaded");
    assert_eq!(zone.counters.el1_space_refusals.load(Ordering::Relaxed), 1);
}

/// A foreign-COW publication for B's address space is covered by one
/// broadcast invalidation of its ASID before its roots are installed, once.
#[test]
fn an_owed_cow_invalidation_runs_before_the_install() {
    let zone = zone();
    publish_space(&zone, MM, TTBR_MM);
    let other = publish_space(&zone, OTHER_MM, TTBR_OTHER);
    zone.spaces.note_cow(other);
    host_publish(&zone, SLOT, MM, None, 0);
    zone.enter_guest(SLOT);
    let a_word = AtomicU32::new(0);
    let b_word = AtomicU32::new(0);
    let (a_addr, b_addr) = (a_word.as_ptr() as u64, b_word.as_ptr() as u64);
    queue_foreign(&zone, 202, OTHER_MM, b_addr, thread_ctx(0xB, b_addr));
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, a_addr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert_eq!(cpu.asid_invalidations, [TTBR_OTHER]);
    assert_eq!(zone.spaces.grant(other, OTHER_MM).unwrap().cow_owed, None);
    assert_eq!(
        zone.counters.el1_cow_invalidations.load(Ordering::Relaxed),
        1
    );
}

/// A vCPU that parks in WFI holds no address space: it switches to the
/// maintenance root and empties its occupancy slot, so no pause of the
/// process it ran kicks it; the wake reinstalls the space.
#[test]
fn a_vcpu_in_wfi_holds_no_address_space() {
    let zone = zone();
    publish_space(&zone, MM, TTBR_MM);
    host_publish(&zone, SLOT, MM, None, 0);
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    cpu.ttbr = (TTBR_MM, TTBR_MM);
    let ts = libc_timespec(0, 5_000_000);
    frame.x[3] = &ts as *const [u64; 2] as u64;
    assert_eq!(serve(&mut frame, &task, &zone, &mut cpu), SWITCHED);
    assert!(cpu.wfis >= 1);
    assert_eq!(
        cpu.translations,
        [(IDLE_TTBR, IDLE_TTBR), (TTBR_MM, TTBR_MM)],
        "left for WFI, reinstalled for the timeout"
    );
    assert_eq!(zone.installed_space(SLOT), MM);
}

/// A vCPU in the idle entry (its executor has no task loaded) runs no
/// thread itself and switches no address space: a thread woken with only
/// such a vCPU in the guest goes to its host continuation, whose executor
/// loads it. (Running threads from the idle entry lost a host control claim
/// raced against the idle exit: exit_group waited forever on a sibling.)
#[test]
fn the_idle_entry_runs_no_thread_itself() {
    let zone = zone();
    publish_space(&zone, OTHER_MM, TTBR_OTHER);
    let idle = SlotId::new(6);
    host_publish(&zone, idle, 0, None, 0);
    zone.enter_guest(idle);
    let b_word = AtomicU32::new(0);
    let b_addr = b_word.as_ptr() as u64;
    let guard = zone
        .lock(ZoneTables::bucket_of(OTHER_MM, b_addr), &HostWait)
        .unwrap();
    let record = zone
        .alloc_record(ThreadIdentity {
            mm: OTHER_MM,
            ..identity(202)
        })
        .unwrap();
    // SAFETY: freshly allocated and unpublished.
    unsafe { *zone.record(record).ctx_mut() = thread_ctx(0xB, b_addr) };
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, OTHER_MM, b_addr, u32::MAX, 0)
        .unwrap();
    zone.publish_park(record, seq);
    let (mut handed, mut placed) = (0, 0);
    let woken = zone.wake_host(
        &guard,
        OTHER_MM,
        b_addr,
        u32::MAX,
        1,
        true,
        &mut |_| handed += 1,
        &mut |_| placed += 1,
    );
    drop(guard);
    assert_eq!((woken, handed, placed), (1, 1, 0), "handed to the host");
    assert_eq!(zone.installed_space(idle), 0);
    assert!(!zone.executor_has_task(idle));
}
