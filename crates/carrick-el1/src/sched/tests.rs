#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate std;

use super::*;
use carrick_el1_abi::{
    Claim, Counters, DelegatedFile, DelegatedInotify, DelegatedOpenFile, El1TaskId, FdMapSlot,
    InotifyNameCache,
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
    }
}

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
        sp_el0: ctx.sp_el0,
        tpidr_el0: ctx.tpidr_el0,
        tpidrro_el0: ctx.tpidrro_el0,
        contextidr_el1: ctx.contextidr_el1,
        v: ctx.v,
        fpsr: ctx.fpsr,
        fpcr: ctx.fpcr,
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
    let user = HardwareUserWord;
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &user),
        Some(Served { switched: false })
    );
    assert_eq!(frame.x[0], 1, "one waiter woken");
    assert_eq!(zone.record(b).claim(), Claim::Queued { slot: SLOT, seq: 1 });

    // A waits: it parks and the vCPU switches to B.
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    let a_before_wait = (frame, cpu.clone());
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &user),
        Some(Served { switched: true })
    );
    assert_eq!(frame.x[0], 0, "B's wait returns 0");
    assert_eq!(frame.elr, 0xB << 12);
    assert_eq!(task.task_id.load(Ordering::Relaxed), 202);
    assert_eq!(task.thread_serial.load(Ordering::Relaxed), 1202);
    let a = zone.slot(SLOT).current();
    assert_eq!(a, Some(b), "B is the switched-in record");

    // B runs and uses its FP/SIMD registers.
    cpu.v[0] ^= 0xdead;
    cpu.fpcr ^= 1;

    // B wakes A and waits; A comes back.
    set_op(&mut frame, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &user),
        Some(Served { switched: false })
    );
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &user),
        Some(Served { switched: true })
    );
    assert_eq!(task.task_id.load(Ordering::Relaxed), 101);
    (a_before_wait.0, a_before_wait.1, frame, cpu)
}

#[test]
fn a_futex_handoff_switches_threads_in_guest_and_preserves_state() {
    let (mut before, before_cpu, after, after_cpu) = ping_pong(false);
    before.x[0] = 0; // the wait's return value
    assert_eq!(after, before, "A resumes with exactly its registers");
    assert_eq!(
        after_cpu, before_cpu,
        "and its SP_EL0, TLS, CONTEXTIDR, FP/SIMD"
    );
}

/// Negative control: a switch that does not save FP/SIMD is caught.
#[test]
fn a_switch_without_fpsimd_save_is_detected() {
    let (_, before_cpu, _, after_cpu) = ping_pong(true);
    assert_ne!(after_cpu.v, before_cpu.v);
    assert_ne!(after_cpu.fpcr, before_cpu.fpcr);
}

#[test]
fn a_wait_with_nothing_to_switch_to_forwards() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAIT_PRIVATE, 0);
    let copy = frame;
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &HardwareUserWord),
        None
    );
    assert_eq!(frame, copy, "a forward leaves the frame unchanged");
    assert_eq!(zone.counters.el1_parks.load(Ordering::Relaxed), 0);
}

#[test]
fn a_wait_on_a_changed_word_returns_eagain_without_parking() {
    let zone = zone();
    let word = AtomicU32::new(5);
    let uaddr = word.as_ptr() as u64;
    let task = task_for(101);
    let b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert!(serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &HardwareUserWord).is_some());
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 4);
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &HardwareUserWord),
        Some(Served { switched: false })
    );
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
    let user = HardwareUserWord;
    for (op, timeout, count, bitset) in [
        (0u64, 0u64, 0u64, 0u64),             // non-private wait
        (1, 0, 1, 0),                         // non-private wake
        (FUTEX_WAIT_PRIVATE, 0x1000, 0, 0),   // timed wait
        (FUTEX_WAKE_PRIVATE, 0, 0, 0),        // wake 0 (the host decides)
        (FUTEX_WAIT_BITSET_PRIVATE, 0, 0, 0), // bitset 0 is EINVAL
        (128 | 3, 0, 1, 0),                   // requeue
        (128 | 4, 0, 1, 0),                   // cmp_requeue
        (256 | FUTEX_WAIT_PRIVATE, 0, 0, 0),  // clock-realtime flag
    ] {
        let (mut frame, mut cpu) = live(0xA, uaddr, op, count);
        frame.x[3] = timeout;
        frame.x[5] = bitset;
        assert_eq!(
            serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &user),
            None,
            "op {op:#x}"
        );
    }
    let (mut frame, mut cpu) = live(0xA, uaddr + 1, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &user),
        None,
        "unaligned"
    );
    let off = CurrentTask::new();
    let (mut frame, mut cpu) = live(0xA, uaddr, FUTEX_WAKE_PRIVATE, 1);
    assert_eq!(
        serve_futex(&mut frame, SLOT, &off, &zone, &mut cpu, &user),
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
    assert_eq!(
        serve_futex(&mut frame, SLOT, &task, &zone, &mut cpu, &HardwareUserWord),
        Some(Served { switched: false })
    );
    assert_eq!(frame.x[0], 0);
    assert!(matches!(zone.record(b).claim(), Claim::Parked { .. }));
}

/// While a woken thread waits on the run queue, any other syscall leaves
/// through the host (which takes the woken thread at that exit).
#[test]
fn queued_threads_send_other_syscalls_to_the_host() {
    let zone = zone();
    let word = AtomicU32::new(0);
    let uaddr = word.as_ptr() as u64;
    let tasks = [
        CurrentTask::new(),
        CurrentTask::new(),
        CurrentTask::new(),
        task_for(101),
    ];
    let _b = host_park(&zone, 202, uaddr, thread_ctx(0xB, uaddr));
    let counters = Counters::default();
    let fd_map = [FdMapSlot::new()];
    let objects = [DelegatedFile::new()];
    let opens = [DelegatedOpenFile::new()];
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
    frame.x[8] = 62; // lseek
    assert_eq!(run(&mut frame, &mut cpu), carrick_el1_abi::Action::Forward);
    assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 1);
    // A pending host kick forwards even a servable futex call.
    tasks[3].mark_pending_host_work();
    set_op(&mut frame, uaddr, FUTEX_WAIT_PRIVATE, 0);
    assert_eq!(run(&mut frame, &mut cpu), carrick_el1_abi::Action::Forward);
}
