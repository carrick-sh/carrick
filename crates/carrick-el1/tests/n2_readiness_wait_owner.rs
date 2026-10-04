//! N2 rows 7/8 owner-entry reds, using the production region dispatcher.
//! The two live MM identities share a VA, not bytes. These nonblocking cases
//! isolate missing Linux owner routing before any park/hardware operation.
//! Linux authority: futex(2) value mismatch yields EAGAIN; poll(2) zero timeout
//! with an empty set yields zero. This does not prove wait-set enrollment,
//! mapping-generation custody, signal restoration, or runtime capacity release.
#![allow(clippy::unwrap_used, clippy::panic)]

use carrick_el1::{Zone, dispatch_syscall_with_regions, sched};
use carrick_el1_abi::{
    Action, Counters, CurrentTask, El1TaskId, InotifyNameCache, SlotId, ThreadCtx, TrapFrame,
    ZoneTables,
};
use core::sync::atomic::Ordering;

const SAME_VA: u64 = 0x4000_1000;

struct Words;
impl sched::UserWord for Words {
    fn read_u32(&self, task: &CurrentTask, address: u64) -> Option<u32> {
        (address == SAME_VA).then(|| task.zone_mm.load(Ordering::Acquire) as u32)
    }
    fn read_u64(&self, _: &CurrentTask, address: u64) -> Option<u64> {
        // Read-only, zero timespec for the immediate empty-set ppoll.
        [SAME_VA, SAME_VA + 8].contains(&address).then_some(0)
    }
}

struct NoSwitch;
impl sched::ThreadCpu for NoSwitch {
    fn save(&mut self, _: &TrapFrame, _: &mut ThreadCtx) {
        panic!("nonblocking operation saved context");
    }
    fn load(&mut self, _: &mut TrapFrame, _: &ThreadCtx) {
        panic!("nonblocking operation switched context");
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        panic!("unexpected translation");
    }
    fn invalidate_asid(&mut self, _: u64) {
        panic!("unexpected invalidation");
    }
    fn now(&self) -> u64 {
        1
    }
    fn freq(&self) -> u64 {
        24_000_000
    }
    fn set_timer(&mut self, _: Option<u64>) {
        panic!("nonblocking operation armed timer");
    }
    fn send_sgi(&mut self, _: u64) {
        panic!("unexpected remote wake");
    }
    fn ack_irq(&mut self) -> u32 {
        panic!("unexpected IRQ");
    }
    fn end_irq(&mut self, _: u32) {
        panic!("unexpected IRQ");
    }
    fn wait_for_interrupt(&mut self) {
        panic!("nonblocking operation idled");
    }
    fn spin(&mut self) {
        panic!("nonblocking operation spun");
    }
    fn own_sgi_target(&self) -> u64 {
        1
    }
}

fn owner_witness(nr: usize, arguments: [u64; 6], expected: i64) {
    let mut failures = Vec::new();
    for scale in [1, 8, 32] {
        // SAFETY: ZoneTables' empty ABI representation is all zero, matching
        // n2_creation_owner; direct heap allocation avoids a huge stack value.
        let zone = unsafe { Box::<ZoneTables>::new_zeroed().assume_init() };
        let tasks = [CurrentTask::new(), CurrentTask::new()];
        for (i, (task, mm)) in tasks.iter().zip([71, 83]).enumerate() {
            let space = zone.spaces.publish_closed(mm, mm << 12, mm << 12).unwrap();
            zone.spaces.open(space);
            task.set(El1TaskId::from_linux_tid(40 + i as i32), 1, 500 + i as u64);
            task.zone_mm.store(mm, Ordering::Release);
            task.thread_serial.store(100 + i as u64, Ordering::Release);
            let slot = SlotId::from_index(i).unwrap();
            zone.drive(slot, i as u64 + 1);
            zone.publish_slot(slot, mm, None, 0);
        }
        let counters = Counters::default();
        for _ in 0..scale {
            for slot in 0..2 {
                let mut frame = TrapFrame {
                    slot,
                    elr: 0x4000,
                    ..TrapFrame::default()
                };
                frame.x[8] = nr as u64;
                frame.x[..6].copy_from_slice(&arguments);
                let action = dispatch_syscall_with_regions(
                    &mut frame,
                    &counters,
                    &tasks,
                    &[],
                    &[],
                    &[],
                    &[],
                    &InotifyNameCache::new(),
                    Some(Zone {
                        tables: &zone,
                        cpu: &mut NoSwitch,
                        user: &Words,
                    }),
                    |_| core::ptr::null_mut(),
                );
                if action != Action::Served || frame.x[0] as i64 != expected {
                    failures.push(format!("nr={nr} scale={scale} slot={slot} action={action:?} result={} expected=Served/{expected}", frame.x[0] as i64));
                }
            }
        }
        let forwarded = counters.forwarded[nr].load(Ordering::Relaxed);
        let served = counters.served[nr].load(Ordering::Relaxed);
        println!(
            "n2-l3 owner nr={nr} scale={scale} two_live_mms=71,83 forwarded={forwarded} served={served} expected_forwards=0"
        );
        if forwarded != 0 || served != 2 * scale {
            failures.push(format!(
                "nr={nr} scale={scale} forwards={forwarded} served={served}"
            ));
        }
        assert_eq!(zone.counters.el1_parks.load(Ordering::Relaxed), 0);
        assert_eq!(zone.counters.host_parks.load(Ordering::Relaxed), 0);
    }
    assert!(
        failures.is_empty(),
        "N2 owner route: {}",
        failures.join("\n")
    );
}

#[test]
#[ignore = "N2 red witness: row 7: shared futex mismatch forwards to host policy"]
fn shared_futex_mismatch_is_owned_in_both_live_mms() {
    owner_witness(98, [SAME_VA, 0, 0, 0, 0, 0], -11);
}

#[test]
#[ignore = "N2 red witness: row 8: immediate ppoll forwards to host policy"]
fn empty_ppoll_timeout_is_owned_in_both_live_mms() {
    owner_witness(73, [0, 0, SAME_VA, 0, 8, 0], 0);
}
