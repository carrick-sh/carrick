//! N2 L1 preparatory reds on public production graph APIs.
//! These do not establish EL1 routing, MM publication or signed acceptance.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use carrick_abi::LinuxCloneFlags;
use carrick_abi::syscall::nr;
use carrick_hal::{NullHostSignalBridge, ThreadId};
use carrick_kernel::kernel::{ClonePlan, Kernel, KernelContext};
use carrick_kernel_example::{
    AddressSpace, AsidAllocator, ExampleProcess, Layout, Operand, RelocWidth, ScriptCheckpoint,
    ScriptedBackend, Step, Syscall, alloc_buffer, alloc_word, await_parked, slot, sys, write_word,
};
use carrick_observability::work_meter::WorkMetric;

struct Graph {
    asids: AsidAllocator,
    kernel: Arc<Kernel>,
    parents: [KernelContext; 2],
}

impl Graph {
    fn new() -> Self {
        let asids = AsidAllocator::new();
        let (_, root) = ExampleProcess::boot_root(
            1,
            "N2 L1 root",
            Arc::new(NullHostSignalBridge::default()),
            AddressSpace::allocate(&asids).unwrap(),
        )
        .unwrap();
        let kernel = Arc::clone(root.kernel());
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "N2 L1 peer".into(),
                None,
            )
            .unwrap();
        let tid = ThreadId::from_guest_supplied_tid(reservation.visible_child_id());
        let peer = reservation
            .prepare_with_mm_backend(AddressSpace::allocate(&asids).unwrap().mm_backend(), tid)
            .unwrap()
            .commit()
            .unwrap()
            .start_child()
            .unwrap()
            .into_parts()
            .0;
        Self {
            asids,
            kernel,
            parents: [root, peer],
        }
    }

    fn current(&self, parent: &KernelContext) -> KernelContext {
        self.kernel
            .context(parent.task().key().id, parent.thread().key().tid)
            .unwrap()
    }
}

#[test]
#[ignore = "N2 red witness: row 1/13: delayed ledger birth retains predecessor resources across exec"]
fn delayed_birth_after_exec_cannot_publish_predecessor_edges_at_1_8_32() {
    // execve(2): all other threads disappear; an old birth cannot reintroduce
    // predecessor resources after the successor has been published. This uses
    // the real ledger settlement path, not a fabricated completion queue.
    let mut observed = Vec::new();
    for n in [1, 8, 32] {
        let mut stale_births = 0;
        let graph = Graph::new();
        for parent in &graph.parents {
            let current = graph.current(parent);
            let old_files = current.resources().files();
            let mut pending = Vec::new();
            for _ in 0..n {
                let reservation = graph
                    .kernel
                    .reserve_thread_clone(
                        &current,
                        ClonePlan::from_flags(
                            LinuxCloneFlags::THREAD
                                | LinuxCloneFlags::VM
                                | LinuxCloneFlags::SIGHAND
                                | LinuxCloneFlags::FILES,
                        )
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                let tid = ThreadId::from_guest_supplied_tid(reservation.visible_tid());
                pending.push(reservation.prepare(tid).unwrap());
            }
            let exec = graph
                .kernel
                .prepare_exec_with_mm_backend(
                    &current,
                    AddressSpace::allocate(&graph.asids).unwrap().mm_backend(),
                    None,
                )
                .unwrap();
            let successor = graph.kernel.commit_exec(exec, None).unwrap();
            assert_ne!(successor.shared().mm().id(), current.shared().mm().id());
            assert!(!Arc::ptr_eq(&successor.resources().files(), &old_files));
            assert_eq!(successor.task().threads().len(), 1);

            for delayed in pending {
                let key = delayed.record_birth();
                graph.kernel.settle_thread_ledger();
                if let Some(thread) = successor
                    .task()
                    .threads()
                    .into_iter()
                    .find(|thread| thread.key() == key)
                {
                    assert_eq!(thread.key(), key);
                    let stale = graph
                        .kernel
                        .context(successor.task().key().id, key.tid)
                        .unwrap();
                    assert!(Arc::ptr_eq(&stale.resources().files(), &old_files));
                    stale_births += 1;
                }
            }
            assert_eq!(graph.kernel.registry().task_count(), 2);
        }
        observed.push(stale_births);
    }
    assert_eq!(
        observed,
        vec![0; 3],
        "stale births published after exec at 1/8/32"
    );
}

fn transfer(nr: carrick_abi::CanonicalNr, fd: usize, buffer: Operand, len: usize) -> Step {
    Step::Sys(
        Syscall::new(
            "fixture_transfer",
            nr,
            [slot(fd), buffer, len.into(), 0.into(), 0.into(), 0.into()],
        )
        .ret(len as i64),
    )
}

/// Materialize relocatable guest data through a real pipe into an allocated
/// buffer. This is fixture setup, never a replacement robust-death algorithm.
fn initialize(slot_index: usize, layout: Layout) -> [Step; 2] {
    let len = layout.bytes.len();
    [
        transfer(nr::WRITE, 1, layout.into(), len),
        transfer(nr::READ, 0, slot(slot_index), len),
    ]
}

fn robust_death(pending: bool) {
    // set_robust_list(2): death marks owned words FUTEX_OWNER_DIED.
    // https://man7.org/linux/man-pages/man2/set_robust_list.2.html
    // A robust node may follow its futex word: the signed offset is -16.
    // Separate words at identical VAs in two live MMs must stay independent.
    // The pending case covers death between lock acquisition and list linking.
    // AwaitParked records historical enrollments. Use a distinct label for
    // each round so an earlier join cannot release a later exiting owner.
    let joins = [
        "join_0", "join_1", "join_2", "join_3", "join_4", "join_5", "join_6", "join_7", "join_8",
        "join_9", "join_10", "join_11", "join_12", "join_13", "join_14", "join_15", "join_16",
        "join_17", "join_18", "join_19", "join_20", "join_21", "join_22", "join_23", "join_24",
        "join_25", "join_26", "join_27", "join_28", "join_29", "join_30", "join_31",
    ];
    let mut failures = Vec::new();
    for n in [1, 8, 32] {
        let go = ScriptCheckpoint::default();
        let finish = ScriptCheckpoint::default();
        let mut ready = Vec::new();
        let mut done = Vec::new();
        let mut script = vec![
            alloc_buffer(10, vec![0; 24]), // head
            alloc_buffer(11, vec![0; 16]), // futex plus alignment padding
            alloc_buffer(12, vec![0; 8]),  // node, exactly 16 bytes after word
            alloc_word(13, 1),             // independent clear-TID join word
        ];
        for p in 0..2 {
            let reached = ScriptCheckpoint::default();
            let completed = ScriptCheckpoint::default();
            let mut parent = vec![
                Step::SignalCheckpoint(reached.clone()),
                Step::AwaitCheckpoint(go.clone()),
                Step::Sys(sys::gettid().save(3)),
                Step::Sys(
                    sys::pipe2(0)
                        .ret(0)
                        .save_out_i32(0, 0, 0)
                        .save_out_i32(0, 1, 1),
                ),
            ];
            for join in &joins[..n] {
                parent.push(write_word(13, 1));
                parent.push(Step::Sys(sys::clone_thread(0)));
                let mut child = vec![
                    Step::Sys(sys::gettid().save(4)),
                    Step::Sys(sys::set_tid_address(slot(13))),
                ];
                child.extend(initialize(
                    11,
                    Layout::new(4).with_reloc(0, RelocWidth::U32, slot(4)),
                ));
                child.extend(initialize(
                    12,
                    Layout::new(8).with_reloc(0, RelocWidth::U64, slot(10)),
                ));
                child.extend(initialize(
                    10,
                    Layout::new(24)
                        .with_reloc(0, RelocWidth::U64, slot(if pending { 10 } else { 12 }))
                        .with_i64(8, -16)
                        .with_reloc(
                            16,
                            RelocWidth::U64,
                            if pending { slot(12) } else { 0.into() },
                        ),
                ));
                child.push(Step::Sys(
                    Syscall::new(
                        "register_robust",
                        nr::SET_ROBUST_LIST,
                        [slot(10), 24.into(), 0.into(), 0.into(), 0.into(), 0.into()],
                    )
                    .ret(0),
                ));
                child.push(Step::Sys(
                    Syscall::new(
                        "registered_robust",
                        nr::GET_ROBUST_LIST,
                        [
                            0.into(),
                            Operand::Out(8),
                            Operand::Out(8),
                            0.into(),
                            0.into(),
                            0.into(),
                        ],
                    )
                    .ret(0),
                ));
                child.push(await_parked(slot(3), join));
                child.push(Step::Sys(sys::exit_thread(0)));
                parent.push(Step::ChildMarker(child));
                parent.push(Step::Sys(sys::futex_wait_labeled(join, slot(13), 1).ret(0)));
                parent.push(transfer(nr::WRITE, 1, slot(11), 4));
                let mut read = sys::read(slot(0), 4).ret(4);
                read.label = "dead_owner_word";
                parent.push(Step::Sys(read));
            }
            parent.push(transfer(
                nr::WRITE,
                1,
                Layout::new(24)
                    .with_reloc(0, RelocWidth::U64, slot(10))
                    .with_reloc(8, RelocWidth::U64, slot(11))
                    .with_reloc(16, RelocWidth::U64, slot(12))
                    .into(),
                24,
            ));
            let mut addresses = sys::read(slot(0), 24).ret(24);
            addresses.label = "addresses";
            parent.push(Step::Sys(addresses));
            parent.extend([
                Step::SignalCheckpoint(completed.clone()),
                Step::AwaitCheckpoint(finish.clone()),
                Step::Sys(sys::exit_group(0)),
            ]);
            script.push(Step::Sys(sys::fork().save(p)));
            script.push(Step::ChildMarker(parent));
            ready.push(reached);
            done.push(completed);
        }
        script.extend(ready.into_iter().map(Step::AwaitCheckpoint));
        script.push(Step::SignalCheckpoint(go));
        script.extend(done.into_iter().map(Step::AwaitCheckpoint));
        script.push(Step::SignalCheckpoint(finish));
        for p in 0..2 {
            script.push(Step::Sys(sys::wait4(slot(p), 0)));
        }
        script.push(Step::Sys(sys::exit_group(0)));
        let run = ScriptedBackend::new().run_root(script).unwrap();
        assert_eq!(run.exit_code(), 0);
        assert!(run.deaths().is_empty());
        assert_eq!(run.tasks_started(), 3 + 2 * n);
        let snapshot = run.work_snapshot();
        assert_eq!(snapshot.dropped_events(), 0);
        assert!(snapshot.unknown_metrics().is_empty());
        assert_eq!(
            snapshot.get(WorkMetric::KernelDispatches),
            Some(run.dispatches() as u64)
        );
        let addresses = run.outputs_for("addresses");
        assert_eq!(addresses.len(), 2);
        assert_ne!(addresses[0].pid, addresses[1].pid);
        assert_eq!(addresses[0].bytes, addresses[1].bytes);
        let head = u64::from_le_bytes(addresses[0].bytes[..8].try_into().unwrap());
        let word = u64::from_le_bytes(addresses[0].bytes[8..16].try_into().unwrap());
        let node = u64::from_le_bytes(addresses[0].bytes[16..24].try_into().unwrap());
        assert_eq!(node - word, 16, "validate signed futex offset");
        let registered = run.outputs_for("registered_robust");
        assert_eq!(registered.len(), 4 * n);
        for output in registered {
            let value = u64::from_le_bytes(output.bytes[..8].try_into().unwrap());
            assert_eq!(value, if output.arg == 1 { head } else { 24 });
        }
        let words = run.outputs_for("dead_owner_word");
        assert_eq!(words.len(), 2 * n);
        // FUTEX_OWNER_DIED, with no waiter flag or remaining owner tid.
        let incorrect = words
            .iter()
            .filter(|output| {
                u32::from_le_bytes(output.bytes[..4].try_into().unwrap()) != 0x4000_0000
            })
            .count();
        failures.push(incorrect);
    }
    assert_eq!(
        failures,
        vec![0; 3],
        "robust words missing OWNER_DIED at 1/8/32 (pending={pending})"
    );
}

#[test]
#[ignore = "N2 red witness: row 2/4/7: registered robust list is not walked by scripted thread retirement"]
fn robust_list_death_marks_owned_words_in_two_live_mms_at_1_8_32() {
    robust_death(false);
}

#[test]
#[ignore = "N2 red witness: row 2/4/7: pending robust operation is not retired by scripted thread exit"]
fn robust_pending_death_marks_owned_words_in_two_live_mms_at_1_8_32() {
    robust_death(true);
}
