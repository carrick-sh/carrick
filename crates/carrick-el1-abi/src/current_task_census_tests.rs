//! The current-task census names each slot's loaded task and service notice.
#![allow(clippy::unwrap_used)]
extern crate std;

use super::{CurrentTask, Ordering, write_current_tasks_census};
use carrick_core_abi::SnapshotGeneration;
use carrick_core_abi::service::ServiceSelector;
use carrick_sched_core::{RecordId, RecordRef};
use std::string::String;

#[test]
fn current_task_census_names_a_stranded_service_notice_per_slot() {
    let tasks = [CurrentTask::new(), CurrentTask::new(), CurrentTask::new()];
    let mut empty = String::new();
    write_current_tasks_census(&tasks, &mut empty).unwrap();
    assert!(empty.is_empty(), "{empty}");

    // Slot 0 keeps a published notice after its task was unloaded: the
    // #2620 shape a hang leaves behind.
    tasks[0]
        .service_notice
        .publish(ServiceSelector {
            record: RecordRef {
                id: RecordId::from_raw(7).unwrap(),
                incarnation: 2,
            },
            execution: SnapshotGeneration::INITIAL,
            sequence: core::num::NonZeroU64::new(4).unwrap(),
        })
        .unwrap();
    tasks[2].execution.task.store(41, Ordering::Relaxed);
    tasks[2].mm.key.store(9, Ordering::Relaxed);
    tasks[2].publish_visible_pid(41);
    let mut census = String::new();
    write_current_tasks_census(&tasks, &mut census).unwrap();
    let lines: std::vec::Vec<&str> = census.lines().collect();
    assert_eq!(lines.len(), 2, "{census}");
    assert!(
        lines[0].starts_with("el1 task slot 0: tid=0 ")
            && lines[0].ends_with(&std::format!(
                "service_notice=record=7 incarnation=2 execution={} sequence=4",
                SnapshotGeneration::INITIAL.raw()
            )),
        "{census}"
    );
    assert!(
        lines[1].starts_with("el1 task slot 2: tid=41 ")
            && lines[1].contains(" mm=9 ")
            && lines[1].contains(" pid=41 ")
            && lines[1].ends_with("service_notice=empty"),
        "{census}"
    );
}
