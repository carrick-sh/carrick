//! CPL0 register/stdio admission for the shared retained file-service owner.
use carrick_el1_abi::CurrentTask;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::HostFileStage;

pub(super) fn stage(
    call: &CanonicalCall,
    task: &CurrentTask,
    cpu_slot: u32,
    origin: carrick_core_abi::service::ServiceOrigin,
    delegated: impl FnOnce(i32) -> bool,
) -> Option<HostFileStage> {
    let venue = carrick_el1_linux::ipc::guest_venue(cpu_slot);
    let table = venue
        .as_ref()
        .and_then(|venue| carrick_el1_linux::ipc::native_table(venue, task));
    // The ring's directories: the caller's table, and its process owner's
    // thread-group membership (#2776).
    let group = task
        .lifecycle_refs()
        .zip(task.visible_pid())
        .zip(carrick_sched_core::SlotId::from_index(cpu_slot as usize));
    let mut directories =
        venue
            .as_ref()
            .zip(table)
            .zip(group)
            .map(|((venue, table), (((page, _), pid), slot))| {
                carrick_el1_linux::dispatch::RingDirectoryVenue {
                    region: &venue.region,
                    table,
                    task_group: move |tgid| {
                        crate::native_process::registry().task_group_tids(
                            carrick_x86_carrier::native_execution::source(slot).zone,
                            page,
                            pid,
                            tgid,
                        )
                    },
                }
            });
    crate::native_stage::stage_call(
        call,
        task,
        &carrick_el1_linux::file::HardwareValidator,
        origin,
        delegated,
        || {
            let venue = venue.as_ref()?;
            let table = table?;
            Some((table, move |fd| {
                carrick_el1_linux::ipc::native_descriptor(venue, table, fd)
            }))
        },
        directories.as_mut().map(|directories| {
            directories as &mut dyn carrick_personality_linux::native_host_file::RingDirectories
        }),
    )
}
