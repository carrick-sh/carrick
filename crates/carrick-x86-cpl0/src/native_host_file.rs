//! CPL0 register/stdio admission for the shared retained file-service owner.
use carrick_el1_abi::CurrentTask;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::HostFileStage;

pub(super) fn stage(
    call: &CanonicalCall,
    task: &CurrentTask,
    cpu_slot: u32,
    origin: carrick_core_abi::service::ServiceOrigin,
) -> Option<HostFileStage> {
    crate::native_stage::stage_call(
        call,
        task,
        &carrick_el1_linux::file::HardwareValidator,
        origin,
        || {
            let venue = carrick_el1_linux::ipc::guest_venue(cpu_slot)?;
            let table = carrick_el1_linux::ipc::native_table(&venue, task)?;
            Some((table, move |fd| {
                carrick_el1_linux::ipc::native_descriptor(&venue, table, fd)
            }))
        },
    )
}
