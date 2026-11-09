//! CPL0 register/stdio admission for the shared retained file-service owner.
use carrick_el1_abi::CurrentTask;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::{HostFileCall, HostFileStage, NativeNamespace};

pub(super) fn stage(
    call: &CanonicalCall,
    task: &CurrentTask,
    cpu_slot: u32,
    origin: carrick_core_abi::service::ServiceOrigin,
) -> Option<HostFileStage> {
    let decoded = HostFileCall::decode(
        carrick_syscall_abi::CanonicalNr::new(call.canonical.raw()),
        &call.args,
    )?;
    // Descriptor-based reads remain on their existing route until slice 3
    // binds retained read/output preparation for every descriptor population.
    let mutation = decoded.uses_child_mutation_venue();
    if (mutation && origin == carrick_core_abi::service::ServiceOrigin::Initial)
        || (!mutation
            && !matches!(
                decoded,
                HostFileCall::Openat { .. }
                    | HostFileCall::Faccessat { .. }
                    | HostFileCall::Statx { .. }
            ))
    {
        return None;
    }
    let Some(venue) = carrick_el1_linux::ipc::guest_venue(cpu_slot) else {
        return Some(HostFileStage::InRing);
    };
    let Some(table) = carrick_el1_linux::ipc::native_table(&venue, task) else {
        return Some(HostFileStage::InRing);
    };
    let mut resolve = |fd| carrick_el1_linux::ipc::native_descriptor(&venue, table, fd);
    let mut releases = |_: &mut [carrick_core_abi::host_file::MapSourceReply]| 0;
    let staged = carrick_el1_linux::dispatch::stage_native_host_file(
        decoded,
        task,
        &carrick_el1_linux::file::HardwareValidator,
        &mut NativeNamespace {
            table,
            resolve: &mut resolve,
            releases: &mut releases,
        },
    )
    .unwrap_or(HostFileStage::InRing);
    Some(staged)
}
