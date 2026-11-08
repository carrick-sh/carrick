//! CPL0 register/stdio admission for the shared retained file-service owner.
use carrick_el1_abi::CurrentTask;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::native_host_file::{HostFileCall, HostFileStage, NativeNamespace};

pub(super) fn stage(
    call: &CanonicalCall,
    task: &CurrentTask,
    cpu_slot: u32,
) -> Option<HostFileStage> {
    let decoded = HostFileCall::decode(
        carrick_syscall_abi::CanonicalNr::new(call.canonical.raw()),
        &call.args,
    )?;
    match decoded {
        HostFileCall::Read { fd, .. }
        | HostFileCall::Pread { fd, .. }
        | HostFileCall::Lseek { fd, .. }
        | HostFileCall::Getdents64 { fd, .. }
        | HostFileCall::Fstat { fd, .. }
            if (0..=2).contains(&fd) =>
        {
            return None;
        }
        HostFileCall::Openat { .. }
        | HostFileCall::Faccessat { .. }
        | HostFileCall::Statx { .. }
        | HostFileCall::Read { .. }
        | HostFileCall::Pread { .. }
        | HostFileCall::Lseek { .. }
        | HostFileCall::Getdents64 { .. }
        | HostFileCall::Fstat { .. }
        | HostFileCall::Newfstatat { .. } => {}
        _ => return None,
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
    // These two legacy stat layouts differ by ISA. Their wire binding is a
    // later slice; never let a ring descriptor reach the host task table.
    if matches!(
        decoded,
        HostFileCall::Fstat { .. } | HostFileCall::Newfstatat { .. }
    ) && matches!(staged, HostFileStage::Request { .. })
    {
        Some(HostFileStage::InRing)
    } else {
        Some(staged)
    }
}
