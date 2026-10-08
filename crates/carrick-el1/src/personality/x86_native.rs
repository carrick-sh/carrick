//! Linux policy for x86-native operations over neutral ISA context leaves.
use crate::isa::ArchError;
use crate::isa::x86::context::{self, context_words::TlsRegister};
use carrick_el1_abi::CurrentTask;
use carrick_guest_arch::UserVa;
use carrick_personality_linux::abi::x86_64::ArchPrctlOperation;
use carrick_personality_linux::entry::SyscallResult;

/// Serve Linux arch_prctl for the current task. The initial production lane
/// still lacks ZoneRecord custody; the ISA leaf's TLS projection stays private.
pub fn arch_prctl(
    task: &CurrentTask,
    operation: Option<ArchPrctlOperation>,
    address: UserVa,
) -> Result<SyscallResult, ArchError> {
    let tls = context::task_tls(task)?;
    let Some(operation) = operation else {
        return Ok(SyscallResult::new(-22));
    };
    let register = match operation {
        ArchPrctlOperation::SetFs | ArchPrctlOperation::GetFs => TlsRegister::Fs,
        ArchPrctlOperation::SetGs | ArchPrctlOperation::GetGs => TlsRegister::Gs,
        // CPUID stays enabled; this lane lacks CPUID faulting (native ENODEV).
        ArchPrctlOperation::GetCpuid => return Ok(SyscallResult::new(1)),
        ArchPrctlOperation::SetCpuid => return Ok(SyscallResult::new(-19)),
    };
    let result = match operation {
        ArchPrctlOperation::SetFs | ArchPrctlOperation::SetGs => match tls.write(register, address)
        {
            Ok(()) => 0,
            Err(ArchError::InvalidContext) => -1,
            Err(error) => return Err(error),
        },
        ArchPrctlOperation::GetFs | ArchPrctlOperation::GetGs => {
            let value = tls.read(register)?.raw().to_le_bytes();
            // SAFETY: retained eight-byte source; exact-MM transfer and the
            // task-local #PF gate guard the userspace destination.
            let copied = unsafe {
                crate::substrate::file::copy_to_user_guarded(
                    task,
                    address.raw() as *mut u8,
                    value.as_ptr(),
                    value.len(),
                )
            };
            if copied { 0 } else { -14 }
        }
        ArchPrctlOperation::GetCpuid | ArchPrctlOperation::SetCpuid => -22,
    };
    Ok(SyscallResult::new(result))
}
