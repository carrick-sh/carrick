//! Native fatal and host-effect transport pending the CPL0 binding.

use super::X86Backend;
use carrick_guest_arch::{CrossingBackend, FatalReport, OwnedHostRequest, RequestToken};

impl CrossingBackend for X86Backend {
    fn yield_host_effect(&mut self) -> Result<(), Self::Error> {
        carrick_x86_unbound_host_yield()
    }
    fn submit_host_request(
        &mut self,
        _request: OwnedHostRequest<Self::HostPayload>,
    ) -> Result<RequestToken<Self::HostTicket>, Self::Error> {
        carrick_x86_unbound_host_yield()
    }
    fn consume_completion(
        &mut self,
        _token: RequestToken<Self::HostTicket>,
    ) -> Result<Self::HostCompletion, Self::Error> {
        carrick_x86_unbound_host_yield()
    }
    fn leave_idle(&mut self) -> Result<(), Self::Error> {
        carrick_x86_unbound_host_yield()
    }
    fn report_fatal(&mut self, _report: FatalReport) -> ! {
        carrick_x86_unbound_entry_fatal()
    }
}

/// The ARM HVC fatal transport has no CPL0 equivalent in this module.
#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_entry_fatal() -> ! {
    // SAFETY: faulting in CPL0 is terminal for this unsupported path.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// HVC service suspension has no CPL0 transport in this kernel path yet.
#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_host_yield() -> ! {
    // SAFETY: fail closed before pretending a host effect completed.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
