//! Enrollment predicate shared by the signed witness and its VM-free check.
use carrick_kernel::kernel::continuation::ContinuationDiagnostic;

pub fn enrolled_read(wait: Option<&ContinuationDiagnostic>) -> bool {
    wait.is_some_and(|wait| {
        wait.family == "wait-on-fds"
            && wait.registration.as_ref().is_some_and(|registration| {
                registration.service_alive
                    && registration.state == "enrolled"
                    && registration.event.is_none()
                    && registration
                        .poll_fds
                        .iter()
                        .any(|fd| fd.events & libc::POLLIN != 0)
            })
    })
}
