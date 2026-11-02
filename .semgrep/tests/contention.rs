fn bad(r: Refusal) -> i32 {
    match r {
        // ruleid: carrick-no-contention-errno
        Refusal::Contended(ticket) => LINUX_EBUSY,
        Refusal::Guest(value) => value,
    }
}
fn fatal(r: Refusal) {
    match r {
        // ruleid: carrick-no-contention-errno
        Refusal::Contended(ticket) => Fatal::NativeServiceBusy,
        _ => (),
    }
}
fn discard(r: Refusal) {
    match r {
        // ruleid: carrick-no-ticket-wildcard
        Refusal::Contended(_) => (),
        _ => (),
    }
}
fn good(r: Refusal) {
    match r {
        // ok: carrick-no-contention-errno
        Refusal::Contended(ticket) => park_and_rerun(operation, ticket),
        _ => (),
    }
}

fn wrapped(r: Refusal) -> Result<(), i32> {
    match r {
        // ruleid: carrick-no-contention-errno
        Refusal::Contended(ticket) => Err(LINUX_EIO),
        _ => Ok(()),
    }
}
