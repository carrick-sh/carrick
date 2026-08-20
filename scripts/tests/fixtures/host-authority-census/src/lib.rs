pub use std::fs::read as reexported_read;
use std::process::id as imported_id;

macro_rules! local_call {
    ($expression:expr) => {
        $expression
    };
}

pub fn direct() -> u32 {
    std::process::id()
}

pub fn imported() -> u32 {
    imported_id()
}

pub fn reexported() {
    let _ = reexported_read("/fixture");
}

pub fn function_item() {
    let call = libc::waitpid;
    let _ = call;
}

pub fn local_macro() {
    local_call!(std::thread::yield_now());
}

pub fn dependency_macro() {
    fixture_macros::host_call!(std::fs::metadata("/fixture"));
}

pub fn expected() -> u32 {
    #[expect(clippy::disallowed_methods, reason = "HA-FIXTURE-EXPECTED")]
    std::process::id()
}
