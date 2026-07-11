#![allow(dead_code)] // Additional typed exits consume the same context in later tasks.

use super::super::NativeUcontextSnapshot;
use super::types::{CacheVa, DsrError, NativeDsrExit};

#[repr(C, align(16))]
struct DsrContext {
    snapshot: NativeUcontextSnapshot,
    host_sp: u64,
    host_x19_x30: [u64; 12],
    alignment_pad: u64,
    host_v8_v15: [[u8; 16]; 8],
    entry: u64,
    exit_resume: u64,
}

impl DsrContext {
    fn new(snapshot: NativeUcontextSnapshot, entry: CacheVa, exit_resume: u64) -> Self {
        Self {
            snapshot,
            host_sp: 0,
            host_x19_x30: [0; 12],
            alignment_pad: 0,
            host_v8_v15: [[0; 16]; 8],
            entry: entry.host().raw() as u64,
            exit_resume,
        }
    }
}

const _: () = assert!(std::mem::size_of::<NativeUcontextSnapshot>() == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, snapshot) == 0);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_sp) == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_x19_x30) == 840);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_v8_v15) == 944);
const _: () = assert!(std::mem::offset_of!(DsrContext, entry) == 1072);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_resume) == 1080);
const _: () = assert!(std::mem::size_of::<DsrContext>() == 1088);

unsafe extern "C" {
    fn carrick_dsr_enter_raw(context: *mut DsrContext) -> libc::c_int;
    fn carrick_dsr_exit_syscall();
}

pub(super) fn syscall_exit_address() -> u64 {
    carrick_dsr_exit_syscall as *const () as usize as u64
}

pub(super) fn enter_translated(
    entry: CacheVa,
    snapshot: &mut NativeUcontextSnapshot,
    exit: &mut NativeDsrExit,
) -> Result<(), DsrError> {
    let exit_resume = match *exit {
        NativeDsrExit::Syscall { resume } => resume.raw(),
        _ => {
            return Err(DsrError::Gateway(
                "Task 5 gateway only accepts syscall exits".to_string(),
            ));
        }
    };
    let mut context = DsrContext::new(*snapshot, entry, exit_resume);
    let rc = unsafe { carrick_dsr_enter_raw(&mut context) };
    if rc != 1 {
        return Err(DsrError::Gateway(format!(
            "translated entry returned invalid gateway status {rc}"
        )));
    }
    *snapshot = context.snapshot;
    Ok(())
}
