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
    exit_target: u64,
    exit_source: u64,
    exit_status: u32,
    exit_pad: u32,
    exit_link: u64,
    exit_has_link: u32,
    exit_link_pad: u32,
}

impl DsrContext {
    fn new(snapshot: NativeUcontextSnapshot, entry: CacheVa, exit: NativeDsrExit) -> Self {
        let (exit_target, exit_source, exit_status, exit_link, exit_has_link) = match exit {
            NativeDsrExit::Syscall { resume } => (resume.raw(), 0, 1, 0, 0),
            NativeDsrExit::ResolveDirect { source, target } => {
                (target.raw(), source.raw(), 2, 0, 0)
            }
            NativeDsrExit::ResolveIndirect {
                source,
                target,
                link,
            } => (
                target.raw(),
                source.raw(),
                3,
                link.map_or(0, carrick_guest_mem::GuestVa::raw),
                u32::from(link.is_some()),
            ),
            _ => (0, 0, 0, 0, 0),
        };
        Self {
            snapshot,
            host_sp: 0,
            host_x19_x30: [0; 12],
            alignment_pad: 0,
            host_v8_v15: [[0; 16]; 8],
            entry: entry.host().raw() as u64,
            exit_target,
            exit_source,
            exit_status,
            exit_pad: 0,
            exit_link,
            exit_has_link,
            exit_link_pad: 0,
        }
    }
}

const _: () = assert!(std::mem::size_of::<NativeUcontextSnapshot>() == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, snapshot) == 0);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_sp) == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_x19_x30) == 840);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_v8_v15) == 944);
const _: () = assert!(std::mem::offset_of!(DsrContext, entry) == 1072);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_target) == 1080);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_source) == 1088);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_status) == 1096);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_link) == 1104);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_has_link) == 1112);
const _: () = assert!(std::mem::size_of::<DsrContext>() == 1120);

unsafe extern "C" {
    fn carrick_dsr_enter_raw(context: *mut DsrContext) -> libc::c_int;
    fn carrick_dsr_exit_syscall();
    fn carrick_dsr_exit_direct();
    fn carrick_dsr_exit_indirect();
}

pub(super) fn syscall_exit_address() -> u64 {
    carrick_dsr_exit_syscall as *const () as usize as u64
}

pub(super) fn direct_exit_address() -> u64 {
    carrick_dsr_exit_direct as *const () as usize as u64
}

pub(super) fn indirect_exit_address() -> u64 {
    carrick_dsr_exit_indirect as *const () as usize as u64
}

pub(super) fn enter_translated(
    entry: CacheVa,
    snapshot: &mut NativeUcontextSnapshot,
    exit: &mut NativeDsrExit,
) -> Result<(), DsrError> {
    if !matches!(
        *exit,
        NativeDsrExit::Syscall { .. }
            | NativeDsrExit::ResolveDirect { .. }
            | NativeDsrExit::ResolveIndirect { .. }
    ) {
        return Err(DsrError::Gateway(
            "DSR gateway only accepts syscall or control-flow exits".to_string(),
        ));
    }
    let mut context = DsrContext::new(*snapshot, entry, *exit);
    let rc = unsafe { carrick_dsr_enter_raw(&mut context) };
    if rc != 1 && rc != 2 && rc != 3 {
        return Err(DsrError::Gateway(format!(
            "translated entry returned invalid gateway status {rc}"
        )));
    }
    *snapshot = context.snapshot;
    *exit = match rc {
        1 => NativeDsrExit::Syscall {
            resume: carrick_guest_mem::GuestVa(context.exit_target),
        },
        2 => NativeDsrExit::ResolveDirect {
            source: carrick_guest_mem::GuestVa(context.exit_source),
            target: carrick_guest_mem::GuestVa(context.exit_target),
        },
        3 => NativeDsrExit::ResolveIndirect {
            source: carrick_guest_mem::GuestVa(context.exit_source),
            target: carrick_guest_mem::GuestVa(context.exit_target),
            link: (context.exit_has_link != 0)
                .then_some(carrick_guest_mem::GuestVa(context.exit_link)),
        },
        _ => {
            return Err(DsrError::Gateway(format!(
                "translated entry returned invalid gateway status {rc}"
            )));
        }
    };
    Ok(())
}
