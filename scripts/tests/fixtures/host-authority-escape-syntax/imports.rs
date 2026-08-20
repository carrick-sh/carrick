#![allow(dead_code, unused_imports)]

extern crate self as libc;

pub unsafe fn syscall(_number: i64) -> i64 {
    0
}

pub unsafe fn dlopen(_path: *const i8, _flags: i32) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

pub unsafe fn dlsym(_handle: *mut core::ffi::c_void, _symbol: *const i8) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

pub unsafe fn direct_watched_paths() {
    let _ = unsafe { libc::syscall(1) };
    let _ = unsafe { ::libc::dlopen(core::ptr::null(), 0) };
    let _ = unsafe { libc::dlsym(core::ptr::null_mut(), core::ptr::null()) };
}

mod direct_libc_alias {
    use ::libc::syscall as carrier_syscall;

    pub fn keeps_alias_live() {
        let _ = carrier_syscall;
    }
}

mod grouped_libc_reexport {
    pub use ::libc::{dlopen as carrier_dlopen, dlsym};
}

mod direct_assembly_alias {
    use core::arch::asm as carrier_asm;

    pub unsafe fn execute() {
        unsafe { carrier_asm!("nop") };
    }
}

mod grouped_assembly_aliases {
    use core::arch::{asm as carrier_asm, global_asm as carrier_global_asm};

    carrier_global_asm!(".text");

    pub unsafe fn execute() {
        unsafe { carrier_asm!("nop") };
    }
}
