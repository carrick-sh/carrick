#![allow(unused_macros)]

macro_rules! fully_qualified_asm {
    () => {{ unsafe { core::arch::asm!("nop") } }};
}

macro_rules! canonical_asm {
    () => {{ unsafe { asm!("nop") } }};
}

macro_rules! fully_qualified_global_asm {
    () => {
        core::arch::global_asm!(".text");
    };
}

macro_rules! canonical_global_asm {
    () => {
        global_asm!(".text");
    };
}

macro_rules! raw_syscall {
    () => {{ unsafe { libc::syscall(1) } }};
}

macro_rules! dynamic_load {
    () => {{ unsafe { libc::dlopen(core::ptr::null(), 0) } }};
}

macro_rules! dynamic_symbol {
    () => {{ unsafe { libc::dlsym(core::ptr::null_mut(), core::ptr::null()) } }};
}
