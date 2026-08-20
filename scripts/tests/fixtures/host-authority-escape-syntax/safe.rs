#![allow(dead_code, unused_macros)]

use core::ffi::CStr;

// libc::syscall(1); unsafe extern "C" { fn waitpid(); }
/* core::arch::asm!("nop"); */
const NORMAL: &str = "libc::dlsym(0, 0)";
const RAW: &str = r##"global_asm!(".text")"##;
const BYTES: &[u8] = br#"#[link_name = "kill"]"#;
const C_STRING: &CStr = c"extern { fn open(); }";

fn labelled<'asm>(value: &'asm str) {
    'libc: loop {
        break 'libc;
    }
    let _ = ('x', b'x', value);
}

trait SafeTrait {
    fn waitpid(&self, pid: i32) -> i32;
}

macro_rules! documentation_only {
    () => {{ "libc::syscall(1)" }};
}

macro_rules! compiler_catalog_owned {
    () => {{ std::process::id() }};
}
