//! Production CPL0 image entry.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

macro_rules! fixture_items {
    ($($item:item)*) => {};
}
macro_rules! fixture_stmt {
    ($($tt:tt)*) => {};
}
macro_rules! fixture_expr {
    ($($tt:tt)*) => {
        false
    };
}

include!("entry.rs");
