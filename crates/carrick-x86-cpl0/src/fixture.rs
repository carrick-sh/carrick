//! Fixture image with synthetic observation syscalls.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

macro_rules! fixture_items { ($($item:item)*) => { $($item)* }; }
macro_rules! fixture_stmt { ($($tt:tt)*) => { $($tt)* }; }
macro_rules! fixture_expr { ($($tt:tt)*) => { $($tt)* }; }

include!("entry.rs");
