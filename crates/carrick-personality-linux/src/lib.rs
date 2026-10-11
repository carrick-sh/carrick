//! Linux interpretation of neutral owner records.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
extern crate alloc;

pub mod abi;
pub mod crossing;
pub mod dispatch;
pub mod entry;
pub mod mm;
pub mod sched;
pub mod signal;

pub mod pending_file;

pub mod pending_anonymous;

pub mod lifecycle;
pub mod thread;

pub mod identity;
pub mod ipc;
pub mod sysinfo;

pub mod native_run_failure;

use carrick_core::Personality;
use carrick_guest_arch::ThreadPointerRegister;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxPersonality;

impl Personality for LinuxPersonality {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn thread_pointer_register(&self) -> ThreadPointerRegister {
        #[cfg(target_arch = "x86_64")]
        {
            ThreadPointerRegister::FS
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            ThreadPointerRegister::TPIDR_EL0
        }
    }
}
