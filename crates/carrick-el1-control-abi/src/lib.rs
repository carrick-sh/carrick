//! Guest-facing constants of Carrick's private EL1 test and diagnostic
//! control syscall.
//!
//! Signed guest fixtures (`fixtures/embed-el1-sched`) issue this syscall and
//! compare its return values. They depend on this dependency-free leaf crate
//! rather than on `carrick-el1-abi`, whose closure spans the kernel cores:
//! every crate in a fixture's path-dependency closure is an input of the
//! signed fixture bundle, so a kernel-only commit must not reach it.
//! `carrick-el1-abi` re-exports these items and asserts they stay identical.
#![no_std]

/// Unaliased Carrick-private test and diagnostic control syscall number
/// (outside the Linux 0..500 syscall space).
pub const SYS_CARRICK_EL1_CONTROL: u64 = 0xCA88_0001;

/// Test/control return used only to ask the caller to cross an EL0 host-work
/// boundary and retry after an asynchronous metadata request completes.
pub const METADATA_GRANT_PENDING: u64 = u64::MAX - 1;
