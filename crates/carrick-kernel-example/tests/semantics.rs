//! Two-process semantics suite for carrick-kernel.
//!
//! Conformance regressions and Linux semantics verified against the VM-free
//! scripted backend.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "semantics/mod.rs"]
pub mod common;
#[path = "semantics/futex.rs"]
mod futex;
#[path = "semantics/pgrp.rs"]
mod pgrp;
#[path = "semantics/pipe.rs"]
mod pipe;
#[path = "semantics/threads.rs"]
mod threads;
#[path = "semantics/wait.rs"]
mod wait;

#[path = "semantics/epoll.rs"]
mod epoll;
#[path = "semantics/pidfd.rs"]
mod pidfd;
#[path = "semantics/unix.rs"]
mod unix;

#[path = "semantics/fork_scaling.rs"]
mod fork_scaling;
#[path = "semantics/futex_contention.rs"]
mod futex_contention;
#[path = "semantics/identity.rs"]
mod identity;
#[path = "semantics/signal.rs"]
mod signal;

#[path = "semantics/inotify_watch.rs"]
mod inotify_watch;
