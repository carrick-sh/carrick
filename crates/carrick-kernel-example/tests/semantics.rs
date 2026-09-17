//! Two-process semantics suite for carrick-kernel.
//!
//! Conformance regressions and Linux semantics verified against the VM-free
//! scripted backend.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "semantics/mod.rs"]
pub mod common;
#[path = "semantics/pgrp.rs"]
mod pgrp;
#[path = "semantics/pipe.rs"]
mod pipe;
#[path = "semantics/wait.rs"]
mod wait;
