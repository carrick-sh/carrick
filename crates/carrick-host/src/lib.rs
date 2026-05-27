//! Darwin host-primitive helpers shared by the carrick runtime: machine facts,
//! `__ulock` futex, host shared-memory mappings, guest-CPU accounting, and
//! libproc-based process introspection.
//!
//! These modules wrap macOS/libc + Mach primitives and have no dependency on
//! the runtime's dispatch/trap/VFS layers, so they live in their own leaf crate
//! to keep edits to them from recompiling the ~40k-line runtime (and vice
//! versa). `carrick-runtime` re-exports them under their original
//! `crate::<module>` paths.

pub mod guest_cpu;
pub mod host_facts;
pub mod host_mapping;
pub mod host_proc;
pub mod ulock;
