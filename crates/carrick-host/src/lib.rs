//! Darwin host-primitive helpers shared by the carrick runtime.
//!
//! THEORY OF OPERATION
//!
//! carrick runs an unmodified Linux process as a native macOS process and has
//! NO guest Linux kernel: every Linux behaviour a guest observes has to be
//! synthesised, ultimately, from a macOS/Mach primitive. This crate is the
//! lowest layer of that synthesis — the thin, self-contained wrappers around the
//! Darwin facilities the runtime leans on most, with the project's governing
//! rule baked in: **the macOS kernel is the source of truth.** Where Linux asks
//! a question the host can answer directly (how many CPUs, how much CPU has this
//! process burned, what is this process's state, what is the hostname), we ask
//! the host kernel rather than fabricate or hardcode an answer. That keeps the
//! emulation fork-coherent and correct across a process tree without carrick
//! having to maintain shadow bookkeeping that a `fork(2)` would desynchronise.
//!
//! The five modules and the host fact each turns into a Linux surface:
//!
//!  - [`host_facts`] — process-invariant machine facts, chiefly the
//!    Linux-visible logical-CPU count (from `sysctl`, preferring the Apple
//!    Silicon performance cluster) and the short hostname (from
//!    `gethostname`, sanitised to an RFC-1123 nodename). Backs
//!    `sched_getaffinity`, `getcpu`, `/proc/cpuinfo`, `uname`, `/etc/hosts`.
//!  - [`guest_cpu`] — per-vCPU guest CPU-time accounting. The crux: HVF guest
//!    execution does NOT accrue to the host thread's rusage (it runs inside the
//!    hypervisor, not the carrick thread), so `proc_pid_rusage` under-reports a
//!    guest's CPU burn by ~40×. This module times `hv_vcpu_run` instead, lock-
//!    free across vCPU threads, and reconciles reaped-child CPU through a
//!    fork-shared table. Source of truth for `getrusage`/`times`/`/proc/stat`.
//!  - [`host_proc`] — libproc/Mach process introspection. Because carrick forks
//!    each guest as a real macOS process and the guest pid IS the host pid, the
//!    host kernel is the source of truth for another guest's `/proc/<pid>/`
//!    state, identity, and resource usage — with a ppid-chain guard so a guest
//!    can only ever read carrick's own descendants, never arbitrary host procs.
//!  - [`host_mapping`] — RAII ownership ([`host_mapping::OwnedHostMapping`]) of
//!    the host `mmap` regions that back guest HVF mappings, so a failed
//!    `hv_vm_map` rolls the host mapping back locally. Distinguishes shared-anon,
//!    private-anon, child-snapshot, and live `MAP_SHARED`-of-file backings.
//!  - [`ulock`] — cross-PROCESS futex. macOS has no `futex(2)`; a guest FUTEX on
//!    a real `MAP_SHARED` page is an inter-process rendezvous (LTP
//!    `tst_checkpoint`), so this wraps the public `os_sync_wait_on_address`
//!    SHARED ops, which key on the physical page and therefore work across the
//!    forked carrick processes that share that page.
//!
//! WHY THIS IS ITS OWN LEAF CRATE
//!
//! None of these modules depend on the runtime's dispatch/trap/VFS layers — they
//! bottom out in libc/Mach — so they live in their own crate to keep edits to
//! them from recompiling the ~41k-line runtime (and vice versa). They are the
//! `cfg(target_os = "macos")` floor of the system: each module ships a non-macOS
//! stub so the workspace still type-checks and unit-tests off-Darwin, even
//! though the real behaviour only exists on Apple Silicon. `carrick-runtime`
//! re-exports every module here under its original `crate::<module>` path, so
//! call sites are unchanged.

pub mod guest_cpu;
pub mod host_facts;
pub mod host_mapping;
pub mod host_proc;
pub mod ulock;
