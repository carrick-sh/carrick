//! Hypervisor-agnostic threading primitives shared by every carrick backend:
//! the per-process thread registry, the private-futex parking table, and the
//! fork / page-table quiesce barriers. Lifted out of `carrick-vmm-hvf` so the KVM
//! (and bhyve) backends use the SAME code as HVF (build-decomposition).
pub mod fork_quiesce;
/// One `PlatformFutex` impl over the shared `FutexTable` + a per-host
/// `SharedFutexSyscall` shim (replaces the per-backend `KvmFutex`/`BhyveFutex`).
pub mod platform_futex;
pub mod thread;
