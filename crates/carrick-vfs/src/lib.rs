// The filesystem layer was extracted wholesale from carrick-runtime, which
// allows these three crate-wide: `collapsible_if` over a guarded lock upgrade
// or a nested `if let` reads better as written, `manual_dangling_ptr` covers
// deliberate libc sentinel pointers, and `items_after_test_module` is an
// artifact of the file layout the move preserved byte-for-byte.
#![allow(
    clippy::collapsible_if,
    clippy::manual_dangling_ptr,
    clippy::items_after_test_module
)]

//! carrick-vfs: the Carrick filesystem model. The `Vfs` trait and its mount
//! table, the dentry cache, the host and in-memory backends, the root
//! filesystem and the layer cache. Names no kernel, carrier or VMM type; the
//! kernel-view filesystems (procfs, sysfs, devpts, /dev) live in
//! carrick-kernel (`carrick_kernel::vfs`) because they render kernel state.

pub mod apfs;
#[cfg(target_os = "macos")]
pub mod darwin_fs;
pub mod fs_backend;
pub mod fs_resolve_cache;
pub mod layer_cache;
pub mod overlay;
pub mod pathcodec;
pub mod rootfs;
pub mod scratch;
pub mod vfs;

// NOTE: this glob does NOT make `carrick_vfs::rootfs` mean `vfs::rootfs`.
// An explicit item beats a glob import, so `carrick_vfs::rootfs` is the OCI
// root filesystem above (`src/rootfs.rs`) and the `/` MOUNT that wraps it is
// `carrick_vfs::vfs::rootfs` (`RootFsVfs`, `OpenDispatchResult`,
// `RenameOutcome`). Rust resolves that silently, so spell the mount module in
// full at every call site.
pub use vfs::*;

// The USDT probe provider is platform-neutral and lives in
// carrick-observability. Re-exported at `crate::probes` so the backend call
// sites that fire `fs_op` read exactly as they did in carrick-runtime.
pub use carrick_observability::probes;

// The host→Linux errno translation the whole filesystem layer speaks. On
// macOS/FreeBSD/NetBSD that is carrick-host-bsd's table; on Linux the host
// errno space already IS the Linux one, so carrick-host-linux's identity hook
// is the translation. Both are leaf-crate functions — this is the name the VFS
// calls them by, not a second implementation.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
pub use carrick_host_bsd::bsd_to_linux_errno as host_to_linux_errno;
#[cfg(target_os = "linux")]
pub use carrick_host_linux::host_to_linux_errno;
