use live_review_repro::aarch64::{PageTableManager, HostArenaResolver};
use std::sync::Arc;
// Compile-only witness. Never call this function: it installs an invalid pointer.
// A caller with an existing valid live manager can do this using safe Rust alone.
#[allow(dead_code)]
fn rebind_from_safe_code(manager: &mut PageTableManager) {
    let resolver: Arc<dyn HostArenaResolver + Send + Sync> =
        Arc::new(|_: u64| Some(std::ptr::dangling_mut::<u64>().cast::<u8>()));
    manager.bind_resolver(resolver);
    let _ = manager.try_translate(0);
}
fn main() {}
