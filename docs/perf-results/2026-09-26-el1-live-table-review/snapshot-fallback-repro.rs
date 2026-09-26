use live_review_repro::aarch64::*;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
struct Backing { words: Box<[AtomicU64]>, available: AtomicBool }
// Allocation remains resident throughout every access. Revocation only removes resolution.
unsafe impl HostArenaResolver for Backing {
 fn host_ptr_for_base(&self, _:u64)->Option<*mut u8> {
  self.available.load(Ordering::Acquire).then_some(self.words.as_ptr().cast_mut().cast())
 }
}
#[test]
fn snapshot_failure_must_not_clone_live_authority() {
 let backing=Arc::new(Backing { words:(0..65536).map(|_|AtomicU64::new(0)).collect(), available:AtomicBool::new(true) });
 let resolver:Arc<dyn HostArenaResolver+Send+Sync>=backing.clone();
 let manager=unsafe { PageTableManager::new_live(0x100000,PageTableLayoutConfig::new(0,524288,0,0),524288,resolver).unwrap() };
 backing.available.store(false,Ordering::Release);
 assert!(manager.snapshot_image().is_err());
 let clone=manager.clone();
 assert!(!clone.is_live(), "failed snapshot silently returned shared live authority");
}
