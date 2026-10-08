use super::*;
use core::sync::atomic::Ordering;
#[test]
fn native_binding_adapter_preserves_exact_words() {
    let task = CurrentTask::new();
    task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
    task.mm.key.store(7, Ordering::Release);
    task.mm.thread_generation.store(101, Ordering::Release);
    let binding = execution_binding(&task);
    assert_eq!(binding.task.raw(), 41);
    assert_eq!(binding.generation.raw(), 11);
    assert_eq!(binding.mm.raw(), 7);
    assert_eq!(binding.thread_generation.raw(), 101);
}

#[test]
fn set_tid_address_registers_only_exact_thread_and_accepts_unmapped_pointer() {
    use carrick_el1_abi::{ThreadControlSlot, ThreadLifecyclePage};
    use carrick_guest_arch::UserVa;
    use carrick_personality_linux::thread::{LifecycleThread, set_tid_address};
    let page = ThreadLifecyclePage::new();
    let a = ThreadControlSlot::new();
    let b = ThreadControlSlot::new();
    assert!(a.publish_visible_tid(41));
    assert!(b.publish_visible_tid(42));
    let task = CurrentTask::new();
    task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
    task.mm.key.store(7, Ordering::Release);
    task.mm.thread_generation.store(101, Ordering::Release);
    let binding = execution_binding(&task);
    assert_eq!(
        set_tid_address(
            LifecycleThread {
                page: &page,
                slot: &a
            },
            binding,
            UserVa::new(u64::MAX)
        )
        .map(|v| v.raw()),
        Some(41)
    );
    assert_eq!(a.clear_child_tid(), u64::MAX);
    assert_eq!(b.clear_child_tid(), 0);
    assert!(
        set_tid_address(
            LifecycleThread {
                page: &page,
                slot: &b
            },
            binding,
            UserVa::new(0x9000)
        )
        .is_none()
    );
    assert_eq!(b.clear_child_tid(), 0);
    assert_eq!(
        set_tid_address(
            LifecycleThread {
                page: &page,
                slot: &a
            },
            binding,
            UserVa::new(0)
        )
        .map(|v| v.raw()),
        Some(41)
    );
    assert_eq!(a.clear_child_tid(), 0);
}
