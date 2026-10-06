use super::*;
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
