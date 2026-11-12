use super::*;

#[test]
fn proc_maps_projects_linux_initial_stack_vma_not_full_rlimit_backing() {
    let image = AddressSpace::from_regions(0x1_0000, Vec::new())
        .expect("empty image")
        .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
        .expect("initial stack");
    let initial_sp = image.initial_stack_pointer().expect("initial SP");
    let maps = proc_maps_from_address_space(&image);
    let stack = maps
        .iter()
        .find(|mapping| mapping.path == "[stack]")
        .expect("Linux-visible stack VMA");
    let expected_start =
        initial_sp.saturating_sub(128 * 1024) & !(crate::linux_abi::LINUX_PAGE_SIZE - 1);

    assert_eq!(stack.start, expected_start);
    assert_eq!(stack.end, crate::memory::LINUX_STACK_TOP);
    assert!(
        stack.start > crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE,
        "the full RLIMIT-sized backing is not the initially grown Linux VMA"
    );
}
