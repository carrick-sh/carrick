use carrick_el1_abi::*;
fn main() {
    let regions = [
        ("image", EL1_IMAGE_OFFSET, EL1_IMAGE_SIZE),
        ("counters", EL1_COUNTERS_OFFSET, EL1_COUNTERS_SIZE),
        ("stacks", EL1_STACKS_OFFSET, EL1_STACKS_SIZE),
        ("current_tasks", EL1_CURRENT_TASKS_OFFSET, EL1_CURRENT_TASKS_SIZE),
        ("objects", EL1_OBJECT_TABLE_OFFSET, EL1_OBJECT_TABLE_SIZE),
        ("fd_map", EL1_FD_MAP_OFFSET, EL1_FD_MAP_SIZE),
        ("open_files", EL1_OPEN_FILE_TABLE_OFFSET, EL1_OPEN_FILE_TABLE_SIZE),
        ("file_cache", EL1_CACHE_OFFSET, EL1_CACHE_SIZE),
        ("inotify", EL1_INOTIFY_TABLE_OFFSET, EL1_INOTIFY_TABLE_SIZE),
        ("name_cache", EL1_NAME_CACHE_OFFSET, EL1_NAME_CACHE_SIZE),
        ("scheduler_zone", EL1_ZONE_OFFSET, EL1_ZONE_SIZE),
    ];
    let mut end = 0;
    let mut free = 0;
    let mut heap_free = 0;
    for (name, start, len) in regions {
        assert!(start >= end, "overlap at {name}");
        assert!(start.checked_add(len).is_some_and(|x| x <= EL1_REGION_SIZE));
        if start > end {
            println!("unassigned offset={end:#x} end={start:#x} bytes={}", start-end);
            free += start-end;
            heap_free += start.saturating_sub(end.max(EL1_HEAP_OFFSET));
        }
        println!("reserved {name} offset={start:#x} end={:#x} bytes={len}", start+len);
        end=start+len;
    }
    assert_eq!(end, EL1_REGION_SIZE);
    println!("region_base={EL1_REGION_BASE:#x} region_size={EL1_REGION_SIZE} unassigned_total={free} nominal_heap_size={EL1_HEAP_SIZE} unassigned_in_nominal_heap={heap_free}");
}
