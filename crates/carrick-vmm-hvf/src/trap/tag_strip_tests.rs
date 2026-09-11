use super::*;

#[test]
fn logical_hvpatch_processes_receive_distinct_vdso_rng_generations() {
    let parent = next_vdso_rng_generation();
    let child = next_vdso_rng_generation();

    assert_ne!(parent, 0);
    assert_ne!(child, 0);
    assert_ne!(parent, child);
}

static EXEC_PAYLOAD_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[test]
fn guest_mapping_plan_shares_address_space_payload() {
    let _env_guard = EXEC_PAYLOAD_ENV_LOCK.lock();
    let perms = carrick_mem::elf::SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };
    let image = carrick_mem::memory::AddressSpace::from_segments(
        0x1_0000,
        [(0x1_0000, perms, vec![0xaa; 0x4000], 0x4000)],
    )
    .expect("one valid region");

    let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");
    let cloned_plan = plan.clone();

    assert_eq!(
        plan.mappings[0].image.as_ptr(),
        image.regions()[0].bytes().as_ptr(),
        "mapping-plan construction must not copy immutable image bytes"
    );
    assert_eq!(
        cloned_plan.mappings[0].image.as_ptr(),
        plan.mappings[0].image.as_ptr(),
        "mapping-plan clones must share immutable image bytes"
    );
}

#[test]
fn global_exec_readonly_spans_preserve_rebased_ipa() {
    let va = 0x20_0000;
    let ipa = 0x5000_0000;
    let mut tables = carrick_mem::page_table::PageTableManager::new(
        carrick_mem::memory::stage1_identity_page_tables(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    tables
        .map_aliased(va, ipa, 0x20_000, true, None)
        .expect("rebase merged writable load region");

    reapply_global_exec_readonly_spans(
        &mut tables,
        &[carrick_mem::elf::RoSpan {
            start: va + 0x4000,
            len: 0x2000,
            exec: false,
        }],
    )
    .expect("restore PT_LOAD protection");

    assert_eq!(tables.translate(va + 0x4000), Some(ipa + 0x4000));
    assert!(
        !tables
            .set_readonly(va + 0x4000, 0x1000, false, None)
            .expect("span is already read-only")
            .changed,
        "reapplying the same read-only protection must be a no-op"
    );
    assert!(
        !tables
            .set_rw(va + 0x3000, 0x1000, true, None)
            .expect("prefix remains writable")
            .changed,
        "the page before the span must retain the merged mapping's RWX attributes"
    );
    assert!(
        !tables
            .set_rw(va + 0x6000, 0x1000, true, None)
            .expect("suffix remains writable")
            .changed,
        "the page after the span must retain the merged mapping's RWX attributes"
    );
}

#[test]
fn guest_mapping_plan_payload_sharing_hatch_restores_deep_copy() {
    let _env_guard = EXEC_PAYLOAD_ENV_LOCK.lock();
    let prior = std::env::var_os("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD");
    // SAFETY: no other test reads or writes this diagnostic-only variable.
    unsafe { std::env::set_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD", "0") };

    let perms = carrick_mem::elf::SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };
    let image = carrick_mem::memory::AddressSpace::from_segments(
        0x1_0000,
        [(0x1_0000, perms, vec![0xaa; 0x4000], 0x4000)],
    )
    .expect("one valid region");
    let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");

    match prior {
        Some(value) => {
            // SAFETY: restores the value this test replaced.
            unsafe { std::env::set_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD", value) };
        }
        None => {
            // SAFETY: restores the absence this test replaced.
            unsafe { std::env::remove_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD") };
        }
    }

    assert_ne!(
        plan.mappings[0].image.as_ptr(),
        image.regions()[0].bytes().as_ptr(),
        "the =0 bisection hatch must restore the pre-optimization payload copy"
    );
    assert_eq!(
        plan.mappings[0].image.as_slice(),
        image.regions()[0].bytes()
    );
}

#[test]
fn guest_mapping_plan_keeps_full_stack_extent_but_only_initialized_tail_payload() {
    let image = carrick_mem::memory::AddressSpace::from_regions(0x1_0000, Vec::new())
        .expect("empty image")
        .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
        .expect("initial stack");
    let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");
    let stack_start = carrick_mem::memory::LINUX_STACK_TOP - carrick_mem::memory::LINUX_STACK_SIZE;
    let mapping = plan
        .mappings
        .iter()
        .find(|mapping| mapping.guest_start == stack_start)
        .expect("stack mapping");

    assert_eq!(
        mapping.mapped_size,
        carrick_mem::memory::LINUX_STACK_SIZE,
        "Linux stack growth must retain the full RLIMIT_STACK extent"
    );
    assert!(mapping.offset_in_mapping > 7 * 1024 * 1024);
    assert!(mapping.image.len() < 64 * 1024);
    assert_eq!(
        mapping.offset_in_mapping + mapping.image.len() as u64,
        mapping.mapped_size,
        "the sparse payload must cover the initialized tail through stack top"
    );
    let source = image
        .regions()
        .iter()
        .find(|region| region.start == stack_start)
        .expect("source stack");
    assert_eq!(
        mapping.image.as_slice(),
        &source.bytes()[mapping.offset_in_mapping as usize..]
    );
}

#[test]
fn private_exec_file_artifact_reuses_bytes_but_each_mapping_is_cow() {
    use std::os::fd::AsRawFd;

    let source = std::sync::Arc::new(vec![0xA5; super::HVF_PAGE_SIZE as usize]);
    let first = super::cached_exec_private_file_backing(
        std::sync::Arc::clone(&source),
        super::HVF_PAGE_SIZE as usize,
    )
    .expect("cache private executable artifact");
    let second = super::cached_exec_private_file_backing(
        std::sync::Arc::clone(&source),
        super::HVF_PAGE_SIZE as usize,
    )
    .expect("reuse private executable artifact");
    assert_eq!(
        first, second,
        "the same immutable payload must reuse one artifact"
    );

    let mapped = crate::host_mapping::OwnedHostMapping::map_private_file(
        first.file.as_raw_fd(),
        0,
        super::HVF_PAGE_SIZE as usize,
    )
    .expect("map private executable artifact");
    unsafe { mapped.as_ptr().write_volatile(0x5A) };
    assert_eq!(unsafe { mapped.as_ptr().read_volatile() }, 0x5A);

    let fresh = crate::host_mapping::OwnedHostMapping::map_private_file(
        second.file.as_raw_fd(),
        0,
        super::HVF_PAGE_SIZE as usize,
    )
    .expect("map fresh private executable artifact");
    assert_eq!(
        unsafe { fresh.as_ptr().read_volatile() },
        0xA5,
        "one exec's COW write must not contaminate the cached artifact"
    );
}

#[test]
fn strips_top_16_bits() {
    // Rosetta's RWX ExecutableHeap hint, and an x86-64 high-half address.
    assert_eq!(
        strip_pointer_tag(0xffff_fff7_ff70_0000),
        0x0000_fff7_ff70_0000
    );
    assert_eq!(
        strip_pointer_tag(0xffff_ffff_fff3_a000),
        0x0000_ffff_fff3_a000
    );
    // Native (top-byte-zero) pointers are untouched.
    assert_eq!(
        strip_pointer_tag(0x0000_0001_2345_6000),
        0x0000_0001_2345_6000
    );
}
