use carrick::elf::SegmentPerms;
use carrick::memory::AddressSpace;
use carrick::trap::{
    AARCH64_SVC_EXCEPTION_CLASS, GuestMappingPlan, HVF_PAGE_SIZE, HvfTrapEngine, TrapBackend,
    aarch64_exception_class, hvf_capabilities, is_aarch64_svc_exception,
};

#[test]
fn hvf_capabilities_report_compiled_backend() {
    let caps = hvf_capabilities();

    assert_eq!(caps.backend, TrapBackend::HypervisorFramework);
    assert_eq!(
        caps.available_on_this_host,
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    );
    assert_eq!(
        caps.implemented,
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    );
}

#[test]
fn guest_mapping_plan_rounds_regions_to_pages() {
    let image = AddressSpace::from_segments(
        0x1000,
        [(
            0x210120,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            vec![0xaa; 40],
            40,
        )],
    )
    .unwrap();

    let plan = GuestMappingPlan::from_address_space(&image).unwrap();

    assert_eq!(plan.entry, 0x1000);
    assert_eq!(plan.mappings.len(), 1);
    assert_eq!(plan.mappings[0].guest_start, 0x210000);
    assert_eq!(plan.mappings[0].offset_in_mapping, 0x120);
    assert_eq!(plan.mappings[0].mapped_size, HVF_PAGE_SIZE);
    assert_eq!(plan.mappings[0].payload_size, 40);
    assert!(plan.mappings[0].perms.execute);
}

#[test]
fn classifies_aarch64_svc_exception_syndrome() {
    let svc_syndrome = AARCH64_SVC_EXCEPTION_CLASS << 26;
    let brk_syndrome = 0x3c_u64 << 26;

    assert_eq!(
        aarch64_exception_class(svc_syndrome),
        AARCH64_SVC_EXCEPTION_CLASS
    );
    assert!(is_aarch64_svc_exception(svc_syndrome));
    assert!(!is_aarch64_svc_exception(brk_syndrome));
}

#[test]
fn hvf_engine_constructor_is_real_or_platform_gated() {
    match HvfTrapEngine::new() {
        Ok(engine) => {
            assert_eq!(engine.backend(), TrapBackend::HypervisorFramework);
        }
        Err(err) => {
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                let message = err.to_string();
                assert!(
                    message.contains("Hypervisor.framework"),
                    "unexpected HVF error: {message}"
                );
            } else {
                assert!(err.to_string().contains("only available"));
            }
        }
    }
}

#[test]
fn hvf_engine_maps_address_space_when_backend_is_available() {
    let image = AddressSpace::from_segments(
        0x4000,
        [(
            0x4000,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            0xd4200000_u32.to_le_bytes().to_vec(),
            4,
        )],
    )
    .unwrap();

    let mut engine = match HvfTrapEngine::new() {
        Ok(engine) => engine,
        Err(err) => {
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                assert!(
                    err.to_string().contains("Hypervisor.framework"),
                    "unexpected HVF error: {err}"
                );
            } else {
                assert!(err.to_string().contains("only available"));
            }
            return;
        }
    };

    let plan = engine.map_address_space(&image).unwrap();

    assert_eq!(plan.entry, 0x4000);
    assert_eq!(engine.mapped_region_count(), 1);
    assert_eq!(engine.program_counter().unwrap(), 0x4000);
}
