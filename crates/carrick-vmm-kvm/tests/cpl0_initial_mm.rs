//! Live KVM witness: a static x86 ELF enters through the shared CPL0 MM owner.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use carrick_mem::x86_initial_image::prepare_static_x86_elf;
use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_entry::OBSERVE_INITIAL_MM;
use std::path::PathBuf;

fn image() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0-fixture")
}

fn tiny_elf() -> Vec<u8> {
    let mut bytes = vec![0; 0xc0];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_00b0_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0xc0u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    // mov eax,231; mov edi,7; syscall; ud2. No libc or host ELF loader.
    bytes[0xb0..0xbe].copy_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    bytes
}

fn write_then_exit_elf(pointer: u64, count: u32) -> Vec<u8> {
    let mut bytes = tiny_elf();
    let mut code = vec![0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0]; // write(1, ...)
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, pointer
    code.extend_from_slice(&pointer.to_le_bytes());
    code.push(0xba); // mov edx, count
    code.extend_from_slice(&count.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x89, 0xc7]); // syscall; mov edi, eax
    code.extend_from_slice(&[0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]);
    let end = 0xb0 + code.len();
    bytes.resize(end, 0);
    bytes[96..104].copy_from_slice(&(end as u64).to_le_bytes());
    bytes[0xb0..end].copy_from_slice(&code);
    bytes
}

#[test]
fn initial_write_returns_prefix_or_efault_without_aborting_carrier() {
    for (pointer, count, expected_exit, expected_bytes) in [
        (0x400ff0, 0x10_0001, 16, 16),
        (0x7_0000, 32, 242, 0), // -EFAULT = -14, low exit byte 242
    ] {
        let elf = write_then_exit_elf(pointer, count);
        let image = prepare_static_x86_elf(&elf).expect("static write ELF");
        let extent =
            Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("initial grant extent");
        let mut carrier = Cpl0Carrier::boot_production(extent).expect("production KVM boot");
        carrier
            .load_guest_mm(&image, &[], &[])
            .expect("shared MM owner");
        let mut observed_bytes = 0;
        let (status, _) = carrier
            .run_initial_process(8, |fd, bytes| {
                assert_eq!(fd, 1);
                observed_bytes += bytes.len();
                bytes.len() as i64
            })
            .expect("bounded initial process completion");
        assert_eq!(status, expected_exit);
        assert_eq!(observed_bytes, expected_bytes);
    }
}

#[test]
fn explicit_initial_process_cancel_stops_without_a_deadline() {
    let elf = tiny_elf();
    let image = prepare_static_x86_elf(&elf).expect("static ELF");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("initial grant extent");
    let mut carrier = Cpl0Carrier::boot_production(extent).expect("production KVM boot");
    carrier
        .load_guest_mm(&image, &[], &[])
        .expect("shared MM owner");
    carrier
        .fixture_cancel_next_run(0)
        .expect("cancel stopped vCPU");
    let error = carrier
        .run_initial_process(8, |_, _| 0)
        .expect_err("cancel must interrupt KVM_RUN");
    assert!(
        error.to_string().contains("initial process cancelled"),
        "{error}"
    );
}

#[test]
fn shared_guest_owner_loads_static_elf_and_exits_seven() {
    let elf = tiny_elf();
    let plan = prepare_static_x86_elf(&elf).expect("shared ELF parser");
    assert_eq!(
        (plan.entry, plan.phdr, plan.phent, plan.phnum),
        (0x4000b0, 0x400040, 56, 1)
    );
    assert_eq!(plan.regions.len(), 1);
    assert!(plan.regions[0].perms.execute && !plan.regions[0].perms.write);
    let mut program = vec![0x48, 0xbf]; // mov rdi, staged ELF pointer
    program.extend_from_slice(&0x10100u64.to_le_bytes());
    program.extend_from_slice(&[0x48, 0xbe]); // mov rsi, ELF length
    program.extend_from_slice(&(elf.len() as u64).to_le_bytes());
    program.extend_from_slice(&[0x48, 0xb8]); // mov rax, owner request
    program.extend_from_slice(&OBSERVE_INITIAL_MM.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    program.resize(0x100, 0x90);
    program.extend_from_slice(&elf);
    let mut carrier = Cpl0Carrier::boot(&image(), [&program, &program]).expect("real KVM image");
    let observed = carrier.observe(0).expect("static ELF exit");
    assert_eq!(observed.result, 7);
    assert_eq!(observed.semantic_host_exits, 0);
}

#[test]
fn production_extent_cannot_alias_kernel_metadata() {
    use carrick_el1_abi::{EL1_DYNAMIC_METADATA_SIZE, X86_CPL0_DYNAMIC_METADATA_BASE};

    let extent_bytes = 192 * 1024 * 1024 + 4096;
    let mut carrier = Cpl0Carrier::boot_production(extent_bytes).expect("production KVM image");
    let elf = tiny_elf();
    let image = prepare_static_x86_elf(&elf).expect("static ELF");
    carrier
        .load_guest_mm(&image, &[], &[])
        .expect("shared MM owner");

    let extent_va = carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_VA;
    let extent_end = extent_va + extent_bytes as u64;
    let metadata_end = X86_CPL0_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE;
    assert!(
        extent_end <= X86_CPL0_DYNAMIC_METADATA_BASE || extent_va >= metadata_end,
        "initial extent aliases the dynamic metadata aperture"
    );
}

#[test]
fn production_boot_binds_both_kvm_local_apics() {
    let carrier = Cpl0Carrier::boot_production(0x20_000).expect("production KVM boot");
    assert!(
        carrier
            .bootstrap_lapic_mapped()
            .expect("bootstrap LAPIC table walk"),
        "production CPL0 needs a writable supervisor mapping to xAPIC MMIO"
    );
    for slot in 0..2 {
        let version = carrier
            .lapic_register(slot, 0x30)
            .expect("production vCPU needs a live local APIC");
        assert_ne!(version & 0xff, 0, "missing LAPIC version on slot {slot}");
    }
}
