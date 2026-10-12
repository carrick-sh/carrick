//! VM-free contract for the static x86 ELF's exact load description.
use carrick_mem::x86_initial_image::prepare_x86_elf;

fn tiny_static_elf() -> Vec<u8> {
    let mut bytes = vec![0; 0x2003];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    // RX header + text segment; the ELF program header table is mapped.
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x1010u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1010u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    // RW data with an initialized prefix and a page of zero-filled BSS.
    bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&0x2000u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x402000u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&3u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[168..176].copy_from_slice(&0x1000u64.to_le_bytes());
    // mov eax,231; mov edi,7; syscall; ud2.
    bytes[0x1000..0x100f].copy_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b, 0x90,
    ]);
    bytes[0x2000..].copy_from_slice(b"hi\n");
    bytes
}

#[test]
fn static_x86_image_reuses_elf_plan_without_host_mm_edits() {
    let elf = tiny_static_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static x86 ELF");
    assert_eq!(image.entry, 0x401000);
    assert_eq!((image.phdr, image.phent, image.phnum), (0x400040, 56, 2));
    let text = image.regions.iter().find(|r| r.start == 0x400000).unwrap();
    assert!(text.perms.read && text.perms.execute && !text.perms.write);
    assert_eq!(
        &text.file_bytes[0x1000..0x100c],
        &[0xb8, 0xe7, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05]
    );
    let data = image.regions.iter().find(|r| r.start == 0x402000).unwrap();
    assert!(data.perms.read && data.perms.write && !data.perms.execute);
    assert_eq!(data.file_bytes, b"hi\n");
    assert_eq!(data.end - data.start, 4096);
}

fn dynamic_elf() -> Vec<u8> {
    let mut elf = tiny_static_elf();
    elf[56..58].copy_from_slice(&3u16.to_le_bytes());
    // Move the two PT_LOAD records after PT_INTERP (the ABI ordering).
    elf.copy_within(64..176, 120);
    elf[64..120].fill(0);
    elf[64..68].copy_from_slice(&3u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x300u64.to_le_bytes());
    let path = b"/lib/ld-test.so\0";
    elf[96..104].copy_from_slice(&(path.len() as u64).to_le_bytes());
    elf[0x300..0x300 + path.len()].copy_from_slice(path);
    elf
}

fn pie_elf(mut elf: Vec<u8>, first_load: usize, second_load: usize) -> Vec<u8> {
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[first_load + 16..first_load + 24].copy_from_slice(&0u64.to_le_bytes());
    elf[second_load + 16..second_load + 24].copy_from_slice(&0x2000u64.to_le_bytes());
    elf
}

#[test]
fn dynamic_x86_image_enters_interpreter_with_executable_auxv() {
    let elf = dynamic_elf();
    let interpreter = pie_elf(tiny_static_elf(), 64, 120);
    let reads = std::cell::Cell::new(0);
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|path| {
        assert_eq!(path, "/lib/ld-test.so");
        reads.set(reads.get() + 1);
        Some(interpreter.clone())
    })
    .expect("ELF program");
    let image = prepare_x86_elf(&program)
        .expect("PT_INTERP must be resolved through the shared ELF loader");
    assert_eq!((image.phdr, image.phent, image.phnum), (0x400040, 56, 3));
    let base = carrick_mem::memory::LINUX_INTERPRETER_BASE;
    assert_eq!(image.entry, base + 0x1000);
    assert_eq!(image.executable_entry, 0x401000);
    assert_eq!(image.interpreter_base, base);
    assert_eq!(reads.get(), 1, "one interpreter read, no recursive loader");
    assert_eq!(image.regions.len(), 4);
    assert_eq!(image.executable_region_count, 2);
    assert_eq!(
        image.regions[..2].iter().map(|r| r.end).max(),
        Some(0x403000)
    );
    assert_eq!(image.regions[2].start, base);
    assert_eq!(image.regions[3].file_bytes, b"hi\n");
    assert_eq!(image.regions[3].end, base + 0x3000);
}

#[test]
fn pie_executable_and_interpreter_keep_distinct_biases() {
    let elf = pie_elf(dynamic_elf(), 120, 176);
    let interpreter = pie_elf(tiny_static_elf(), 64, 120);
    let program =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| Some(interpreter.clone())).unwrap();
    let image = prepare_x86_elf(&program).unwrap();
    let main = carrick_mem::elf::LINUX_PIE_DEFAULT_BASE;
    assert_eq!(image.executable_entry, main + 0x1000);
    assert_eq!(image.phdr, main + 64);
    assert_eq!(
        image.regions[..image.executable_region_count]
            .iter()
            .map(|r| r.end)
            .max(),
        Some(main + 0x3000)
    );
    assert_eq!(
        image.entry,
        carrick_mem::memory::LINUX_INTERPRETER_BASE + 0x1000
    );
}

#[test]
fn fixed_interpreter_keeps_its_addresses_and_collisions_are_refused() {
    let elf = dynamic_elf();
    let mut interpreter = tiny_static_elf();
    for at in [24, 80, 136] {
        let va = u64::from_le_bytes(interpreter[at..at + 8].try_into().unwrap()) + 0x400000;
        interpreter[at..at + 8].copy_from_slice(&va.to_le_bytes());
    }
    let program =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| Some(interpreter.clone())).unwrap();
    let image = prepare_x86_elf(&program).unwrap();
    assert_eq!(image.entry, 0x801000);
    assert_eq!(image.interpreter_base, 0);
    let colliding =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| Some(tiny_static_elf())).unwrap();
    assert!(matches!(
        prepare_x86_elf(&colliding),
        Err(carrick_mem::x86_initial_image::X86InitialImageError::InvalidRegion)
    ));
}

#[test]
fn interpreter_resolution_preserves_provenance_and_never_recurses() {
    use carrick_mem::elf::{ElfInspectError, ElfProgram};
    let elf = dynamic_elf();
    assert!(
        matches!(ElfProgram::load(&elf, 62, &|_| None), Err(ElfInspectError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    let mut wrong = tiny_static_elf();
    wrong[18..20].copy_from_slice(&183u16.to_le_bytes());
    assert!(matches!(
        ElfProgram::load(&elf, 62, &|_| Some(wrong.clone())),
        Err(ElfInspectError::Interpreter(cause)) if matches!(*cause, ElfInspectError::UnsupportedMachine(183))
    ));
    let reads = std::cell::Cell::new(0);
    let nested = pie_elf(dynamic_elf(), 120, 176);
    let program = ElfProgram::load(&elf, 62, &|_| {
        reads.set(reads.get() + 1);
        Some(nested.clone())
    })
    .expect("interpreter PT_INTERP metadata never requests another image");
    assert_eq!(
        program.entry(),
        carrick_mem::memory::LINUX_INTERPRETER_BASE + 0x1000
    );
    assert_eq!(reads.get(), 1);
}

#[test]
fn x86_description_refuses_a_program_validated_for_another_isa() {
    let mut elf = tiny_static_elf();
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    let program = carrick_mem::elf::ElfProgram::load(&elf, 183, &|_| None).unwrap();
    assert!(
        prepare_x86_elf(&program).is_err(),
        "x86 entry needs an x86-validated load plan"
    );
}
