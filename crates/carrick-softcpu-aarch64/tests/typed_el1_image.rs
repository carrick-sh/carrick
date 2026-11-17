//! Real-image A1 closure witness. Set CARRICK_A64_ELF to the freshly built
//! carrick-el1-image OUT_DIR/el1-target/aarch64-unknown-none-softfloat/el1-image/
//! carrick-el1 ELF. Explicit invocation avoids rebuilding the kernel in every
//! VM-free decoder test. No instruction inventory or fixed word count is used.
use carrick_softcpu_aarch64::{Instruction, classify, decode_instruction};
use std::collections::BTreeMap;

#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the rebuilt production EL1 ELF"]
fn linked_el1_executable_mapping_spans_are_typed() {
    fn u16_at(bytes: &[u8], offset: usize) -> usize {
        usize::from(u16::from_le_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("ELF field has the expected width"),
        ))
    }
    fn u32_at(bytes: &[u8], offset: usize) -> usize {
        usize::try_from(u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("ELF field has the expected width"),
        ))
        .expect("valid production ELF fixture")
    }
    fn u64_at(bytes: &[u8], offset: usize) -> usize {
        usize::try_from(u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("ELF field has the expected width"),
        ))
        .expect("valid production ELF fixture")
    }
    fn string_at(bytes: &[u8], offset: usize) -> &str {
        let tail = &bytes[offset..];
        std::str::from_utf8(
            &tail[..tail
                .iter()
                .position(|&b| b == 0)
                .expect("valid production ELF fixture")],
        )
        .expect("valid production ELF fixture")
    }

    // ELF64 fields per the System V ABI; the AArch64 ELF ABI defines the
    // authoritative $x/$d mapping symbols. Malformed inputs fail the witness.
    let path = std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF");
    let bytes = std::fs::read(path).expect("valid production ELF fixture");
    assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
    assert_eq!(u16_at(&bytes, 18), 183, "not AArch64");
    let table = u64_at(&bytes, 40);
    let stride = u16_at(&bytes, 58);
    assert_eq!(stride, 64);
    let sections: Vec<_> = (0..u16_at(&bytes, 60))
        .map(|i| &bytes[table + i * stride..table + (i + 1) * stride])
        .collect();
    let mut symbols = Vec::new();
    for section in &sections {
        if u32_at(section, 4) != 2 {
            continue;
        } // SHT_SYMTAB
        assert_eq!(u64_at(section, 56), 24);
        let strings = sections[u32_at(section, 40)];
        let strings = &bytes[u64_at(strings, 24)..u64_at(strings, 24) + u64_at(strings, 32)];
        let offset = u64_at(section, 24);
        for symbol in bytes[offset..offset + u64_at(section, 32)].chunks_exact(24) {
            let name = string_at(strings, u32_at(symbol, 0));
            let code = if name == "$x" || name.starts_with("$x.") {
                true
            } else if name == "$d" || name.starts_with("$d.") {
                false
            } else {
                continue;
            };
            symbols.push((u16_at(symbol, 6), u64_at(symbol, 8), code));
        }
    }
    let mut words = 0;
    let mut unknown = BTreeMap::<String, usize>::new();
    for (index, section) in sections.iter().enumerate() {
        if u64_at(section, 8) & 4 == 0 || u64_at(section, 32) == 0 {
            continue;
        }
        assert_eq!(u32_at(section, 4), 1, "executable section lacks file bytes");
        let start = u64_at(section, 16);
        let end = start
            .checked_add(u64_at(section, 32))
            .expect("valid production ELF fixture");
        let mut boundaries = BTreeMap::new();
        for &(_, address, code) in symbols.iter().filter(|s| s.0 == index) {
            assert!((start..end).contains(&address));
            if let Some(previous) = boundaries.insert(address, code) {
                assert_eq!(previous, code);
            }
        }
        assert!(
            boundaries.contains_key(&start),
            "missing initial mapping symbol"
        );
        boundaries.insert(end, false);
        let points: Vec<_> = boundaries.into_iter().collect();
        for pair in points.windows(2) {
            if !pair[0].1 {
                continue;
            }
            let (lo, hi) = (pair[0].0, pair[1].0);
            assert_eq!(lo % 4, 0);
            assert_eq!((hi - lo) % 4, 0);
            let offset = u64_at(section, 24)
                .checked_add(lo - start)
                .expect("valid production ELF fixture");
            for (i, word) in bytes[offset..offset + hi - lo].chunks_exact(4).enumerate() {
                let word =
                    u32::from_le_bytes(word.try_into().expect("ELF field has the expected width"));
                words += 1;
                if decode_instruction(word) == Instruction::Unallocated {
                    *unknown.entry(format!("{:?}", classify(word))).or_default() += 1;
                }
            }
        }
    }
    assert!(words > 0, "no code measured");
    println!("measured {words} code words; undecoded by class: {unknown:?}");
    assert!(
        unknown.is_empty(),
        "undecoded class populations: {unknown:?}"
    );
    println!("typed {words} production ELF code words; 0 unknown");
}
