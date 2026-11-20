//! Production command witness: reserved code fails, identical literal data is
//! excluded by mapping symbols. No assembler or external decoder is needed.
use std::process::Command;

fn put(bytes: &mut [u8], offset: usize, value: u64, width: usize) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 168 + 4 * 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value, width) in [
        (16, 2, 2),
        (18, 183, 2),
        (20, 1, 4),
        (40, 168, 8),
        (52, 64, 2),
        (58, 64, 2),
        (60, 4, 2),
    ] {
        put(&mut bytes, offset, value, width);
    }
    for (offset, word) in [(64, 0xd503201f), (68, 0xffffffff), (72, 0xffffffff)] {
        put(&mut bytes, offset, word, 4);
    }
    bytes[80..87].copy_from_slice(b"\0$x\0$d\0");
    for (symbol, name, address) in [(120, 1, 0x1000), (144, 4, 0x1008)] {
        put(&mut bytes, symbol, name, 4);
        put(&mut bytes, symbol + 6, 1, 2);
        put(&mut bytes, symbol + 8, address, 8);
    }
    for (section, kind, flags, address, offset, size, link, entry) in [
        (1, 1, 6, 0x1000, 64, 12, 0, 0),
        (2, 3, 0, 0, 80, 7, 0, 0),
        (3, 2, 0, 0, 96, 72, 2, 24),
    ] {
        let base = 168 + section * 64;
        for (field, value, width) in [
            (4, kind, 4),
            (8, flags, 8),
            (16, address, 8),
            (24, offset, 8),
            (32, size, 8),
            (40, link, 4),
            (48, 1, 8),
            (56, entry, 8),
        ] {
            put(&mut bytes, base + field, value, width);
        }
    }
    bytes
}
#[test]
fn command_rejects_reserved_code_excludes_literals_and_is_deterministic() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("reserved.elf");
    std::fs::write(&path, fixture())?;
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_carrick"))
            .args(["debug", "a64-census", "--strict"])
            .arg(&path)
            .output()
    };
    let first = invoke()?;
    let second = invoke()?;
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(first.stdout, second.stdout);
    let measurement = Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["debug", "a64-census"])
        .arg(&path)
        .output()?;
    assert_eq!(measurement.status.code(), Some(0));
    assert_eq!(measurement.stdout, first.stdout);
    let report: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    assert!(
        report["typed_undecoded_count"]
            .as_u64()
            .is_some_and(|n| n > 0)
    );
    assert!(report["typed_undecoded"].as_array().is_some_and(|words| {
        words.iter().any(|word| word["address"] == 0x1004)
            && !words.iter().any(|word| word["address"] == 0x1008)
    }));
    let unknown = report["unknown"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing unknown words"))?;
    assert!(
        unknown
            .iter()
            .any(|word| word["address"] == 0x1004 && word["encoding"] == "0xffffffff")
    );
    assert!(
        !unknown
            .iter()
            .any(|word| word["span"] == "" && word["address"] == 0x1008)
    );
    assert!(!unknown.iter().any(|word| word["address"] == 0x1008));
    // A recognized LSE atomic is deliberately outside this typed decoder.
    // Strict must reject it even though the classifier has no unknown words.
    let mut typed_gap = fixture();
    put(&mut typed_gap, 68, 0xf8208000, 4);
    std::fs::write(&path, typed_gap)?;
    let typed = invoke()?;
    assert_eq!(typed.status.code(), Some(1));
    let typed_report: serde_json::Value = serde_json::from_slice(&typed.stdout)?;
    assert_eq!(typed_report["unknown_count"], 0);
    assert!(
        typed_report["typed_undecoded"]
            .as_array()
            .is_some_and(|words| {
                words
                    .iter()
                    .any(|word| word["address"] == 0x1004 && word["encoding"] == "0xf8208000")
            })
    );
    Ok(())
}

#[test]
fn command_exports_all_loader_words_deterministically() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("image.elf");
    std::fs::write(&input, fixture())?;
    let mut exports = Vec::new();
    for name in ["first.bin", "second.bin"] {
        let export = directory.path().join(name);
        let output = Command::new(env!("CARGO_BIN_EXE_carrick"))
            .args(["debug", "a64-census"])
            .arg(&input)
            .arg("--export-loader-spans")
            .arg(&export)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        // The fixture has one ELF code span. The remaining spans are the
        // production loader pages, including repeated vector configurations.
        let loader_bytes: u64 = report["spans"]
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
            .map(|span| span["bytes"].as_u64().unwrap())
            .sum();
        let bytes = std::fs::read(export)?;
        assert!(loader_bytes > 0);
        assert_eq!(bytes.len() as u64, loader_bytes);
        exports.push(bytes);
    }
    assert_eq!(exports[0], exports[1]);
    Ok(())
}

#[test]
fn rootfs_census_excludes_mapped_data_even_inside_a_function() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut elf = fixture();
    elf.splice(168..168, [0; 24]);
    put(&mut elf, 40, 192, 8);
    put(&mut elf, 120 + 24 * 2 + 4, 2, 1); // STT_FUNC
    put(&mut elf, 120 + 24 * 2 + 6, 1, 2);
    put(&mut elf, 120 + 24 * 2 + 8, 0x1000, 8);
    put(&mut elf, 120 + 24 * 2 + 16, 12, 8);
    put(&mut elf, 192 + 3 * 64 + 32, 96, 8);
    std::fs::write(root.path().join("libc.so.6"), elf)?;
    let output = Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["debug", "a64-census", "--strict"])
        .arg(root.path())
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let file = &report["files"][0];
    assert_eq!(file["path"], "libc.so.6");
    assert_eq!(file["executable_words"], 2);
    assert_eq!(file["unclassified_words"], 1);
    Ok(())
}

#[test]
fn rootfs_census_uses_pcrel_fdes_and_separates_withheld_words() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut elf = fixture();
    put(&mut elf, 62, 2, 2); // section-header string table index
    put(&mut elf, 168 + 2 * 64 + 32, 11, 8);
    elf[80..91].copy_from_slice(b"\0.eh_frame\0");
    let sh = 168 + 3 * 64;
    put(&mut elf, sh, 1, 4); // .eh_frame name
    put(&mut elf, sh + 4, 1, 4); // SHT_PROGBITS
    put(&mut elf, sh + 16, 0x2000, 8);
    put(&mut elf, sh + 32, 40, 8);
    put(&mut elf, sh + 40, 0, 4);
    put(&mut elf, sh + 56, 0, 8);

    let frame = &mut elf[96..136];
    frame.fill(0);
    put(frame, 0, 16, 4); // CIE length
    frame[8..17].copy_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 30, 1, 0x1b]);
    put(frame, 20, 16, 4); // FDE length
    put(frame, 24, 24, 4); // backward CIE pointer
    put(frame, 28, 0x1000u32.wrapping_sub(0x201c).into(), 4); // pcrel start
    put(frame, 32, 8, 4); // range excludes the final poison word
    put(&mut elf, 68, 0xf820_0020, 4); // withheld LDADD
    std::fs::write(root.path().join("ld.so"), elf)?;

    let output = Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["debug", "a64-census", "--strict"])
        .arg(root.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let file = &report["files"][0];
    assert_eq!(file["executable_words"], 2);
    assert_eq!(file["coverage"]["function_range_words"], 2);
    assert_eq!(file["coverage"]["uncovered_executable_section_bytes"], 4);
    assert_eq!(file["unclassified_words"], 0);
    assert_eq!(file["withheld_by_profile"]["lse"], 1);
    Ok(())
}
