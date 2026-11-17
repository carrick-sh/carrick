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
    // A recognized FP computation is deliberately outside this typed decoder.
    // Strict must reject it even though the classifier has no unknown words.
    let mut typed_gap = fixture();
    put(&mut typed_gap, 68, 0x1e602800, 4);
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
                    .any(|word| word["address"] == 0x1004 && word["encoding"] == "0x1e602800")
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
            .args(["debug", "a64-census-export-spans"])
            .arg(&input)
            .arg(&export)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        // The fixture has one ELF code span. All subsequent spans are the
        // production maintenance/vector pages, including repeated configurations.
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
