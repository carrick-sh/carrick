//! The embedded production CPL0 image rebuilds whenever any source it compiles
//! changes. `build.rs` derives its `rerun-if-changed` inputs through
//! `cpl0_inputs.rs`; this test proves the derivation reaches every file the
//! image's sources pull in by `#[path]`/`include*!` (carrick-x86's cpl0_*.rs
//! sit outside the image's dependency closure) and the build configuration
//! that sets `code-model=kernel`. VM-free: reads sources and manifests.
#![allow(clippy::expect_used)]

#[path = "../cpl0_inputs.rs"]
mod cpl0_inputs;

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn derive() -> cpl0_inputs::Cpl0Inputs {
    cpl0_inputs::derive(&workspace()).expect("derive CPL0 image inputs")
}

#[test]
fn every_literal_include_of_the_image_is_a_watched_input() {
    let inputs = derive();
    assert!(
        inputs.unresolved.is_empty(),
        "include literals that resolve to no file escape the watch list: {:?}",
        inputs.unresolved
    );
    let watched = inputs.watch_list(&workspace());
    for (from, target) in &inputs.includes {
        assert!(
            inputs.covers(target) && watched.iter().any(|w| target.starts_with(w)),
            "{} includes {}, which build.rs does not watch",
            from.display(),
            target.display()
        );
    }
}

#[test]
fn carrick_x86_cpl0_sources_and_build_config_are_inputs() {
    let inputs = derive();
    let root = workspace();
    for file in [
        "crates/carrick-x86/src/cpl0_entry.rs",
        "crates/carrick-x86/src/cpl0_scheduler.rs",
        "crates/carrick-x86/src/cpl0_lifecycle.rs",
    ] {
        let path = root.join(file).canonicalize().expect("cpl0 source exists");
        assert!(
            inputs.external_files.contains(&path),
            "{file} is compiled into the image but is not a derived input"
        );
    }
    let watched = inputs.watch_list(&root);
    for file in cpl0_inputs::WORKSPACE_INPUTS {
        assert!(
            watched.contains(&root.join(file)),
            "{file} configures the image build but is not watched"
        );
    }
    assert!(
        cpl0_inputs::WORKSPACE_INPUTS.contains(&".cargo/config.toml"),
        "code-model=kernel lives in .cargo/config.toml"
    );
    // The original target-filtered closure plus the conservative host-only
    // carrick-el1-linux -> carrick-fatal edge, and the watch-only
    // carrick-el1-linux -> carrick-zeroed-pages edge: an optional, host-only
    // dependency enabled solely by `host-test`, which the image build never
    // compiles: `cargo tree -p carrick-x86-cpl0 -e normal,build --target all`
    // lists no carrick-zeroed-pages (0 matches; #2822).
    let packages = [
        "carrick-abi",
        "carrick-core",
        "carrick-core-abi",
        "carrick-el1",
        "carrick-el1-abi",
        "carrick-el1-control-abi",
        "carrick-el1-linux",
        "carrick-fatal",
        "carrick-fd-core",
        "carrick-guest-arch",
        "carrick-inotify-core",
        "carrick-mmu-core",
        "carrick-personality-api",
        "carrick-personality-linux",
        "carrick-pipe-core",
        "carrick-sched-core",
        "carrick-signal-core",
        "carrick-syscall-abi",
        "carrick-x86-carrier",
        "carrick-x86-cpl0",
        "carrick-zeroed-pages",
    ];
    assert_eq!(inputs.package_dirs.len(), packages.len());
    for package in packages {
        let dir = root
            .join("crates")
            .join(package)
            .canonicalize()
            .expect("crate dir");
        assert!(
            inputs.package_dirs.contains(&dir),
            "{package} is in the image's dependency closure but not watched"
        );
    }
}

#[test]
fn local_manifest_closure_needs_no_registry_or_lockfile() {
    let temp = tempfile::tempdir().expect("fixture root");
    let root = temp.path();
    std::fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace.dependencies]
alias = { package = "shared", path = "crates/shared" }
"#,
    )
    .expect("workspace manifest");
    for (name, manifest) in [
        (
            "carrick-x86-cpl0",
            r#"
[dependencies]
alias.workspace = true
remote = "999.0"
optional = { path = "../optional", optional = true }
[target.'cfg(target_os = "none")'.build-dependencies]
builder = { path = "../builder" }
[dev-dependencies]
missing = { path = "../missing" }
"#,
        ),
        (
            "shared",
            "[dependencies]\ncycle = { path = '../carrick-x86-cpl0' }",
        ),
        ("optional", "[package]\nname = 'optional'"),
        ("builder", "[package]\nname = 'builder'"),
    ] {
        let dir = root.join("crates").join(name);
        std::fs::create_dir_all(&dir).expect("fixture crate");
        std::fs::write(dir.join("Cargo.toml"), manifest).expect("fixture manifest");
    }
    let inputs = cpl0_inputs::derive(root).expect("file-only closure");
    let expected = ["carrick-x86-cpl0", "shared", "optional", "builder"]
        .into_iter()
        .map(|name| {
            root.join("crates")
                .join(name)
                .canonicalize()
                .expect("crate path")
        })
        .collect();
    assert_eq!(inputs.package_dirs, expected);
}

/// #3005: the build-time budget report reads each image's loaded span and
/// its extent from the image itself. On the real embedded images the
/// extent is the ABI's supervisor extent and every image fits it; any
/// truncation, and a big-endian header, reads as `None`, never a panic.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../cpl0_budget.rs"]
mod cpl0_budget;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod image_budget {
    use super::cpl0_budget::ImageBudget;

    const IMAGES: [(&str, &[u8]); 3] = [
        ("production", include_bytes!(env!("CARRICK_X86_CPL0_IMAGE"))),
        ("test", include_bytes!(env!("CARRICK_X86_CPL0_TEST_IMAGE"))),
        (
            "fixture",
            include_bytes!(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE")),
        ),
    ];

    #[test]
    fn every_embedded_cpl0_image_reads_its_budget_from_its_own_extent_symbol() {
        for (name, image) in IMAGES {
            let budget = ImageBudget::of(image).expect(name);
            assert_eq!(
                budget.extent,
                carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE,
                "{name}"
            );
            assert!(
                0 < budget.loaded && budget.loaded <= budget.extent,
                "{name}: {budget:?}"
            );
        }
    }

    #[test]
    fn a_truncated_cpl0_image_reads_as_no_budget() {
        let (_, image) = IMAGES[0];
        // Every header prefix, then coarse steps through the tables.
        for len in (0..0x100).chain((0x100..image.len()).step_by(4093)) {
            assert_eq!(ImageBudget::of(&image[..len]), None, "prefix {len:#x}");
        }
    }

    #[test]
    fn a_big_endian_cpl0_image_reads_as_no_budget() {
        let mut big_endian = IMAGES[0].1.to_vec();
        big_endian[5] = 2;
        assert_eq!(ImageBudget::of(&big_endian), None);
    }

    /// The real production image with one 8-byte header field at `u64::MAX`.
    fn with_header_field_at_max(field: usize) -> Vec<u8> {
        let mut image = IMAGES[0].1.to_vec();
        image[field..field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        image
    }

    /// Program headers at `u64::MAX`: every offset sum is checked, so the
    /// read is `None`, not an overflow panic in the build script.
    #[test]
    fn cpl0_program_headers_at_the_end_of_the_address_space_read_as_no_budget() {
        assert_eq!(ImageBudget::of(&with_header_field_at_max(0x20)), None);
    }

    /// Section headers at `u64::MAX`, the same.
    #[test]
    fn cpl0_section_headers_at_the_end_of_the_address_space_read_as_no_budget() {
        assert_eq!(ImageBudget::of(&with_header_field_at_max(0x28)), None);
    }

    /// A minimal ELF64 image: one `PT_LOAD` of 0x300 bytes at 0x1000, a
    /// second program header left `PT_NULL`, and a symbol table whose one
    /// symbol is the extent end at 0x1800. `nul`
    /// ends the name inside its string table; `symtab_tail` adds bytes to
    /// the symbol table's declared size.
    fn synthetic_image(nul: bool, symtab_tail: u64) -> Vec<u8> {
        fn put(image: &mut [u8], at: usize, bytes: &[u8]) {
            image[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let (phoff, symoff, stroff, shoff) = (64, 176, 224, 256);
        let mut names = vec![0];
        names.extend_from_slice(super::cpl0_budget::EXTENT_END_SYMBOL);
        if nul {
            names.push(0);
        }
        let mut image = vec![0_u8; shoff + 3 * 64];
        put(&mut image, 0, b"\x7fELF\x02\x01\x01");
        put(&mut image, 0x20, &(phoff as u64).to_le_bytes());
        put(&mut image, 0x28, &(shoff as u64).to_le_bytes());
        put(&mut image, 0x36, &56_u16.to_le_bytes());
        put(&mut image, 0x38, &2_u16.to_le_bytes());
        put(&mut image, 0x3a, &64_u16.to_le_bytes());
        put(&mut image, 0x3c, &3_u16.to_le_bytes());
        put(&mut image, phoff, &1_u32.to_le_bytes());
        put(&mut image, phoff + 0x10, &0x1000_u64.to_le_bytes());
        put(&mut image, phoff + 0x28, &0x300_u64.to_le_bytes());
        put(&mut image, symoff + 24, &1_u32.to_le_bytes());
        put(&mut image, symoff + 24 + 8, &0x1800_u64.to_le_bytes());
        put(&mut image, stroff, &names);
        let (symtab, strtab) = (shoff + 64, shoff + 128);
        put(&mut image, symtab + 4, &2_u32.to_le_bytes());
        put(&mut image, symtab + 0x18, &(symoff as u64).to_le_bytes());
        put(&mut image, symtab + 0x20, &(48 + symtab_tail).to_le_bytes());
        put(&mut image, symtab + 0x28, &2_u32.to_le_bytes());
        put(&mut image, symtab + 0x38, &24_u64.to_le_bytes());
        put(&mut image, strtab + 4, &3_u32.to_le_bytes());
        put(&mut image, strtab + 0x18, &(stroff as u64).to_le_bytes());
        put(
            &mut image,
            strtab + 0x20,
            &(names.len() as u64).to_le_bytes(),
        );
        image
    }

    #[test]
    fn a_well_formed_synthetic_image_reads_its_known_budget() {
        assert_eq!(
            ImageBudget::of(&synthetic_image(true, 0)),
            Some(ImageBudget {
                loaded: 0x300,
                extent: 0x800,
            })
        );
    }

    /// The whole symbol table is checked against its entry size: a declared
    /// size one byte past a whole number of entries is malformed (#3008).
    #[test]
    fn a_symbol_table_with_a_partial_entry_reads_as_no_budget() {
        assert_eq!(ImageBudget::of(&synthetic_image(true, 1)), None);
    }

    /// A symbol name that runs to the end of its string table without a
    /// NUL is not a name, even when its bytes spell the extent symbol.
    #[test]
    fn an_unterminated_extent_name_reads_as_no_budget() {
        assert_eq!(ImageBudget::of(&synthetic_image(false, 0)), None);
    }

    /// Each table is checked whole: a file cut one byte inside the last
    /// section header is malformed even though every field the reader
    /// uses from that header is still present.
    #[test]
    fn a_section_table_cut_inside_its_last_entry_reads_as_no_budget() {
        let image = synthetic_image(true, 0);
        assert_eq!(ImageBudget::of(&image[..image.len() - 1]), None);
    }

    /// The synthetic image with program header `index` made a `PT_LOAD`
    /// with this file offset, file size and memory size.
    fn with_load_segment(index: usize, offset: u64, filesz: u64, memsz: u64) -> Vec<u8> {
        let header = 64 + index * 56;
        let mut image = synthetic_image(true, 0);
        image[header..header + 4].copy_from_slice(&1_u32.to_le_bytes());
        for (at, value) in [(0x08, offset), (0x20, filesz), (0x28, memsz)] {
            image[header + at..header + at + 8].copy_from_slice(&value.to_le_bytes());
        }
        image
    }

    /// A load segment's file bytes must lie inside the file.
    #[test]
    fn a_load_segment_past_the_end_of_the_file_reads_as_no_budget() {
        let len = synthetic_image(true, 0).len() as u64;
        assert_eq!(ImageBudget::of(&with_load_segment(0, len, 1, 0x300)), None);
    }

    /// A load segment's file bytes must fit its memory size.
    #[test]
    fn a_load_segment_larger_in_the_file_than_in_memory_reads_as_no_budget() {
        assert_eq!(ImageBudget::of(&with_load_segment(0, 0, 0x10, 0x8)), None);
    }

    /// The same holds for an empty load segment beside a valid one: it adds
    /// nothing to the span, but its file bytes are still checked.
    #[test]
    fn an_empty_load_segment_with_file_bytes_reads_as_no_budget() {
        let known = ImageBudget {
            loaded: 0x300,
            extent: 0x800,
        };
        assert_eq!(ImageBudget::of(&with_load_segment(1, 0, 0, 0)), Some(known));
        assert_eq!(ImageBudget::of(&with_load_segment(1, 0, 1, 0)), None);
    }
}
