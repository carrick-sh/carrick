//! Verifies that an arbitrary external / detached composition root crate
//! (representing an out-of-tree / non-Linux test personality) can be packaged
//! via `carrick_xtask::guest_image::package_guest_image` and boots under KVM.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/physical_inventory.rs"]
mod physical_inventory;
use physical_inventory::physical_inventory;

use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_xtask::guest_image::{GuestImageBuildConfig, GuestTargetArch, package_guest_image};
use std::fs;
use std::path::{Path, PathBuf};

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

#[test]
fn detached_example_composition_root_packages_and_boots_under_kvm() {
    let root = repo_root();
    let fixture_src =
        root.join("crates/carrick-kernel-example/tests/fixtures/example-composition-root");
    assert!(fixture_src.exists(), "fixture exists at {fixture_src:?}");

    // Copy fixture to a detached temporary directory outside the repository tree:
    let temp = tempfile::tempdir().expect("tempdir");
    let detached_root = temp.path().join("detached-composition-root");
    copy_dir_all(&fixture_src, &detached_root).expect("copy fixture to detached path");

    let out_dir = temp.path().join("out");
    let config = GuestImageBuildConfig::new(&detached_root, GuestTargetArch::X86_64, &out_dir);

    // Package the guest image from the detached path using the exported xtask library:
    let artifact =
        package_guest_image(&config).expect("package guest image from detached composition root");
    assert_eq!(artifact.target_arch, GuestTargetArch::X86_64);
    assert!(
        artifact.binary_path.exists(),
        "binary exists: {:?}",
        artifact.binary_path
    );

    // Verify the resulting carrier image boots under KVM:
    let carrier = Cpl0Carrier::boot(physical_inventory(), &artifact.binary_path, [&[], &[]])
        .expect("KVM boot of image packaged from detached composition root");

    // Verify that supervisor layout access is initialized and valid:
    let pml4 = 0x60_0000;
    assert!(
        carrier
            .bootstrap_supervisor_access(pml4, carrick_mmu_core::x86::descriptor_txn::Access::Write)
            .expect("supervisor data access")
    );
}
