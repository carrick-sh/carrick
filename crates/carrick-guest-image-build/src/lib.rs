//! Single source of truth for guest kernel image build parameters and command construction.
//!
//! Shared by `crates/carrick-el1-image/build.rs`, `crates/carrick-vmm-kvm/build.rs`,
//! and `crates/carrick-xtask/src/shared_kernel_scorecard.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Package name for the aarch64 EL1 guest kernel.
pub const EL1_PACKAGE: &str = "carrick-el1";

/// Target triple for the aarch64 EL1 guest kernel.
pub const EL1_TARGET: &str = "aarch64-unknown-none-softfloat";

/// Package name for the x86_64 CPL0 guest kernel.
pub const CPL0_PACKAGE: &str = "carrick-x86-cpl0";

/// Target triple for the x86_64 CPL0 guest kernel.
pub const CPL0_TARGET: &str = "x86_64-unknown-none";

/// Production binary target name for CPL0.
pub const CPL0_BIN_PRODUCTION: &str = "carrick-x86-cpl0";

/// Test fixture binary target name for CPL0.
pub const CPL0_BIN_FIXTURE: &str = "carrick-x86-cpl0-fixture";

/// Cargo environment variables that must be removed when invoking a nested Cargo build
/// to prevent host compiler flags, makeflags, or rustflags from interfering with the
/// bare-metal guest target compilations.
pub const ENV_VARS_TO_REMOVE: &[&str] =
    &["CARGO_MAKEFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS"];

/// Remove environment variables that might interfere with nested Cargo invocations.
pub fn clean_cargo_env(cmd: &mut Command) {
    for var in ENV_VARS_TO_REMOVE {
        cmd.env_remove(var);
    }
}

/// Build configuration for the aarch64 EL1 guest image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct El1ImageBuild {
    pub locked: bool,
    pub allocator_test_control: bool,
}

impl Default for El1ImageBuild {
    fn default() -> Self {
        Self {
            locked: true,
            allocator_test_control: false,
        }
    }
}

impl El1ImageBuild {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_locked(mut self, locked: bool) -> Self {
        self.locked = locked;
        self
    }

    pub fn with_allocator_test_control(mut self, enabled: bool) -> Self {
        self.allocator_test_control = enabled;
        self
    }

    /// Configure a `Command` invoking `cargo build` for the EL1 image.
    pub fn configure_command(&self, cmd: &mut Command, target_dir: impl AsRef<Path>) {
        cmd.arg("build");
        if self.locked {
            cmd.arg("--locked");
        }
        cmd.arg("--release")
            .arg("-p")
            .arg(EL1_PACKAGE)
            .arg("--target")
            .arg(EL1_TARGET)
            .arg("--target-dir")
            .arg(target_dir.as_ref());

        if self.allocator_test_control {
            cmd.arg("--features").arg("allocator-test-control");
        }

        clean_cargo_env(cmd);
    }

    /// Relative path of the compiled ELF output inside `target_dir`.
    pub fn elf_rel_path(&self) -> PathBuf {
        Path::new(EL1_TARGET).join("release").join(EL1_PACKAGE)
    }
}

/// Build configuration for the x86_64 CPL0 guest image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpl0ImageBuild {
    pub locked: bool,
    pub include_fixture: bool,
}

impl Default for Cpl0ImageBuild {
    fn default() -> Self {
        Self {
            locked: true,
            include_fixture: true,
        }
    }
}

impl Cpl0ImageBuild {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_locked(mut self, locked: bool) -> Self {
        self.locked = locked;
        self
    }

    pub fn with_fixture(mut self, include_fixture: bool) -> Self {
        self.include_fixture = include_fixture;
        self
    }

    /// Configure a `Command` invoking `cargo build` for the CPL0 image.
    pub fn configure_command(&self, cmd: &mut Command, target_dir: impl AsRef<Path>) {
        cmd.arg("build");
        if self.locked {
            cmd.arg("--locked");
        }
        cmd.arg("--release")
            .arg("-p")
            .arg(CPL0_PACKAGE)
            .arg("--bin")
            .arg(CPL0_BIN_PRODUCTION);

        if self.include_fixture {
            cmd.arg("--bin").arg(CPL0_BIN_FIXTURE);
        }

        cmd.arg("--target")
            .arg(CPL0_TARGET)
            .arg("--target-dir")
            .arg(target_dir.as_ref());

        clean_cargo_env(cmd);
    }

    /// Relative path of a compiled binary output inside `target_dir`.
    pub fn bin_rel_path(&self, bin_name: &str) -> PathBuf {
        Path::new(CPL0_TARGET).join("release").join(bin_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_el1_image_build_config() {
        let build = El1ImageBuild::new();
        assert!(build.locked);
        assert!(!build.allocator_test_control);
        assert_eq!(
            build.elf_rel_path(),
            PathBuf::from("aarch64-unknown-none-softfloat/release/carrick-el1")
        );

        let test_build = build.with_allocator_test_control(true);
        assert!(test_build.allocator_test_control);
    }

    #[test]
    fn test_cpl0_image_build_config() {
        let build = Cpl0ImageBuild::new();
        assert!(build.locked);
        assert!(build.include_fixture);
        assert_eq!(
            build.bin_rel_path(CPL0_BIN_PRODUCTION),
            PathBuf::from("x86_64-unknown-none/release/carrick-x86-cpl0")
        );
        assert_eq!(
            build.bin_rel_path(CPL0_BIN_FIXTURE),
            PathBuf::from("x86_64-unknown-none/release/carrick-x86-cpl0-fixture")
        );

        let no_fixture = build.with_fixture(false);
        assert!(!no_fixture.include_fixture);
    }
}
