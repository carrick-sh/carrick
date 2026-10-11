//! Guest carrier image composition and packaging.
//!
//! Provides reusable tooling to compile, audit, and package guest carrier images
//! for arbitrary composition roots and target architectures, supporting both
//! in-tree and out-of-tree personalities.

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// Target architecture for guest carrier image packaging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, Serialize, Deserialize)]
pub enum GuestTargetArch {
    #[value(name = "aarch64", alias = "arm64")]
    Aarch64,
    #[value(name = "x86_64", alias = "amd64")]
    X86_64,
}

impl GuestTargetArch {
    /// Returns the bare-metal Rust target triple for guest compilation.
    pub const fn rust_target(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64-unknown-none-softfloat",
            Self::X86_64 => "x86_64-unknown-none",
        }
    }

    /// The default binary filename for the packaged image artifact.
    pub fn default_artifact_name(self, bin_name: &str) -> String {
        match self {
            Self::Aarch64 => format!("{bin_name}.bin"),
            Self::X86_64 => bin_name.to_string(),
        }
    }
}

impl fmt::Display for GuestTargetArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aarch64 => write!(f, "aarch64"),
            Self::X86_64 => write!(f, "x86_64"),
        }
    }
}

impl From<carrick_guest_arch::GuestIsa> for GuestTargetArch {
    fn from(isa: carrick_guest_arch::GuestIsa) -> Self {
        match isa {
            carrick_guest_arch::GuestIsa::Aarch64 => Self::Aarch64,
            carrick_guest_arch::GuestIsa::X86_64 => Self::X86_64,
        }
    }
}

impl From<GuestTargetArch> for carrick_guest_arch::GuestIsa {
    fn from(arch: GuestTargetArch) -> Self {
        match arch {
            GuestTargetArch::Aarch64 => Self::Aarch64,
            GuestTargetArch::X86_64 => Self::X86_64,
        }
    }
}

/// Cargo build profile for guest images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, Default, Serialize, Deserialize)]
pub enum BuildProfile {
    #[default]
    #[value(name = "release")]
    Release,
    #[value(name = "debug")]
    Debug,
}

impl BuildProfile {
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Debug => "debug",
        }
    }
}

/// Configuration for packaging a guest carrier image.
#[derive(Debug, Clone)]
pub struct GuestImageBuildConfig {
    /// Path to the composition root crate directory (or its Cargo.toml).
    pub composition_root: PathBuf,
    /// Target architecture for the guest image.
    pub target_arch: GuestTargetArch,
    /// Directory where the output image binary should be written.
    pub out_dir: PathBuf,
    /// Cargo target directory for build intermediates (defaults to `out_dir.join("target")`).
    pub target_dir: Option<PathBuf>,
    /// Optional package name (`-p <pkg>`) when building within a workspace.
    pub package: Option<String>,
    /// Optional binary target name (`--bin <name>`).
    pub bin_name: Option<String>,
    /// Build profile (release or debug). Defaults to Release.
    pub profile: BuildProfile,
    /// Features to enable (`--features <features>`).
    pub features: Vec<String>,
    /// Whether to pass `--locked` to cargo.
    pub locked: bool,
    /// Custom cargo binary path (defaults to `CARGO` env or `cargo`).
    pub cargo_path: Option<PathBuf>,
    /// Routines audited and allowed to use FP/SIMD on AArch64.
    /// If empty, any FP/SIMD instruction is rejected.
    pub expected_fpsimd_routines: Vec<String>,
    /// Additional rustflags to supply via environment.
    pub rustflags: Vec<String>,
}

impl GuestImageBuildConfig {
    pub fn new(
        composition_root: impl Into<PathBuf>,
        target_arch: GuestTargetArch,
        out_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            composition_root: composition_root.into(),
            target_arch,
            out_dir: out_dir.into(),
            target_dir: None,
            package: None,
            bin_name: None,
            profile: BuildProfile::Release,
            features: Vec::new(),
            locked: false,
            cargo_path: None,
            expected_fpsimd_routines: Vec::new(),
            rustflags: Vec::new(),
        }
    }
}

/// Packaged guest carrier image artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestImageArtifact {
    /// Target architecture of the image.
    pub target_arch: GuestTargetArch,
    /// Path to the packaged carrier image binary.
    /// (For AArch64 this is the raw flat binary; for x86_64 this is the ELF image).
    pub binary_path: PathBuf,
    /// Path to the compiled ELF binary before conversion.
    pub elf_path: PathBuf,
}

/// Errors occurring during guest image packaging.
#[derive(Debug, Error)]
pub enum GuestImageError {
    #[error(
        "Target '{target}' is required to build guest image. Install with: rustup target add {target}"
    )]
    MissingTarget { target: String },

    #[error(
        "Tool '{tool}' not found in sysroot ({sysroot_path}) or on PATH. Install with: rustup component add llvm-tools-preview"
    )]
    MissingTool { tool: String, sysroot_path: String },

    #[error("Failed to run rustc: {0}")]
    RustcFailed(String),

    #[error("Failed to invoke cargo build: {0}")]
    CargoIo(#[source] std::io::Error),

    #[error("Cargo build failed with exit status: {0}")]
    CargoBuildFailed(std::process::ExitStatus),

    #[error("llvm-objdump failed: {0}")]
    ObjdumpFailed(String),

    #[error(
        "FP/SIMD instructions detected in AArch64 guest image ({count} violations):\n{details}"
    )]
    FpsimdViolation { count: usize, details: String },

    #[error(
        "FP/SIMD switch routine {routine} missing or incomplete ({hits} FP/SIMD instructions, expected 16 q-pair moves plus FPSR/FPCR)"
    )]
    FpsimdRoutineIncomplete { routine: String, hits: usize },

    #[error("Failed to run rust-objcopy: {0}")]
    ObjcopyIo(#[source] std::io::Error),

    #[error("rust-objcopy failed with exit status: {0}")]
    ObjcopyFailed(std::process::ExitStatus),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Composition root manifest not found at: {0}")]
    ManifestNotFound(PathBuf),

    #[error("Built ELF not found at: {0}")]
    ElfNotFound(PathBuf),

    #[error("Failed to determine binary name from manifest: {0}")]
    PackageNameResolution(String),
}

fn get_sysroot() -> Result<String, GuestImageError> {
    let output = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .map_err(GuestImageError::CargoIo)?;
    if !output.status.success() {
        return Err(GuestImageError::RustcFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| GuestImageError::RustcFailed(format!("sysroot not valid utf-8: {e}")))?;
    Ok(stdout.trim().to_string())
}

fn get_host_triple() -> Result<String, GuestImageError> {
    if let Ok(host) = std::env::var("HOST") {
        return Ok(host);
    }
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(GuestImageError::CargoIo)?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| GuestImageError::RustcFailed(format!("rustc -vV not valid utf-8: {e}")))?;
    for line in stdout.lines() {
        if let Some(host) = line.strip_prefix("host: ") {
            return Ok(host.trim().to_string());
        }
    }
    Err(GuestImageError::RustcFailed(
        "host triple not found in rustc -vV output".to_string(),
    ))
}

fn find_sysroot_tool(tool: &str, sysroot: &str, host: &str) -> Result<PathBuf, GuestImageError> {
    let sysroot_path = Path::new(sysroot)
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(tool);
    if sysroot_path.exists() {
        return Ok(sysroot_path);
    }

    if Command::new(tool).arg("--version").output().is_ok() {
        return Ok(PathBuf::from(tool));
    }

    Err(GuestImageError::MissingTool {
        tool: tool.to_string(),
        sysroot_path: sysroot_path.display().to_string(),
    })
}

fn check_no_fp_simd_instructions(
    llvm_objdump: &Path,
    elf_path: &Path,
    allowed_routines: &[String],
) -> Result<(), GuestImageError> {
    let output = Command::new(llvm_objdump)
        .arg("-d")
        .arg("--no-show-raw-insn")
        .arg(elf_path)
        .output()
        .map_err(|e| GuestImageError::ObjdumpFailed(format!("failed to run llvm-objdump: {e}")))?;
    if !output.status.success() {
        return Err(GuestImageError::ObjdumpFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| GuestImageError::ObjdumpFailed(format!("disassembly not valid utf-8: {e}")))?;

    let mut allowed_hits = vec![0usize; allowed_routines.len()];
    let mut in_routine: Option<usize> = None;
    let mut violations = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        // A symbol header: `0000000000001234 <name>:`.
        if let Some(name) = trimmed
            .strip_suffix(">:")
            .and_then(|head| head.split_once(" <"))
            .map(|(_, name)| name)
        {
            in_routine = allowed_routines.iter().position(|r| r == name);
            continue;
        }
        let Some((addr, rest)) = trimmed.split_once(':') else {
            continue;
        };
        // In disassembly, instruction lines start with hex address: "<hex>:\t<instruction>"
        if u64::from_str_radix(addr.trim(), 16).is_err() {
            continue;
        }
        let rest = rest.trim();
        if rest.is_empty() {
            continue;
        }

        // Strip comments (// or ;)
        let code_part = if let Some((code, _)) = rest.split_once("//") {
            code.trim()
        } else if let Some((code, _)) = rest.split_once(';') {
            code.trim()
        } else {
            rest
        };

        let parts: Vec<&str> = code_part.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let mnemonic = parts[0];
        let operands = if parts.len() > 1 {
            code_part[mnemonic.len()..].trim()
        } else {
            ""
        };

        let mut is_violation = false;
        // Check for floating-point/SIMD mnemonics starting with 'f'
        // (AArch64 floating point instructions: fadd, fsub, fmul, fdiv, fmov, fcmp, fcvt*, etc.)
        if mnemonic.starts_with('f') {
            is_violation = true;
        }

        // Check for SIMD specific mnemonics
        let simd_mnemonics = [
            "tbl", "tbx", "dup", "ins", "smov", "umov", "ext", "zip1", "zip2", "uzp1", "uzp2",
            "trn1", "trn2", "addv", "saddv", "uaddv", "smaxv", "sminv", "umaxv", "uminv",
        ];
        if simd_mnemonics.contains(&mnemonic) {
            is_violation = true;
        }

        // Tokenize operands: split by commas, brackets, braces, whitespace
        for token in operands.split(|c: char| {
            c == ',' || c == '[' || c == ']' || c == '{' || c == '}' || c.is_whitespace()
        }) {
            let token = token.trim();
            if token.is_empty() || token.starts_with('#') || token.starts_with("0x") {
                continue;
            }
            // Strip vector element specs like .4s, .16b, [0]
            let reg_base = token.split('.').next().unwrap_or(token);
            let reg_base = reg_base.split('[').next().unwrap_or(reg_base);

            if reg_base.eq_ignore_ascii_case("fpcr") || reg_base.eq_ignore_ascii_case("fpsr") {
                is_violation = true;
                break;
            }

            // Check if reg_base is q0..q31, v0..v31, d0..d31, s0..s31, h0..h31, b0..b31
            if reg_base.len() >= 2 && reg_base.len() <= 3 {
                let first = reg_base.as_bytes()[0].to_ascii_lowercase();
                if matches!(first, b'q' | b'v' | b'd' | b's' | b'h' | b'b')
                    && let Ok(reg_num) = reg_base[1..].parse::<u32>()
                    && reg_num <= 31
                {
                    is_violation = true;
                    break;
                }
            }
        }

        if is_violation {
            match in_routine {
                Some(routine) => allowed_hits[routine] += 1,
                None => violations.push(line.to_string()),
            }
        }
    }

    for (routine, &hits) in allowed_routines.iter().zip(&allowed_hits) {
        if (routine == "carrick_el1_fpsimd_save" || routine == "carrick_el1_fpsimd_load")
            && hits < 18
        {
            return Err(GuestImageError::FpsimdRoutineIncomplete {
                routine: routine.clone(),
                hits,
            });
        }
    }

    if !violations.is_empty() {
        return Err(GuestImageError::FpsimdViolation {
            count: violations.len(),
            details: violations.join("\n  "),
        });
    }

    Ok(())
}

fn resolve_manifest(composition_root: &Path) -> Result<PathBuf, GuestImageError> {
    if composition_root.is_file() {
        if composition_root.exists() {
            return Ok(composition_root.to_path_buf());
        }
        return Err(GuestImageError::ManifestNotFound(
            composition_root.to_path_buf(),
        ));
    }
    let manifest = composition_root.join("Cargo.toml");
    if manifest.exists() {
        return Ok(manifest);
    }
    Err(GuestImageError::ManifestNotFound(manifest))
}

fn resolve_bin_name(
    config: &GuestImageBuildConfig,
    manifest_path: &Path,
) -> Result<String, GuestImageError> {
    if let Some(bin) = &config.bin_name {
        return Ok(bin.clone());
    }
    if let Some(pkg) = &config.package {
        return Ok(pkg.clone());
    }
    let text = std::fs::read_to_string(manifest_path)?;
    let value: toml::Value = toml::from_str(&text).map_err(|e| {
        GuestImageError::PackageNameResolution(format!("failed to parse manifest as TOML: {e}"))
    })?;
    if let Some(name) = value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
    {
        return Ok(name.to_string());
    }
    if let Some(first_bin) = value
        .get("bin")
        .and_then(|b| b.as_array())
        .and_then(|a| a.first())
        .and_then(|b| b.get("name"))
        .and_then(|n| n.as_str())
    {
        return Ok(first_bin.to_string());
    }
    Err(GuestImageError::PackageNameResolution(
        "no package.name or bin[0].name found in Cargo.toml".to_string(),
    ))
}

/// Package a guest carrier image for an arbitrary composition root and target architecture.
pub fn package_guest_image(
    config: &GuestImageBuildConfig,
) -> Result<GuestImageArtifact, GuestImageError> {
    let manifest_path = resolve_manifest(&config.composition_root)?;
    let bin_name = resolve_bin_name(config, &manifest_path)?;
    let sysroot = get_sysroot()?;
    let host = get_host_triple()?;

    let target_str = config.target_arch.rust_target();
    let target_installed = Path::new(&sysroot).join("lib/rustlib").join(target_str);
    if !target_installed.exists() {
        return Err(GuestImageError::MissingTarget {
            target: target_str.to_string(),
        });
    }

    let target_dir = config
        .target_dir
        .clone()
        .unwrap_or_else(|| config.out_dir.join("target"));

    std::fs::create_dir_all(&config.out_dir)?;
    std::fs::create_dir_all(&target_dir)?;

    let cargo = config
        .cargo_path
        .clone()
        .or_else(|| std::env::var_os("CARGO").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("cargo"));

    let mut cmd = Command::new(&cargo);
    cmd.arg("build");
    cmd.arg("--manifest-path").arg(&manifest_path);
    if let Some(pkg) = &config.package {
        cmd.arg("-p").arg(pkg);
    }
    if let Some(bin) = &config.bin_name {
        cmd.arg("--bin").arg(bin);
    }
    cmd.arg("--target").arg(target_str);
    if config.profile == BuildProfile::Release {
        cmd.arg("--release");
    }
    cmd.arg("--target-dir").arg(&target_dir);
    if config.locked {
        cmd.arg("--locked");
    }
    if !config.features.is_empty() {
        cmd.arg("--features").arg(config.features.join(","));
    }

    cmd.env_remove("CARGO_MAKEFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    if !config.rustflags.is_empty() {
        cmd.env("RUSTFLAGS", config.rustflags.join(" "));
    }

    let status = cmd.status().map_err(GuestImageError::CargoIo)?;
    if !status.success() {
        return Err(GuestImageError::CargoBuildFailed(status));
    }

    let elf_path = target_dir
        .join(target_str)
        .join(config.profile.dir_name())
        .join(&bin_name);
    if !elf_path.exists() {
        return Err(GuestImageError::ElfNotFound(elf_path));
    }

    let binary_path = match config.target_arch {
        GuestTargetArch::Aarch64 => {
            let llvm_objdump = find_sysroot_tool("llvm-objdump", &sysroot, &host)?;
            let rust_objcopy = find_sysroot_tool("rust-objcopy", &sysroot, &host)?;

            check_no_fp_simd_instructions(
                &llvm_objdump,
                &elf_path,
                &config.expected_fpsimd_routines,
            )?;

            let bin_path = config
                .out_dir
                .join(config.target_arch.default_artifact_name(&bin_name));
            let mut objcopy_cmd = Command::new(&rust_objcopy);
            objcopy_cmd
                .arg("-O")
                .arg("binary")
                .arg(&elf_path)
                .arg(&bin_path);
            let objcopy_status = objcopy_cmd.status().map_err(GuestImageError::ObjcopyIo)?;
            if !objcopy_status.success() {
                return Err(GuestImageError::ObjcopyFailed(objcopy_status));
            }
            bin_path
        }
        GuestTargetArch::X86_64 => {
            let bin_path = config
                .out_dir
                .join(config.target_arch.default_artifact_name(&bin_name));
            if elf_path != bin_path {
                std::fs::copy(&elf_path, &bin_path)?;
            }
            bin_path
        }
    };

    Ok(GuestImageArtifact {
        target_arch: config.target_arch,
        binary_path,
        elf_path,
    })
}

/// CLI arguments for `carrick-xtask package-guest-image`.
#[derive(Args, Debug)]
pub struct PackageGuestImageArgs {
    #[arg(long, help = "Path to composition root crate directory or Cargo.toml")]
    pub root: PathBuf,

    #[arg(long, value_enum, help = "Target architecture (aarch64 or x86_64)")]
    pub arch: GuestTargetArch,

    #[arg(long, help = "Output directory for packaged image")]
    pub out_dir: PathBuf,

    #[arg(long, help = "Package name (-p) within a workspace")]
    pub package: Option<String>,

    #[arg(long, help = "Binary target name (--bin)")]
    pub bin: Option<String>,

    #[arg(long, value_enum, default_value = "release", help = "Build profile")]
    pub profile: BuildProfile,

    #[arg(long, help = "Features to enable (comma-separated)")]
    pub features: Vec<String>,

    #[arg(long, help = "Run cargo with --locked")]
    pub locked: bool,
}

pub fn run_package_guest_image(args: &PackageGuestImageArgs) -> Result<(), GuestImageError> {
    let mut config = GuestImageBuildConfig::new(&args.root, args.arch, &args.out_dir);
    config.package = args.package.clone();
    config.bin_name = args.bin.clone();
    config.profile = args.profile;
    config.features = args.features.clone();
    config.locked = args.locked;

    let artifact = package_guest_image(&config)?;
    println!(
        "Successfully packaged {} guest image: {}",
        artifact.target_arch,
        artifact.binary_path.display()
    );
    Ok(())
}
