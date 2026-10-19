//! `cargo xtask frame-budget`: the ring stack audit outside an image build.
//!
//! The image build scripts already fail on a violation; this builds the ARM
//! EL1 image and both x86 CPL0 images into a private target directory (or
//! takes `--elf` paths), prints every entry's deepest chain, and with
//! `--red-fixture` proves the audit rejects the fixture personality's
//! deliberately oversized frame.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use carrick_ring_audit::frames::Violation;

#[derive(clap::Args, Debug, Clone)]
pub struct FrameBudgetArgs {
    /// Audit these built ring images instead of building them.
    #[arg(long)]
    pub elf: Vec<PathBuf>,

    /// Build the x86 fixture image with its oversized red-fixture frame and
    /// succeed only if the audit rejects it for that frame.
    #[arg(long)]
    pub red_fixture: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameBudgetError {
    #[error("{0}")]
    Toolchain(String),
    #[error("{0}")]
    Build(String),
    #[error("ring stack audit failed for {0}")]
    Failed(String),
    #[error(
        "the red fixture image passed the ring stack audit; the gate cannot see an oversized frame"
    )]
    RedFixturePassed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The red fixture's oversized function, as the audit names it.
pub const RED_FIXTURE_FUNCTION: &str = "frame_budget_red_fixture";

/// Cargo as `cargo run` supplies it, else the first `cargo` on `PATH`
/// (whose sibling `rustc` honours this checkout's toolchain pin).
fn cargo() -> PathBuf {
    if let Some(cargo) = std::env::var_os("CARGO") {
        return PathBuf::from(cargo);
    }
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join("cargo"))
                .find(|candidate| candidate.is_file())
        })
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

fn build(root: &Path, target_dir: &Path, args: &[&str]) -> Result<(), FrameBudgetError> {
    let status = Command::new(cargo())
        .current_dir(root)
        .arg("build")
        .arg("--locked")
        .arg("--release")
        .args(args)
        .arg("--target-dir")
        .arg(target_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(FrameBudgetError::Build(format!(
            "cargo build {} failed: {status}",
            args.join(" ")
        )))
    }
}

fn ring_images(root: &Path) -> Result<Vec<PathBuf>, FrameBudgetError> {
    let target = root.join("target/frame-budget");
    build(
        root,
        &target,
        &[
            "-p",
            "carrick-el1-linux",
            "--bin",
            "carrick-el1",
            "--target",
            "aarch64-unknown-none-softfloat",
        ],
    )?;
    build(
        root,
        &target,
        &[
            "-p",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0-fixture",
            "--target",
            "x86_64-unknown-none",
        ],
    )?;
    Ok(vec![
        target.join("aarch64-unknown-none-softfloat/release/carrick-el1"),
        target.join("x86_64-unknown-none/release/carrick-x86-cpl0"),
        target.join("x86_64-unknown-none/release/carrick-x86-cpl0-fixture"),
    ])
}

/// The two red fixture images: the EL1 image and the CPL0 fixture image,
/// each with its `frame-budget-red-fixture` record.
fn red_fixture_images(root: &Path) -> Result<Vec<PathBuf>, FrameBudgetError> {
    let target = root.join("target/frame-budget-red");
    build(
        root,
        &target,
        &[
            "-p",
            "carrick-el1-linux",
            "--bin",
            "carrick-el1",
            "--features",
            "frame-budget-red-fixture",
            "--target",
            "aarch64-unknown-none-softfloat",
        ],
    )?;
    build(
        root,
        &target,
        &[
            "-p",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0-fixture",
            "--features",
            "frame-budget-red-fixture",
            "--target",
            "x86_64-unknown-none",
        ],
    )?;
    Ok(vec![
        target.join("aarch64-unknown-none-softfloat/release/carrick-el1"),
        target.join("x86_64-unknown-none/release/carrick-x86-cpl0-fixture"),
    ])
}

/// Whether `violations` name the red fixture's frame on its entry chain.
pub fn rejects_red_fixture(violations: &[Violation]) -> bool {
    let ceiling = violations.iter().any(|violation| {
        matches!(violation, Violation::FunctionCeiling { name, .. } if name.ends_with(RED_FIXTURE_FUNCTION))
    });
    let chain = violations.iter().any(|violation| match violation {
        Violation::EntryBudget(depth) => depth.chain.iter().any(|link| {
            matches!(link, carrick_ring_audit::frames::Link::Call { name, .. } if name.ends_with(RED_FIXTURE_FUNCTION))
        }),
        _ => false,
    });
    ceiling && chain
}

pub fn run(
    root: &Path,
    args: &FrameBudgetArgs,
    out: &mut dyn Write,
) -> Result<(), FrameBudgetError> {
    let objdump = carrick_ring_audit::toolchain::llvm_objdump(&cargo())
        .map_err(FrameBudgetError::Toolchain)?;
    if args.red_fixture {
        for image in red_fixture_images(root)? {
            let report = carrick_ring_audit::audit_image(&objdump, &image)
                .map_err(FrameBudgetError::Toolchain)?;
            write!(out, "{}", carrick_ring_audit::summary(&report))?;
            if !rejects_red_fixture(&report.violations) {
                return Err(FrameBudgetError::RedFixturePassed);
            }
            writeln!(
                out,
                "red fixture rejected ({:?}): {RED_FIXTURE_FUNCTION} has an oversized frame on a ring entry chain",
                report.arch
            )?;
        }
        return Ok(());
    }
    let images = if args.elf.is_empty() {
        ring_images(root)?
    } else {
        args.elf.clone()
    };
    let mut failed = Vec::new();
    for image in &images {
        let report = carrick_ring_audit::audit_image(&objdump, image)
            .map_err(FrameBudgetError::Toolchain)?;
        writeln!(out, "== {}", image.display())?;
        if let Some((name, frame)) = &report.largest_frame {
            writeln!(out, "largest frame {frame:#x}: {name}")?;
        }
        writeln!(out, "reachable functions: {}", report.reachable)?;
        for entry in &report.entries {
            write!(out, "{entry}")?;
        }
        for violation in &report.violations {
            writeln!(out, "VIOLATION: {violation}")?;
        }
        if !report.passed() {
            failed.push(image.display().to_string());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(FrameBudgetError::Failed(failed.join(", ")))
    }
}
