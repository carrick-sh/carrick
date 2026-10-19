//! The pinned toolchain's own binary tools, found the way Cargo would.
//!
//! Every ring image build script and the `frame-budget` xtask resolve the
//! compiler sysroot and its `llvm-tools` here, so an image is inspected by
//! the same toolchain that produced it.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::frames::Arch;

/// The sysroot of the toolchain whose Cargo is `cargo`.
///
/// Cargo supplies its executable path. Query that toolchain's sibling rustc,
/// independently of `PATH` and any census compiler wrappers.
pub fn get_sysroot(cargo: &Path) -> Result<String, String> {
    let cargo_bin = cargo
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("Cargo path {cargo:?} has no compiler directory"))?;
    let mut command = Command::new(cargo_bin.join("rustc"));
    let output = command
        .args(["--print", "sysroot"])
        .output()
        .map_err(|error| format!("failed to query compiler sysroot ({command:?}): {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compiler sysroot query ({command:?}) failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let sysroot = String::from_utf8(output.stdout)
        .map_err(|error| format!("sysroot is not valid UTF-8: {error}"))?;
    let sysroot = sysroot.trim();
    if sysroot.is_empty() {
        return Err(format!(
            "compiler sysroot query ({command:?}) returned an empty path"
        ));
    }
    Ok(sysroot.to_owned())
}

/// `tool` from the sysroot's `llvm-tools` component for `host`, or from
/// `PATH` when the component directory lacks it.
pub fn find_sysroot_tool(tool: &str, sysroot: &str, host: &str) -> Result<PathBuf, String> {
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
    Err(format!(
        "{tool} not found in sysroot ({sysroot_path:?}) or on PATH.\n\
         Install the llvm-tools component with:\n    rustup component add llvm-tools-preview"
    ))
}

/// `llvm-objdump` output for `elf` with `args`.
pub fn objdump(llvm_objdump: &Path, elf: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(llvm_objdump)
        .args(args)
        .arg(elf)
        .output()
        .map_err(|error| format!("failed to run {llvm_objdump:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "llvm-objdump {} failed on {elf:?}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("llvm-objdump output is not UTF-8: {error}"))
}

/// Demangled disassembly of `elf` with its symbol table, in the syntax the
/// frame parser reads (Intel syntax on x86_64).
pub fn disassemble(llvm_objdump: &Path, elf: &Path, arch: Arch) -> Result<String, String> {
    let mut args = vec!["-d", "--syms", "--no-show-raw-insn", "--demangle"];
    if arch == Arch::X86_64 {
        args.extend(["-M", "intel"]);
    }
    objdump(llvm_objdump, elf, &args)
}

/// The host triple of the toolchain whose Cargo is `cargo`.
pub fn host_triple(cargo: &Path) -> Result<String, String> {
    let cargo_bin = cargo
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("Cargo path {cargo:?} has no compiler directory"))?;
    let mut command = Command::new(cargo_bin.join("rustc"));
    let output = command
        .arg("-vV")
        .output()
        .map_err(|error| format!("failed to query compiler host ({command:?}): {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compiler host query ({command:?}) failed with {}",
            output.status
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_owned())
        .ok_or_else(|| format!("compiler host query ({command:?}) printed no host"))
}

/// `llvm-objdump` from the toolchain whose Cargo is `cargo`.
pub fn llvm_objdump(cargo: &Path) -> Result<PathBuf, String> {
    let sysroot = get_sysroot(cargo)?;
    find_sysroot_tool("llvm-objdump", &sysroot, &host_triple(cargo)?)
}
