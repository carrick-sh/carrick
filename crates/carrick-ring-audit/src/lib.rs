//! Build-time audits of Carrick's freestanding ring images.
//!
//! The ARM EL1 image (`carrick-el1-image`) and the x86 CPL0 images
//! (`carrick-vmm-kvm`) run this from their build scripts on the exact
//! artifact they embed, so a ring stack overflow that is statically knowable
//! fails the build (#338, #369). `cargo xtask frame-budget` runs the same
//! audit outside a build and prints every entry chain.

pub mod elf;
pub mod frames;
pub mod policy;
pub mod toolchain;

use std::path::Path;

pub use frames::{Arch, Report};

/// Audit one built ring image file with its architecture's policy, or with
/// the policy `select` picks for that architecture.
pub fn audit_image_with(
    llvm_objdump: &Path,
    elf: &Path,
    select: fn(Arch) -> &'static frames::Policy,
) -> Result<Report, String> {
    let headers = toolchain::objdump(llvm_objdump, elf, &["-h"])?;
    let arch = elf::arch_of(&headers)?;
    let mut args = vec!["-s".to_owned()];
    for section in elf::data_sections(&headers) {
        args.push("-j".to_owned());
        args.push(section);
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let data = elf::ElfData::parse(arch, &toolchain::objdump(llvm_objdump, elf, &args)?)?;
    let disassembly = toolchain::disassemble(llvm_objdump, elf, arch)?;
    let image = frames::Image::parse(arch, &disassembly, Some(&data))?;
    Ok(frames::audit(&image, select(arch)))
}

/// Audit one built ring image file with its architecture's policy.
pub fn audit_image(llvm_objdump: &Path, elf: &Path) -> Result<Report, String> {
    audit_image_with(llvm_objdump, elf, policy::for_arch)
}

/// The deepest entry chain of each kind on one line apiece, then every
/// violation: what an image build prints.
pub fn summary(report: &Report) -> String {
    use frames::Depth;
    let mut text = String::new();
    for (kind, label) in [
        (Depth::Certain, "each recursion once"),
        (Depth::Bounded, "recursion at its bound"),
    ] {
        if let Some(entry) = report
            .entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .max_by_key(|entry| entry.depth)
        {
            text.push_str(&format!(
                "{:?} ring stack ({label}): {} bytes worst case, from {}; limit {} bytes, usable stack {} bytes\n",
                report.arch, entry.depth, entry.entry, entry.budget, report.stack_budget
            ));
        }
    }
    if let Some((name, frame)) = &report.largest_frame {
        text.push_str(&format!(
            "{:?} largest ring frame: {frame} bytes, {name}\n",
            report.arch
        ));
    }
    for violation in &report.violations {
        text.push_str(&format!("{violation}\n"));
    }
    text
}
