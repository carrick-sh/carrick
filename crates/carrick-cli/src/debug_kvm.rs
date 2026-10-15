//! Live x86 KVM capture over the existing authenticated kernel debug socket.

use std::path::Path;

use anyhow::Context;

pub(crate) fn capture(run_id: &str, output_dir: &Path) -> anyhow::Result<()> {
    let snapshot = carrick_kernel::kernel::debug::capture(run_id)
        .with_context(|| format!("capture live KVM run {run_id}"))?;
    let output = snapshot
        .write_to_dir(output_dir)
        .with_context(|| format!("write KVM capture to {}", output_dir.display()))?;
    println!("{}", output.display());
    Ok(())
}
