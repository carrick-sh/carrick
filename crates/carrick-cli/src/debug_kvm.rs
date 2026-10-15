//! Live x86 KVM capture over the existing authenticated kernel debug socket.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;

pub(crate) fn capture(run_id: &str, output: &Path) -> anyhow::Result<()> {
    let snapshot = carrick_kernel::kernel::debug::capture(run_id)
        .with_context(|| format!("capture live KVM run {run_id}"))?;
    let bytes = serde_json::to_vec_pretty(&snapshot)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(output)
        .with_context(|| format!("open KVM capture at {}", output.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write KVM capture to {}", output.display()))?;
    file.sync_all()
        .with_context(|| format!("sync KVM capture at {}", output.display()))?;
    println!("{}", output.display());
    Ok(())
}
