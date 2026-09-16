//! Explicit host-operator boundary for `carrick volume`.
//!
//! This module may create the `diskutil` operator process. It is never linked
//! into `carrick-runtime`; carrier launch receives neither this type nor an
//! [`carrick_vfs::apfs::ApfsOperator`] capability.

use std::process::Command;

pub(crate) struct DiskutilOperator;

impl carrick_vfs::apfs::ApfsOperator for DiskutilOperator {
    fn run_diskutil(&mut self, args: &[&str]) -> Result<String, carrick_vfs::apfs::ApfsError> {
        let output = Command::new("diskutil")
            .args(args)
            .output()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    carrick_vfs::apfs::ApfsError::DiskutilMissing
                } else {
                    carrick_vfs::apfs::ApfsError::Io(error)
                }
            })?;
        if !output.status.success() {
            return Err(carrick_vfs::apfs::ApfsError::DiskutilFailed {
                operation: args.join(" "),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}
