//! Read-only retirement admission. The director destroys only after this passes;
//! Proxmox's base-volume reference check remains the final destructive backstop.
use super::{CloneLane, ScalerError, execute, site};
use serde_json::Value;
use std::{os::unix::fs::MetadataExt, path::Path, process::Command, time::Duration};

pub(super) fn check(vmid: u16) -> Result<(), ScalerError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ScalerError::Guard(
            "template retirement check requires root",
        ));
    }
    check_with(site::Site::local()?, vmid, |args| {
        let (program, args) = args
            .split_first()
            .ok_or(ScalerError::Guard("empty command"))?;
        String::from_utf8(execute(
            Command::new(program).args(args),
            &[],
            Duration::from_secs(40),
        )?)
        .map_err(|_| ScalerError::Guard("non UTF-8 storage output"))
    })?;
    println!(
        "Agent template {vmid} has no linked disk references; Proxmox must recheck at destruction. Keep its ACL and firewall until qm destroy succeeds."
    );
    Ok(())
}

fn check_with(
    site: site::Site,
    vmid: u16,
    mut run: impl FnMut(&[&str]) -> Result<String, ScalerError>,
) -> Result<(), ScalerError> {
    let template = site::AgentTemplate::try_from(vmid)?;
    let agent_site = site.for_lane(CloneLane::Agent)?;
    if agent_site.template()? == template.vmid() {
        return Err(ScalerError::Guard(
            "cannot retire the active agent template",
        ));
    }
    let id = vmid.to_string();
    let config = run(&["qm", "config", &id])?;
    if !config.lines().any(|line| line == "template: 1") {
        return Err(ScalerError::Guard("retirement target is not a template"));
    }
    // Inspect storage, not the controller ledger or pool: stopped clones and
    // clones outside the pool also retain bases. Directory-backed agent bases
    // cannot be referenced by raw disks; every qcow2 chain must be readable.
    let volumes = super::live::image_inventory(site.node, site.storage, &mut |args| {
        Ok(serde_json::from_str(&run(args)?)?)
    })?;
    let mut bases = Vec::new();
    let mut disks = Vec::new();
    for volume in &volumes {
        let format = volume["format"]
            .as_str()
            .ok_or(ScalerError::Guard("missing volume format"))?;
        if format == "raw" {
            continue;
        }
        if format != "qcow2" {
            return Err(ScalerError::Guard("unrecognized directory image format"));
        }
        let volid = volume["volid"]
            .as_str()
            .ok_or(ScalerError::Guard("missing volume ID"))?;
        let path = run(&["pvesm", "path", volid])?.trim().to_owned();
        if !Path::new(&path).is_absolute() || path.contains(['\n', '\r']) {
            return Err(ScalerError::Guard("invalid image path"));
        }
        let owner = super::live::pve_vmid(volume);
        if owner == Some(u64::from(vmid)) {
            bases.push(image_identity(&path)?);
        } else {
            disks.push(path);
        }
    }
    if bases.is_empty() {
        return Err(ScalerError::Guard("retirement base image missing"));
    }
    for disk in disks {
        // -U permits inspection of a running clone, without taking its write
        // lock. This is an observation, not a substitute for qm destroy's check.
        let chain: Value = serde_json::from_str(&run(&[
            "qemu-img",
            "info",
            "-U",
            "--backing-chain",
            "--output=json",
            &disk,
        ])?)?;
        let chain = chain
            .as_array()
            .filter(|chain| !chain.is_empty())
            .ok_or(ScalerError::Guard("invalid backing chain"))?;
        for image in chain {
            let filename = image["filename"]
                .as_str()
                .ok_or(ScalerError::Guard("backing chain lacks filename"))?;
            if !Path::new(filename).is_absolute() {
                return Err(ScalerError::Guard("backing chain path is not absolute"));
            }
            let identity = image_identity(filename)?;
            let backing = image["full-backing-filename"]
                .as_str()
                .map(image_identity)
                .transpose()?;
            if bases.contains(&identity) || backing.is_some_and(|id| bases.contains(&id)) {
                return Err(ScalerError::Guard(
                    "agent template still has a linked clone",
                ));
            }
        }
    }
    Ok(())
}

// Resolve symlinks, relative components and hard-link aliases by identity,
// rather than trusting a particular spelling of qemu-img's backing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImageIdentity {
    device: u64,
    inode: u64,
}
fn image_identity(path: &str) -> Result<ImageIdentity, ScalerError> {
    if !Path::new(path).is_absolute() {
        return Err(ScalerError::Guard("image path is not absolute"));
    }
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(ScalerError::Guard("image is not a regular file"));
    }
    Ok(ImageIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn retirement_checks_stopped_and_unpooled_disks_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        for subdir in ["9001", "308"] {
            std::fs::create_dir(dir.path().join(subdir)).unwrap();
        }
        std::fs::write(dir.path().join("9001/base.qcow2"), []).unwrap();
        std::fs::write(dir.path().join("308/disk.qcow2"), []).unwrap();
        std::fs::hard_link(
            dir.path().join("9001/base.qcow2"),
            dir.path().join("alias.qcow2"),
        )
        .unwrap();
        for (chain, allowed) in [
            (
                json!([{"filename":"/images/308/disk.qcow2", "full-backing-filename":"/images/9001/base.qcow2"},
                    {"filename":"/images/9001/base.qcow2"}]),
                false,
            ),
            (
                json!([{"filename":"/images/308/disk.qcow2"}, {"filename":"/images/alias.qcow2"}]),
                false,
            ),
            (json!([{"filename":"/images/308/disk.qcow2"}]), true),
            (json!([]), false),
        ] {
            let result = check_with(site::CONTABO, 9001, |args| {
                let output: String = match args {
                    ["qm", "config", "9001"] => "template: 1\n".into(),
                    [
                        "pvesh",
                        "get",
                        "/nodes/carrick-ctb/storage/local/content",
                        "--content",
                        "images",
                        "--output-format",
                        "json",
                    ] => json!([
                        {"content":"images","vmid":"9001","format":"qcow2","volid":"local:9001/base.qcow2"},
                        {"content":"images","vmid":308,"format":"qcow2","volid":"local:308/disk.qcow2"}
                    ])
                    .to_string(),
                    ["pvesm", "path", "local:9001/base.qcow2"] => {
                        "/images/9001/base.qcow2\n".into()
                    }
                    ["pvesm", "path", "local:308/disk.qcow2"] => "/images/308/disk.qcow2\n".into(),
                    [
                        "qemu-img",
                        "info",
                        "-U",
                        "--backing-chain",
                        "--output=json",
                        _,
                    ] => chain.to_string(),
                    _ => panic!("unexpected command: {args:?}"),
                };
                Ok(output.replace("/images", &dir.path().to_string_lossy()))
            });
            assert_eq!(result.is_ok(), allowed, "{result:?}");
        }
    }

    #[test]
    fn retirement_refuses_active_and_unapproved_ids_before_commands() {
        for vmid in [9000, 9002, 300, 308] {
            assert!(check_with(site::CONTABO, vmid, |_| panic!("must refuse first")).is_err());
        }
    }
}
