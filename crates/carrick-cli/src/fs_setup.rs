//! Filesystem backend setup for CLI runs.

use anyhow::Result;
use carrick_runtime::dispatch::SyscallDispatcher;
use carrick_runtime::fs_backend::{FsBackend, HostFsBackend, MemoryBackend};
use carrick_spec::FsBackendKind;

/// Resolve `--fs <memory|host>` into a concrete `Box<dyn FsBackend>`
/// and install it on the dispatcher. When the user did not pass an
/// explicit `--fs`, the default is `host` iff the scratch root sits
/// on a case-sensitive volume (the only place Linux semantics survive
/// intact) and `memory` otherwise, with a stderr warning.
///
/// If `--fs host` is requested but the cap-std scratch directory
/// cannot be constructed (e.g. `HOME` is unwritable) we fall back to
/// the in-memory backend with a warning rather than failing the run.
pub(crate) fn install_fs_backend(
    dispatcher: &mut SyscallDispatcher,
    fs: Option<FsBackendKind>,
) -> Result<()> {
    let kind = fs.unwrap_or_else(default_fs_backend_kind);
    // Set once the host backend has materialised the COMPLETE rootfs onto
    // disk - after which the in-memory rootfs layer is redundant and gets
    // dropped (the disk overlay is authoritative for every read).
    let mut host_seeded = false;
    let mut backend: Box<dyn FsBackend> = match kind {
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                // SEED THE BACKEND WITH THE FULL ROOTFS.
                //
                // This is the "rootfs as APFS, throw away when done"
                // architecture: instead of layering the writable
                // overlay on top of the in-memory tar, materialise
                // every rootfs file/dir/symlink onto the cap-std-
                // sandboxed scratch directory. After this point, all
                // fs syscalls flow through real host syscalls
                // (openat/renameat/symlinkat/...) against a real
                // filesystem - which fixes apt's downstream chain
                // (symlinkat EROFS, SplitClearSignedFile, atomic
                // rename) by giving it real Linux fs semantics.
                if let Some(rootfs) = dispatcher.rootfs() {
                    if let Err(err) = host.seed_from_rootfs(rootfs) {
                        tracing::warn!(
                            "carrick: --fs host seed-from-rootfs failed ({err}); falling back to in-memory backend"
                        );
                        let mut mem: Box<dyn FsBackend> = Box::new(MemoryBackend::new());
                        seed_guest_baseline(&mut *mem);
                        let _ = dispatcher.set_fs_backend(mem);
                        return Ok(());
                    }
                    host_seeded = true;
                }
                Box::new(host)
            }
            Err(err) => {
                tracing::warn!(
                    "carrick: --fs host failed ({err}); falling back to in-memory backend"
                );
                Box::new(MemoryBackend::new())
            }
        },
    };
    seed_guest_baseline(&mut *backend);
    let _ = dispatcher.set_fs_backend(backend);
    // The disk overlay now holds the entire filesystem; drop the redundant
    // in-memory rootfs layer so reads, execve and the ELF interpreter
    // loader all flow through the materialised host disk.
    if host_seeded {
        dispatcher.drop_rootfs_layer();
    }
    Ok(())
}

/// Pre-populate the writable overlay with a small Linux baseline plus
/// `/etc/hosts` entries resolved on the macOS host. Raw static binaries have
/// no OCI rootfs to supply `/tmp`, passwd/group databases, or resolver files;
/// enough real software assumes those paths exist that Carrick seeds them for
/// both memory and host backends.
fn seed_guest_baseline(backend: &mut dyn FsBackend) {
    use std::net::ToSocketAddrs;
    for dir in [
        "/tmp",
        "/var",
        "/var/tmp",
        "/root",
        "/etc",
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/sbin",
    ] {
        let _ = backend.make_dir(dir);
    }
    let _ = backend.set_mode("/tmp", 0o1777);
    let _ = backend.set_mode("/var/tmp", 0o1777);
    let _ = backend.set_file_contents(
        "/etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            .to_vec(),
    );
    let _ = backend.set_file_contents("/etc/group", b"root:x:0:\nnogroup:x:65534:\n".to_vec());
    let _ = backend.set_file_contents(
        "/etc/nsswitch.conf",
        b"passwd: files\ngroup: files\nhosts: files dns\n".to_vec(),
    );

    const HOSTNAMES: &[&str] = &[
        "deb.debian.org",
        "security.debian.org",
        "ftp.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "ports.ubuntu.com",
    ];
    let mut hosts_content = String::from(
        "127.0.0.1\tlocalhost\n\
         ::1\tlocalhost ip6-localhost ip6-loopback\n\
         ff02::1\tip6-allnodes\n\
         ff02::2\tip6-allrouters\n",
    );
    for hostname in HOSTNAMES {
        if let Ok(addrs) = (*hostname, 80u16).to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        hosts_content.push_str(&format!("{}\t{}\n", v4, hostname));
                        break; // one A record is enough; saves /etc/hosts noise
                    }
                    std::net::IpAddr::V6(_) => {}
                }
            }
        }
    }
    let _ = backend.set_file_contents("/etc/hosts", hosts_content.into_bytes());
}

/// Default backend choice: prefer `host` because that's the secure-
/// by-default option, but quietly fall back to `memory` when the
/// scratch root sits on a case-insensitive filesystem (a common
/// macOS default that breaks anything assuming Linux semantics).
fn default_fs_backend_kind() -> FsBackendKind {
    // Probe the SAME scratch root the host backend will actually use
    // (`preferred_scratch_root` prefers the dedicated case-sensitive
    // `/Volumes/carrick` volume), not a hardcoded `~/.carrick/scratch`.
    // Otherwise the decision and the real scratch location disagree: the
    // dedicated volume can be case-sensitive while `~/.carrick` is not, and we
    // would wrongly fall back to the in-memory backend.
    let probe = carrick_runtime::apfs::preferred_scratch_root()
        .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
    if std::fs::create_dir_all(&probe).is_err() {
        return FsBackendKind::Memory;
    }
    if carrick_runtime::apfs::probe_case_sensitive(&probe) {
        FsBackendKind::Host
    } else {
        tracing::warn!(
            "carrick: {} is case-insensitive; defaulting --fs to memory. \
             Pass `--fs host` to force the cap-std backend (some Linux tools may misbehave).",
            probe.display()
        );
        FsBackendKind::Memory
    }
}
