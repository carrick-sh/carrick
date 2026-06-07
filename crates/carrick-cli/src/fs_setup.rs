//! Filesystem-backend selection and guest-baseline seeding for `run-elf` runs.
//!
//! # Theory of operation
//!
//! A guest needs a writable root filesystem with Linux semantics. Two backends
//! provide one (both in `carrick_runtime::fs_backend`), and this module is the
//! policy layer that picks between them and pre-populates them — for the
//! engine-less `run-elf` fixture path. (The docker `run` path makes the
//! equivalent choice inside `carrick-engine`; this module is what the bare-ELF
//! and conformance fixtures use.)
//!
//! - **`MemoryBackend`** — an in-memory tmpfs overlay layered on the OCI rootfs
//!   tar. Works anywhere, but writes are RAM-only and gone at exit.
//! - **`HostFsBackend`** — the "rootfs as APFS, throw away when done"
//!   architecture. Instead of overlaying a writable layer on the in-memory tar,
//!   it *materialises* every rootfs file/dir/symlink onto a cap-std-sandboxed
//!   scratch directory on a real (case-sensitive) host volume. After that seed,
//!   every fs syscall flows through *real* host syscalls (openat/renameat/
//!   symlinkat/…) against a real filesystem. That is what gives apt/dpkg their
//!   genuine Linux fs semantics (atomic rename, `symlinkat`, clear-signed-file
//!   splitting) that the in-memory overlay could only approximate. Once the host
//!   backend has materialised the COMPLETE rootfs, the redundant in-memory
//!   rootfs layer is dropped (`drop_rootfs_layer`) so reads, `execve`, and the
//!   ELF interpreter loader all resolve against the authoritative disk overlay.
//!
//! ## Default selection: case-sensitivity is the deciding fact
//!
//! Linux paths assume a case-sensitive filesystem; the stock macOS boot volume
//! is case-INsensitive. `host` is the secure-by-default, real-semantics choice,
//! so the default (`carrick_runtime::apfs::default_writable_backend_kind`) probes
//! the *exact* scratch root the host backend will use —
//! `apfs::preferred_scratch_root`, which prefers the
//! dedicated case-sensitive `/Volumes/carrick` volume — and chooses `host` iff
//! that root is case-sensitive, else falls back to `memory` with a warning.
//! Probing the real root (not a hardcoded `~/.carrick`) matters: the dedicated
//! volume can be case-sensitive while `$HOME` is not, and probing the wrong path
//! would wrongly downgrade to memory.
//!
//! Both fall-back paths are non-fatal by design: a failed `--fs host` seed, or
//! an unconstructable scratch dir, degrades to the in-memory backend with a
//! warning rather than failing the run.
//!
//! ## Guest baseline seeding
//!
//! `seed_guest_baseline` pre-populates *either* backend with a minimal Linux
//! skeleton (`/tmp` sticky, passwd/group/nsswitch, an `/etc/hosts` whose entries
//! are resolved on the macOS host, and an `/etc/hostname`/`127.0.1.1` line in
//! lockstep with `carrick_runtime::execute::guest_hostname` — the single UTS
//! nodename source that also feeds `uname(2)` and `/proc`). Raw static binaries
//! arrive with no OCI rootfs, yet enough real software assumes these paths exist
//! that carrick seeds them unconditionally.

use anyhow::Result;
use carrick_runtime::dispatch::SyscallDispatcher;
#[cfg(feature = "fs-memory")]
use carrick_runtime::fs_backend::MemoryBackend;
use carrick_runtime::fs_backend::{FsBackend, HostFsBackend};
use carrick_spec::FsBackendKind;

/// On a `--fs host` failure, fall back to the in-memory backend when the
/// `fs-memory` feature is compiled in, or hard-error with an actionable message
/// when it isn't (the "host, then error" rule).
#[cfg(feature = "fs-memory")]
fn host_failure_fallback(reason: &str) -> Result<(Box<dyn FsBackend>, FsBackendKind)> {
    tracing::warn!("carrick: {reason}; falling back to in-memory backend");
    Ok((Box::new(MemoryBackend::new()), FsBackendKind::Memory))
}

#[cfg(not(feature = "fs-memory"))]
fn host_failure_fallback(reason: &str) -> Result<(Box<dyn FsBackend>, FsBackendKind)> {
    anyhow::bail!(
        "carrick: {reason}; the in-memory fallback is not compiled in. \
         Rebuild with `--features fs-memory`, or run on a writable case-sensitive scratch volume."
    )
}

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
) -> Result<FsBackendKind> {
    let kind = fs.unwrap_or_else(carrick_runtime::apfs::default_writable_backend_kind);
    // Set once the host backend has materialised the COMPLETE rootfs onto
    // disk - after which the in-memory rootfs layer is redundant and gets
    // dropped (the disk overlay is authoritative for every read).
    let mut host_seeded = false;
    let mut backend: Box<dyn FsBackend> = match kind {
        #[cfg(feature = "fs-memory")]
        FsBackendKind::Memory => Box::new(MemoryBackend::new()),
        FsBackendKind::Host => match HostFsBackend::new() {
            Ok(mut host) => {
                // SEED THE BACKEND WITH THE FULL ROOTFS. ("rootfs as APFS, throw
                // away when done": materialise every rootfs file/dir/symlink onto
                // the cap-std scratch dir so all fs syscalls flow through real
                // host syscalls against a real filesystem.)
                if let Some(rootfs) = dispatcher.rootfs() {
                    if let Err(err) = host.seed_from_rootfs(rootfs) {
                        let (mut mem, kind) = host_failure_fallback(&format!(
                            "--fs host seed-from-rootfs failed ({err})"
                        ))?;
                        seed_guest_baseline(&mut *mem);
                        let _ = dispatcher.set_fs_backend(mem);
                        return Ok(kind);
                    }
                    host_seeded = true;
                }
                Box::new(host)
            }
            Err(err) => host_failure_fallback(&format!("--fs host failed ({err})"))?.0,
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
    Ok(kind)
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
    // Self-mapping so the guest's own hostname resolves
    // (`gethostbyname(gethostname())`), as every Linux host and Docker container
    // has. Debian convention: the configured hostname on a dedicated 127.0.1.1,
    // distinct from 127.0.0.1 localhost. The name is the canonical UTS nodename
    // (single source of truth) so /etc/hosts stays in lockstep with uname(2) and
    // /proc/sys/kernel/hostname. --net=host: one global hostname on loopback.
    hosts_content.push_str(&format!(
        "127.0.1.1\t{}\n",
        carrick_runtime::execute::guest_hostname()
    ));
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
    // /etc/hostname must agree with uname(2)/gethostname()/proc — overwrite the
    // image's build-time value (e.g. `debuerreotype`) with the runtime guest
    // hostname, like Docker writes the container hostname at create.
    let _ = backend.set_file_contents(
        "/etc/hostname",
        format!("{}\n", carrick_runtime::execute::guest_hostname()).into_bytes(),
    );
}
