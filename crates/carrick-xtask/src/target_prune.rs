//! Target cleanup with lifetime-held directory and native Cargo authorities.
use crate::host_lease::{DEFAULT_LOCK_PATH, HostLease};
use crate::lock_file::OwnedFileLock;
use crate::prune_fs as at;
use crate::remote_accept::shell_quote;
use crate::worktree_gc::{GcError, WorktreeGcArgs};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type CensusHandles = BTreeMap<i32, PathBuf>;
struct CheckoutGuard(PathBuf);
impl CheckoutGuard {
    fn claim(path: &Path) -> std::io::Result<Option<Self>> {
        match fs::create_dir(path) {
            Ok(()) => {
                let guard = Self(path.to_owned());
                fs::write(
                    path.join("run_id"),
                    format!("target-prune-{}", std::process::id()),
                )?;
                Ok(Some(guard))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(error),
        }
    }
}
impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("run_id"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[derive(clap::Args, Debug)]
pub struct TargetPruneArgs {
    /// Require the descriptor-anchored helper protocol; old helpers fail closed.
    #[arg(long, value_enum)]
    pub protocol: PruneProtocol,
    #[arg(long)]
    pub dev_root: PathBuf,
    #[arg(long)]
    pub target_dir: PathBuf,
    #[arg(long, default_value_t = 2)]
    pub days: u64,
    #[arg(long)]
    pub apply: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum PruneProtocol {
    #[value(name = "fd-v1")]
    DirectoryDescriptors,
}

fn cutoff(days: u64) -> Result<i128, GcError> {
    if days == 0 || days > i32::MAX as u64 {
        return Err(GcError::Census(
            "artifact age must be 1..=2147483647 days".into(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| GcError::Census(e.to_string()))?;
    Ok(now.as_nanos() as i128 - i128::from(days) * 86_400 * 1_000_000_000)
}
fn identity(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.file_type() == b.file_type()
}
fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    identity(a, b)
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.len() == b.len()
        && a.nlink() == b.nlink()
        && a.blocks() == b.blocks()
}
fn allocated(total: u64, blocks: u64) -> Result<u64, GcError> {
    blocks
        .checked_mul(512)
        .and_then(|bytes| total.checked_add(bytes))
        .ok_or_else(|| GcError::Census("allocated byte accounting overflow".into()))
}
fn keepable(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR)
    )
}

struct Tree {
    file: File,
    metadata: Metadata,
    children: Vec<(OsString, Tree)>,
    bytes: u64,
}
impl Tree {
    fn capture(
        parent: &File,
        name: &OsStr,
        device: u64,
        cutoff: i128,
    ) -> Result<Option<Self>, GcError> {
        let file = match at::open(parent, name, false) {
            Ok(file) => file,
            Err(error) if keepable(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        let modified =
            i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
        if metadata.dev() != device
            || modified > cutoff
            || (!metadata.is_dir() && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Ok(None);
        }
        let mut bytes = allocated(0, metadata.blocks())?;
        let mut children = Vec::new();
        if metadata.is_dir() {
            for name in at::entries(&file)? {
                let Some(child) = Self::capture(&file, &name, device, cutoff)? else {
                    return Ok(None);
                };
                bytes = bytes
                    .checked_add(child.bytes)
                    .ok_or_else(|| GcError::Census("allocated byte accounting overflow".into()))?;
                children.push((name, child));
            }
        }
        if !unchanged(&metadata, &file.metadata()?) || !at::same(parent, name, &metadata)? {
            return Err(GcError::Census(
                "artifact changed during descriptor traversal".into(),
            ));
        }
        Ok(Some(Self {
            file,
            metadata,
            children,
            bytes,
        }))
    }
    fn register(&self, path: &Path, handles: &mut CensusHandles) {
        handles.insert(self.file.as_raw_fd(), path.to_owned());
        for (name, child) in &self.children {
            child.register(&path.join(name), handles);
        }
    }
    fn valid(&self, parent: &File, name: &OsStr) -> Result<bool, GcError> {
        if !at::same(parent, name, &self.metadata)?
            || !unchanged(&self.metadata, &self.file.metadata()?)
        {
            return Ok(false);
        }
        if self.metadata.is_dir() {
            if at::entries(&self.file)?
                != self
                    .children
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>()
            {
                return Ok(false);
            }
            for (name, child) in &self.children {
                if !child.valid(&self.file, name)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
    fn remove(&self, parent: &File, name: &OsStr) -> Result<(), GcError> {
        if !at::same(parent, name, &self.metadata)? {
            return Err(GcError::Census(
                "staged entry changed; preserved for recovery".into(),
            ));
        }
        if self.metadata.is_dir() {
            self.file
                .set_permissions(fs::Permissions::from_mode(self.metadata.mode() | 0o700))?;
        }
        for (name, child) in &self.children {
            child.remove(&self.file, name)?;
        }
        at::unlink(parent, name, self.metadata.is_dir())?;
        Ok(())
    }
}

// Require complete owned records AND every anchored object in the queried
// subtree. An empty census cannot conceal a path swapped during lsof's walk.
fn idle_fields(code: Option<i32>, stdout: &[u8], stderr: &[u8], handles: &CensusHandles) -> bool {
    if !matches!(code, Some(0 | 1)) || !stderr.is_empty() || stdout.is_empty() || handles.is_empty()
    {
        return false;
    }
    let mut processes = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut pid = None;
    let mut descriptor = None;
    let mut named = false;
    let Some(records) = stdout.strip_suffix(b"\n") else {
        return false;
    };
    for field in records.split(|b| *b == b'\n') {
        let Some((&tag, value)) = field.split_first() else {
            return false;
        };
        match tag {
            b'p' => {
                if pid.is_some() && (descriptor.is_none() || !named) {
                    return false;
                }
                let Ok(value) = std::str::from_utf8(value) else {
                    return false;
                };
                let Ok(process) = value.parse::<u32>() else {
                    return false;
                };
                if process != std::process::id()
                    || value != process.to_string()
                    || !processes.insert(process)
                {
                    return false;
                }
                pid = Some(process);
                descriptor = None;
                named = false;
            }
            b'f' => {
                if pid.is_none() || (descriptor.is_some() && !named) {
                    return false;
                }
                let Ok(value) = std::str::from_utf8(value) else {
                    return false;
                };
                let Ok(fd) = value.parse::<i32>() else {
                    return false;
                };
                if value != fd.to_string() || !handles.contains_key(&fd) || !seen.insert(fd) {
                    return false;
                }
                descriptor = Some(fd);
                named = false;
            }
            b'n' => {
                let Some(fd) = descriptor else {
                    return false;
                };
                if named
                    || handles
                        .get(&fd)
                        .is_none_or(|path| path.as_os_str().as_bytes() != value)
                {
                    return false;
                }
                named = true;
            }
            _ => return false,
        }
    }
    named && seen.len() == handles.len()
}
fn census_output(path: &Path, directory: bool) -> Option<std::process::Output> {
    let lsof = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("lsof"))
            .find(|file| {
                fs::metadata(file)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
            .and_then(|file| fs::canonicalize(file).ok())
    })?;
    // SAFETY: geteuid has no preconditions and observes the invoking user.
    let mut command = if unsafe { libc::geteuid() } == 0 {
        Command::new(lsof)
    } else {
        let mut command = Command::new("sudo");
        command.args(["-n", "-u", "root"]).arg(lsof);
        command
    };
    command.args(["-F", "pfn"]);
    if directory {
        command.arg("+D");
    }
    command.arg(path).output().ok()
}
fn census(path: &Path, directory: bool, handles: &CensusHandles) -> bool {
    census_output(path, directory)
        .is_some_and(|out| idle_fields(out.status.code(), &out.stdout, &out.stderr, handles))
}

fn stage(root: &File) -> Result<(OsString, File), GcError> {
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let name = OsString::from(format!(".carrick-prune-{token}"));
    at::mkdir(root, &name)?;
    let directory = at::open(root, &name, true)?;
    Ok((name, directory))
}

fn prune_target(
    target: &Path,
    cutoff: i128,
    apply: bool,
    writer: &mut impl Write,
    before_delete: &mut impl FnMut(),
) -> Result<u64, GcError> {
    let source = match fs::symlink_metadata(target) {
        Ok(meta) if meta.is_dir() => meta,
        Ok(_) => {
            writeln!(
                writer,
                "keep target (symlink or non-directory) | {}",
                target.display()
            )?;
            return Ok(0);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let canonical = fs::canonicalize(target)?;
    let root = at::root(&canonical)?;
    let root_meta = root.metadata()?;
    if !identity(&source, &root_meta) {
        return Err(GcError::Census(
            "target changed during authentication".into(),
        ));
    }
    let mut handles = CensusHandles::from([(root.as_raw_fd(), canonical.clone())]);
    let mut profiles = Vec::new();
    for name in ["debug", "release"] {
        let directory = match at::open(&root, OsStr::new(name), true) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                at::mkdir(&root, OsStr::new(name))?;
                at::open(&root, OsStr::new(name), true)?
            }
            Err(error) if keepable(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        if directory.metadata()?.dev() != root_meta.dev() {
            return Err(GcError::Census("profile crosses target filesystem".into()));
        }
        let lock = at::lock(&directory)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                writeln!(
                    writer,
                    "keep target (Cargo lock is held) | {}",
                    canonical.display()
                )?;
                return Ok(0);
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let lock = OwnedFileLock::from_locked(lock);
        handles.insert(directory.as_raw_fd(), canonical.join(name));
        handles.insert(lock.as_raw_fd(), canonical.join(name).join(".cargo-lock"));
        profiles.push((name, directory, lock));
    }
    if !identity(&root_meta, &fs::symlink_metadata(&canonical)?) {
        return Err(GcError::Census(
            "target changed during lock acquisition".into(),
        ));
    }
    if !census(&canonical, true, &handles) {
        writeln!(
            writer,
            "keep target (in use or unknown visibility) | {}",
            canonical.display()
        )?;
        return Ok(0);
    }
    let mut total: u64 = 0;
    for (profile, directory, _lock) in &profiles {
        for kind in ["deps", "build", ".fingerprint"] {
            let parent = match at::open(directory, OsStr::new(kind), true) {
                Ok(parent) => parent,
                Err(error) if keepable(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let kind_path = canonical.join(profile).join(kind);
            for name in at::entries(&parent)? {
                let Some(tree) = Tree::capture(&parent, &name, root_meta.dev(), cutoff)? else {
                    continue;
                };
                let path = kind_path.join(&name);
                let mut candidate_handles = CensusHandles::new();
                tree.register(&path, &mut candidate_handles);
                if !census(&path, tree.metadata.is_dir(), &candidate_handles) {
                    continue;
                }
                if !tree.valid(&parent, &name)?
                    || !identity(&root_meta, &fs::symlink_metadata(&canonical)?)
                {
                    return Err(GcError::Census(
                        "target or artifact changed before pruning".into(),
                    ));
                }
                let next_total = total
                    .checked_add(tree.bytes)
                    .ok_or_else(|| GcError::Census("allocated byte accounting overflow".into()))?;
                if apply {
                    // The regression pauses here, AFTER the final path identity check.
                    // Everything below addresses retained directory descriptors only.
                    before_delete();
                    root.set_permissions(fs::Permissions::from_mode(root_meta.mode() | 0o700))?;
                    parent.set_permissions(fs::Permissions::from_mode(
                        parent.metadata()?.mode() | 0o700,
                    ))?;
                    let (stage_name, staged) = stage(&root)?;
                    at::rename(&parent, &name, &staged, OsStr::new("artifact"))?;
                    if !tree.valid(&staged, OsStr::new("artifact"))? {
                        return Err(GcError::Census(format!(
                            "changed candidate preserved in {}/{}",
                            canonical.display(),
                            stage_name.to_string_lossy()
                        )));
                    }
                    tree.remove(&staged, OsStr::new("artifact"))?;
                    at::unlink(&root, &stage_name, true)?;
                }
                total = next_total;
                writeln!(
                    writer,
                    "{} {} allocated bytes | {}",
                    if apply { "pruned" } else { "eligible" },
                    tree.bytes,
                    path.display()
                )?;
            }
        }
    }
    Ok(total)
}
fn prune_targets(
    targets: &[PathBuf],
    days: u64,
    apply: bool,
    writer: &mut impl Write,
) -> Result<(), GcError> {
    let cutoff = cutoff(days)?;
    let mut total: u64 = 0;
    for target in targets {
        total = total
            .checked_add(prune_target(target, cutoff, apply, writer, &mut || {})?)
            .ok_or_else(|| GcError::Census("allocated byte accounting overflow".into()))?;
    }
    writeln!(
        writer,
        "target pruning: {} {} allocated bytes (age >= {days} days)",
        if apply { "freed" } else { "would free" },
        total
    )?;
    Ok(())
}
fn guarded(
    dev: &Path,
    targets: &[PathBuf],
    days: u64,
    apply: bool,
    writer: &mut impl Write,
) -> Result<(), GcError> {
    cutoff(days)?;
    let Some(_checkout) = CheckoutGuard::claim(&dev.join("gate-worktree.lock"))? else {
        writeln!(writer, "target pruning skipped: gate checkout lock is held")?;
        return Ok(());
    };
    let path = std::env::var_os("CARRICK_HOST_LEASE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_PATH));
    let Some(_lease) = HostLease::try_exclusive(&path)? else {
        writeln!(writer, "target pruning skipped: host lease is held")?;
        return Ok(());
    };
    prune_targets(targets, days, apply, writer)
}
pub(crate) fn run_helper(args: TargetPruneArgs, writer: &mut impl Write) -> Result<(), GcError> {
    guarded(
        &args.dev_root,
        &[args.target_dir],
        args.days,
        args.apply,
        writer,
    )
}
pub(crate) fn run(
    root: &Path,
    args: WorktreeGcArgs,
    writer: &mut impl Write,
) -> Result<(), GcError> {
    let dev = root
        .parent()
        .ok_or_else(|| GcError::Census("checkout has no parent directory".into()))?;
    let targets = if let Some(target) = args.target_dir {
        vec![target]
    } else {
        let census = crate::command::run_checked(
            "git",
            ["worktree", "list", "--porcelain", "-z"],
            Some(root),
        )?;
        census
            .stdout
            .split('\0')
            .filter_map(|field| field.strip_prefix("worktree "))
            .map(|path| Path::new(path).join("target"))
            .collect()
    };
    guarded(dev, &targets, args.days, args.apply, writer)
}
pub(crate) fn remote_script(remote_root: &str) -> Result<String, GcError> {
    let env = shell_quote(&format!("{remote_root}/env.sh"));
    let helper = shell_quote(&format!("{remote_root}/build-tools/carrick-xtask"));
    let dev = shell_quote(remote_root);
    let target = shell_quote(&format!("{remote_root}/gate-worktree/target"));
    Ok(format!(
        "set -eu\nif [ -f {env} ]; then . {env}; fi\npruner=${{CARRICK_TARGET_PRUNER:-{helper}}}\nexec \"$pruner\" target-prune --protocol fd-v1 --dev-root {dev} --target-dir {target} --days 2 --apply\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Child, Stdio};
    use std::time::Duration;

    fn old_artifact(root: &Path) -> (PathBuf, PathBuf) {
        let target = root.join("target");
        let artifact = target.join("debug/deps/old-output");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::write(&artifact, "original aged artifact").unwrap();
        age(&artifact);
        (target, artifact)
    }
    fn age(path: &Path) {
        File::open(path)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_secs(4 * 86_400)),
            )
            .unwrap();
    }
    fn spawn(target: &Path, apply: bool, socket: Option<&Path>) -> Child {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--ignored",
                "--exact",
                "target_prune::tests::prune_child_fixture",
                "--nocapture",
            ])
            .env("PRUNE_FIXTURE_TARGET", target)
            .env("PRUNE_FIXTURE_APPLY", if apply { "1" } else { "0" })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(socket) = socket {
            child.env("PRUNE_FIXTURE_SOCKET", socket);
        }
        child.spawn().unwrap()
    }
    #[test]
    #[ignore = "isolated native pruning process invoked by concurrent fixtures"]
    fn prune_child_fixture() {
        let target = PathBuf::from(std::env::var_os("PRUNE_FIXTURE_TARGET").unwrap());
        let apply = std::env::var("PRUNE_FIXTURE_APPLY").unwrap() == "1";
        let case = std::env::var("PRUNE_FIXTURE_CASE").unwrap_or_default();
        if case == "host" {
            let dev = target.parent().unwrap();
            let path = dev.join("host.lock");
            for mode in [
                crate::host_lease::HostLeaseMode::Carrick,
                crate::host_lease::HostLeaseMode::Gate,
            ] {
                let _lease = HostLease::acquire_path(&path, mode).unwrap();
                let mut output = Vec::new();
                guarded(dev, std::slice::from_ref(&target), 2, true, &mut output).unwrap();
                assert!(
                    String::from_utf8(output)
                        .unwrap()
                        .contains("host lease is held")
                );
                assert!(!dev.join("gate-worktree.lock").exists());
            }
            return;
        }
        if case == "fields" {
            let root = at::root(&target).unwrap();
            let lock = at::lock(&root).unwrap();
            let handles = CensusHandles::from([
                (root.as_raw_fd(), target.clone()),
                (lock.as_raw_fd(), target.join(".cargo-lock")),
            ]);
            let output = census_output(&target, true).unwrap();
            assert!(
                idle_fields(
                    output.status.code(),
                    &output.stdout,
                    &output.stderr,
                    &handles
                ),
                "{output:?}"
            );
            let real = String::from_utf8(output.stdout).unwrap();
            let missing_f = real
                .lines()
                .filter(|line| !line.starts_with('f'))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let missing_n = real
                .lines()
                .filter(|line| !line.starts_with('n'))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            for malformed in [
                missing_f,
                missing_n,
                format!("{real}fcwd\nn{}\n", target.display()),
                format!("{real}p{}\nf0\nn{}\n", std::process::id(), target.display()),
                format!("{real}n{}\n", target.display()),
                format!("{real}xunknown\n"),
            ] {
                assert!(
                    !idle_fields(Some(0), malformed.as_bytes(), b"", &handles),
                    "{malformed}"
                );
            }
            let _unrelated = File::open(target.join("debug/deps/old-output")).unwrap();
            let unrelated = census_output(&target, true).unwrap();
            assert!(
                !idle_fields(
                    unrelated.status.code(),
                    &unrelated.stdout,
                    &unrelated.stderr,
                    &handles
                ),
                "{unrelated:?}"
            );
            return;
        }
        let _own_artifact =
            (case == "own-open").then(|| File::open(target.join("debug/deps/old-output")).unwrap());
        let socket = std::env::var_os("PRUNE_FIXTURE_SOCKET");
        let mut hook = || {
            if let Some(socket) = &socket {
                let mut peer = UnixStream::connect(socket).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                peer.write_all(b"ready\n").unwrap();
                let mut reply = [0];
                peer.read_exact(&mut reply).unwrap();
            }
        };
        let mut output = Vec::new();
        let result = prune_target(&target, cutoff(2).unwrap(), apply, &mut output, &mut hook);
        std::io::stdout().write_all(&output).unwrap();
        result.unwrap();
    }
    fn prune(target: &Path, apply: bool) -> String {
        let output = spawn(target, apply, None).wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }
    fn barrier(listener: UnixListener) -> UnixStream {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(listener.accept()).unwrap());
        let (mut peer, _) = receiver
            .recv_timeout(Duration::from_secs(15))
            .expect("pruner must reach final pre-unlink boundary")
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut ready = [0; 6];
        peer.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready\n");
        peer
    }
    #[test]
    fn replacement_after_final_check_is_never_deleted() {
        for link in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let (target, _) = old_artifact(&root);
            let socket = root.join("before-delete.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let child = spawn(&target, true, Some(&socket));
            let mut peer = barrier(listener);
            let retired = root.join("target.old");
            fs::rename(&target, &retired).unwrap();
            let replacement = if link {
                root.join("replacement")
            } else {
                target.clone()
            };
            fs::create_dir_all(replacement.join("debug/deps")).unwrap();
            let untouched = replacement.join("debug/deps/old-output");
            fs::write(&untouched, "never aged or censused replacement").unwrap();
            if link {
                symlink(&replacement, &target).unwrap();
            }
            peer.write_all(b"delete\n").unwrap();
            drop(peer);
            let output = child.wait_with_output().unwrap();
            assert!(
                untouched.exists(),
                "replacement artifact deleted after final identity check (symlink={link}): {output:?}"
            );
            assert_eq!(
                fs::read_to_string(&untouched).unwrap(),
                "never aged or censused replacement"
            );
            assert!(output.status.success(), "{output:?}");
            assert!(
                !retired.join("debug/deps/old-output").exists(),
                "held directory should address the original artifact"
            );
            assert!(
                !replacement.join("debug/.cargo-lock").exists(),
                "must not acquire locks in replacement"
            );
        }
    }
    #[test]
    fn candidate_replaced_at_final_boundary_is_preserved_in_staging() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let (target, artifact) = old_artifact(&root);
        let socket = root.join("before-delete.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let child = spawn(&target, true, Some(&socket));
        let mut peer = barrier(listener);
        let original = root.join("original-output");
        fs::rename(&artifact, &original).unwrap();
        fs::write(&artifact, "new unchecked candidate").unwrap();
        peer.write_all(b"delete\n").unwrap();
        drop(peer);
        let output = child.wait_with_output().unwrap();
        assert!(
            !output.status.success(),
            "changed candidate must stop pruning"
        );
        let recovery = fs::read_dir(&target)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().as_bytes().starts_with(b".carrick-prune-"))
            .unwrap();
        assert_eq!(
            fs::read_to_string(recovery.path().join("artifact")).unwrap(),
            "new unchecked candidate"
        );
        assert!(original.exists());
    }
    #[test]
    fn real_lsof_descriptor_protocol_prunes_idle_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let (target, artifact) = old_artifact(&root);
        let output = prune(&target, true);
        assert!(
            !artifact.exists(),
            "real lsof must permit idle pruning: {output}"
        );
        assert!(output.contains("pruned"));
    }
    #[test]
    fn real_lsof_canonical_names_prune_symlinked_ancestor_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let checkout = root.join("checkout");
        fs::create_dir(&checkout).unwrap();
        let (_, artifact) = old_artifact(&checkout);
        let alias = root.join("worktree-alias");
        symlink(&checkout, &alias).unwrap();
        let output = prune(&alias.join("target"), true);
        assert!(
            !artifact.exists(),
            "real alias census must permit pruning: {output}"
        );
    }
    #[test]
    fn real_lsof_unrelated_open_artifact_keeps_target() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let _opened = File::open(&artifact).unwrap();
        let output = prune(&target, true);
        assert!(
            artifact.exists() && output.contains("in use or unknown visibility"),
            "{output}"
        );
    }
    #[test]
    fn native_cargo_lock_preserves_old_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let lock = File::create(target.join("debug/.cargo-lock")).unwrap();
        lock.lock().unwrap();
        let output = prune(&target, true);
        assert!(
            artifact.exists() && output.contains("Cargo lock is held"),
            "{output}"
        );
    }
    #[test]
    fn concurrent_cargo_admission_is_excluded_through_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let (target, artifact) = old_artifact(&root);
        let socket = root.join("before-delete.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let child = spawn(&target, true, Some(&socket));
        let mut peer = barrier(listener);
        let lock = File::options()
            .read(true)
            .write(true)
            .open(target.join("debug/.cargo-lock"))
            .unwrap();
        assert!(matches!(
            lock.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        peer.write_all(b"delete\n").unwrap();
        drop(peer);
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success() && !artifact.exists(), "{output:?}");
        lock.try_lock().unwrap();
    }
    #[test]
    fn killed_native_pruner_has_no_surviving_deletion_child() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let (target, artifact) = old_artifact(&root);
        let socket = root.join("before-delete.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut child = spawn(&target, true, Some(&socket));
        let _peer = barrier(listener);
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        child.wait().unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .open(target.join("debug/.cargo-lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success() && artifact.exists(), "{output:?}");
    }
    #[test]
    fn dry_run_and_age_policy_keep_recent_future_symlinks_hardlinks_and_binary() {
        let temp = tempfile::tempdir().unwrap();
        let (target, old) = old_artifact(temp.path());
        let deps = old.parent().unwrap();
        let recent = deps.join("recent");
        fs::write(&recent, "recent").unwrap();
        let future = deps.join("future");
        fs::write(&future, "future").unwrap();
        File::open(&future)
            .unwrap()
            .set_times(
                fs::FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(86_400)),
            )
            .unwrap();
        let hard = deps.join("hard");
        fs::write(&hard, "hard").unwrap();
        age(&hard);
        fs::hard_link(&hard, temp.path().join("hard-alias")).unwrap();
        let link = deps.join("symlink");
        symlink(&old, &link).unwrap();
        let directory = deps.join("tree");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("recent"), "recent").unwrap();
        age(&directory);
        let binary = target.join("debug/carrick");
        fs::write(&binary, "preserve binary").unwrap();
        age(&binary);
        let output = prune(&target, false);
        assert!(old.exists() && output.contains("eligible"), "{output}");
        let output = prune(&target, true);
        assert!(!old.exists(), "{output}");
        for preserved in [recent, future, hard, link, directory, binary] {
            assert!(fs::symlink_metadata(preserved).is_ok());
        }
        assert!(
            target.join("debug/.cargo-lock").exists()
                && target.join("release/.cargo-lock").exists()
        );
    }
    #[test]
    fn nested_descriptor_tree_is_removed_without_following_replaced_parent() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let target = root.join("target");
        let directory = target.join("debug/build/old-build");
        fs::create_dir_all(directory.join("nested")).unwrap();
        fs::write(directory.join("nested/output"), "old nested output").unwrap();
        for path in [
            directory.join("nested/output"),
            directory.join("nested"),
            directory.clone(),
        ] {
            age(&path);
        }
        let socket = root.join("before-delete.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let child = spawn(&target, true, Some(&socket));
        let mut peer = barrier(listener);
        let retired = root.join("build.old");
        fs::rename(target.join("debug/build"), &retired).unwrap();
        fs::create_dir_all(target.join("debug/build/old-build/nested")).unwrap();
        let untouched = target.join("debug/build/old-build/nested/output");
        fs::write(&untouched, "new").unwrap();
        peer.write_all(b"delete\n").unwrap();
        drop(peer);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success() && untouched.exists() && !retired.join("old-build").exists(),
            "{output:?}"
        );
    }
    #[test]
    fn strict_fields_reject_unrelated_malformed_duplicates_cwd_and_missing_owned_objects() {
        let pid = std::process::id();
        let handles = CensusHandles::from([
            (3, PathBuf::from("/target")),
            (4, PathBuf::from("/target/.cargo-lock")),
        ]);
        let valid = format!("p{pid}\nf3\nn/target\nf4\nn/target/.cargo-lock\n");
        assert!(idle_fields(Some(0), valid.as_bytes(), b"", &handles));
        assert!(idle_fields(Some(1), valid.as_bytes(), b"", &handles));
        for invalid in [
            valid.replace("f3\n", ""),
            valid.replace("n/target\n", ""),
            valid.replace("/target/.cargo-lock", "/unrelated"),
            format!("{valid}fcwd\nn/target\n"),
            format!("{valid}f4\nn/target/.cargo-lock\n"),
            format!("{valid}p{pid}\nf9\nn/target\n"),
            format!("{valid}xunknown\n"),
            format!("p{pid}\nf3\nn/target\n"),
            valid.trim_end().into(),
        ] {
            assert!(
                !idle_fields(Some(0), invalid.as_bytes(), b"", &handles),
                "{invalid}"
            );
        }
        assert!(!idle_fields(Some(1), b"", b"", &handles));
        assert!(!idle_fields(
            Some(0),
            valid.as_bytes(),
            b"warning",
            &handles
        ));
        assert!(!idle_fields(Some(2), valid.as_bytes(), b"", &handles));
    }
    #[test]
    fn invalid_ages_and_accounting_overflow_fail_closed() {
        assert!(cutoff(0).is_err() && cutoff(u64::MAX).is_err());
        assert!(allocated(u64::MAX, 1).is_err() && allocated(0, u64::MAX).is_err());
        assert_eq!(allocated(100, 8).unwrap(), 4196);
    }
    #[test]
    fn descriptor_staging_never_overwrites_an_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("source"), "aged source").unwrap();
        fs::write(temp.path().join("destination"), "unchecked destination").unwrap();
        let root = at::root(temp.path()).unwrap();
        assert!(
            at::rename(
                &root,
                OsStr::new("source"),
                &root,
                OsStr::new("destination")
            )
            .is_err()
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("source")).unwrap(),
            "aged source"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("destination")).unwrap(),
            "unchecked destination"
        );
    }
    #[test]
    fn held_checkout_guard_skips_before_host_admission() {
        let temp = tempfile::tempdir().unwrap();
        let _guard = CheckoutGuard::claim(&temp.path().join("gate-worktree.lock"))
            .unwrap()
            .unwrap();
        let mut output = Vec::new();
        guarded(temp.path(), &[], 2, true, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("checkout lock is held")
        );
    }
    #[test]
    fn missing_remote_helper_fails_closed_without_legacy_removal() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let output = Command::new("/bin/sh")
            .args(["-c", &remote_script(temp.path().to_str().unwrap()).unwrap()])
            .env("CARRICK_TARGET_PRUNER", "/nonexistent/carrick-fd-pruner")
            .output()
            .unwrap();
        assert!(!output.status.success() && artifact.exists() && target.exists());
    }
    #[test]
    fn remote_wrapper_requires_native_protocol_and_no_cargo_or_rm_fallback() {
        let script = remote_script("/dev/with spaces").unwrap();
        assert!(
            script.contains("--protocol fd-v1") && script.contains("build-tools/carrick-xtask")
        );
        assert!(
            !script.contains("cargo run")
                && !script.contains("rm -rf")
                && !script.contains("/usr/bin/perl")
        );
    }
    fn fixture_case(target: &Path, case: &str) -> std::process::Output {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "target_prune::tests::prune_child_fixture",
                "--nocapture",
            ])
            .env("PRUNE_FIXTURE_TARGET", target)
            .env("PRUNE_FIXTURE_APPLY", "1")
            .env("PRUNE_FIXTURE_CASE", case)
            .env(
                "CARRICK_HOST_LEASE_PATH",
                target.parent().unwrap().join("host.lock"),
            )
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        output
    }
    #[test]
    fn either_shared_or_exclusive_host_lease_prevents_pruning() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        fixture_case(&target, "host");
        assert!(artifact.exists());
    }
    #[test]
    fn real_lsof_records_reject_malformed_boundaries_and_unrelated_own_files() {
        let temp = tempfile::tempdir().unwrap();
        let (target, _) = old_artifact(temp.path());
        fixture_case(&fs::canonicalize(target).unwrap(), "fields");
    }
    #[test]
    fn unrelated_own_descriptor_remains_visible() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let output = fixture_case(&target, "own-open");
        assert!(
            artifact.exists()
                && String::from_utf8_lossy(&output.stdout).contains("in use or unknown visibility")
        );
    }
    #[test]
    fn missing_lsof_keeps_artifacts_without_fake_census() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let mut child = Command::new(std::env::current_exe().unwrap());
        let output = child
            .args([
                "--ignored",
                "--exact",
                "target_prune::tests::prune_child_fixture",
                "--nocapture",
            ])
            .env("PRUNE_FIXTURE_TARGET", &target)
            .env("PRUNE_FIXTURE_APPLY", "1")
            .env("PATH", temp.path())
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && artifact.exists()
                && String::from_utf8_lossy(&output.stdout).contains("unknown visibility"),
            "{output:?}"
        );
    }
    #[test]
    fn real_cargo_build_and_pruning_share_the_native_lock() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        fs::write(temp.path().join("Cargo.toml"),"[package]\nname=\"native-lock-proof\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\n").unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(temp.path().join("build.rs"),r#"use std::io::{Read,Write}; fn main() { let mut s = std::os::unix::net::UnixStream::connect(std::env::var_os("BUILD_CENSUS_SOCKET").unwrap()).unwrap(); s.write_all(b"ready\n").unwrap(); let mut reply=[0]; s.read_exact(&mut reply).unwrap(); }"#).unwrap();
        let socket = temp.path().join("cargo.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let cargo = Command::new("cargo")
            .arg("build")
            .current_dir(temp.path())
            .env("CARGO_TARGET_DIR", &target)
            .env("RUSTC_WRAPPER", "")
            .env("BUILD_CENSUS_SOCKET", socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut peer = barrier(listener);
        let output = prune(&target, true);
        peer.write_all(b"c").unwrap();
        drop(peer);
        let built = cargo.wait_with_output().unwrap();
        assert!(
            built.status.success() && artifact.exists() && output.contains("Cargo lock is held"),
            "{built:?}; {output}"
        );
    }
}
