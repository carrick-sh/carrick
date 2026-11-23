//! The program `execve` would load for an argv, inside a rootfs directory:
//! the soft single-process runner's command lookup (#1236, #1906).
//!
//! [`run_single_process`](crate::run_single_process) loads one ELF; a parity
//! row names a command (`pip --version`, `go version`). [`resolve_command`]
//! finds it the way `execve(2)` and a shell's `PATH` search do, inside the
//! rootfs: every path walks through [`walk_rootfs`], with the rootfs as the
//! process root (symlinks resolve against it, never the host's root, and `..`
//! stops at it), the execute bit is checked on the command and on its
//! interpreter (`EACCES`), and one `#!` interpreter line is honoured
//! (`#!interpreter [one argument]`, as `execve(2)` documents). A failure
//! carries the status a shell exits with for it
//! ([`CommandError::exit_status`]). `carrick debug soft-run` and the soft-CPU
//! row witnesses (and their syscall fixture's path walk) share it.

use std::{
    collections::VecDeque,
    ffi::OsString,
    fmt, io,
    path::{Component, Path, PathBuf},
};

use carrick_abi::{
    LINUX_EACCES, LINUX_ELOOP, LINUX_ENOENT, LINUX_ENOEXEC, LINUX_ENOTDIR, LinuxErrno,
};

/// A shell's `PATH` when the environment names none.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Symlinks one walk may follow before it is a loop (Linux's `ELOOP` bound).
const MAX_SYMLINK_HOPS: usize = 40;

/// The program `execve` would load for an argv, inside a rootfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    /// The ELF's guest path with every symlink resolved.
    pub executable: String,
    /// The guest argv: the caller's, or an interpreter's in front of it.
    pub argv: Vec<String>,
}

impl ResolvedCommand {
    /// The host path of [`Self::executable`] under `root`.
    pub fn host_executable(&self, root: &Path) -> PathBuf {
        host_path(root, &self.executable)
    }
}

/// Why a command cannot run inside the rootfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandErrorKind {
    /// No such command, or no such file on its path (`ENOENT`).
    NotFound,
    /// The command was found, but `execve` would fail with this errno:
    /// `EACCES` (no execute bit, or not a regular file), `ENOEXEC` (neither
    /// an ELF nor a `#!` script), `ENOTDIR` or `ELOOP` on its path, or any
    /// error on its interpreter.
    CannotExecute(LinuxErrno),
    /// Linux would run it, but this lookup does not: a `#!` interpreter that
    /// is itself a script, or a path that is not UTF-8.
    Unsupported,
}

/// A command lookup that failed, with what a shell reports for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub kind: CommandErrorKind,
    pub message: String,
}

impl CommandError {
    /// The status a shell exits with: 127 when the command is not found, 126
    /// when it is found but cannot be executed, and 125 (a tool error, as
    /// `carrick run` uses it) when this lookup cannot run it.
    pub fn exit_status(&self) -> i32 {
        match self.kind {
            CommandErrorKind::NotFound => 127,
            CommandErrorKind::CannotExecute(_) => 126,
            CommandErrorKind::Unsupported => 125,
        }
    }

    fn new(kind: CommandErrorKind, message: String) -> Self {
        Self { kind, message }
    }

    /// `subject` failed with a host I/O error (a Linux host's errno is the
    /// Linux errno; soft runs need a Linux host).
    fn io(subject: &str, error: &io::Error) -> Self {
        let kind = match error.raw_os_error() {
            Some(errno) if errno == LINUX_ENOENT.get() => CommandErrorKind::NotFound,
            Some(errno) if (1..=4095).contains(&errno) => {
                CommandErrorKind::CannotExecute(LinuxErrno::new(errno))
            }
            _ => CommandErrorKind::Unsupported,
        };
        Self::new(kind, format!("{subject}: {error}"))
    }

    /// The same failure on a file the command needs once it was found (its
    /// interpreter): a missing one is a command that cannot be executed.
    fn after_found(self) -> Self {
        match self.kind {
            CommandErrorKind::NotFound => Self {
                kind: CommandErrorKind::CannotExecute(LINUX_ENOENT),
                ..self
            },
            _ => self,
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

fn errno_error(errno: LinuxErrno) -> io::Error {
    io::Error::from_raw_os_error(errno.get())
}

/// Walk `path` inside the rootfs at `root`, from `base` (an already resolved
/// path relative to `root`; empty for `/`), the way Linux path resolution
/// does with `root` as the process root: a symlink resolves inside `root` (an
/// absolute target restarts at `root`), `..` never climbs above `root`, and a
/// non-directory before the last component is `ENOTDIR`. A symlink in the
/// last component is followed only when `follow` is set (`O_NOFOLLOW` and
/// `AT_SYMLINK_NOFOLLOW` clear it). Returns the resolved path relative to
/// `root`. Errors carry a Linux errno as their `raw_os_error`: `ELOOP` past
/// 40 symlinks, `ENOTDIR`, or the host's (a Linux host's errnos are Linux's).
pub fn walk_rootfs(root: &Path, base: &Path, path: &Path, follow: bool) -> io::Result<PathBuf> {
    let mut pending: VecDeque<OsString> = path
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    let mut resolved = base.to_owned();
    let mut links = 0usize;
    while let Some(part) = pending.pop_front() {
        match Path::new(&part).components().next() {
            Some(Component::RootDir) => resolved.clear(),
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            Some(Component::CurDir) | None => {}
            Some(Component::Normal(_)) => {
                resolved.push(&part);
                let candidate = root.join(&resolved);
                let meta = std::fs::symlink_metadata(&candidate)?;
                if meta.is_symlink() && (follow || !pending.is_empty()) {
                    links += 1;
                    if links > MAX_SYMLINK_HOPS {
                        return Err(errno_error(LINUX_ELOOP));
                    }
                    let target = std::fs::read_link(&candidate)?;
                    resolved.pop();
                    for component in target.components().rev() {
                        pending.push_front(component.as_os_str().to_owned());
                    }
                } else if !pending.is_empty() && !meta.is_dir() {
                    return Err(errno_error(LINUX_ENOTDIR));
                }
            }
            Some(Component::Prefix(_)) => unreachable!("Unix paths have no prefix"),
        }
    }
    Ok(resolved)
}

/// Resolve `guest` (absolute, or relative to `/`, the guest's working
/// directory) inside `root`, following every symlink ([`walk_rootfs`]).
/// Returns the resolved guest path.
pub fn resolve_guest_path(root: &Path, guest: &str) -> Result<String, CommandError> {
    let resolved = walk_rootfs(root, Path::new(""), Path::new(guest), true)
        .map_err(|error| CommandError::io(guest, &error))?;
    let resolved = resolved.to_str().ok_or_else(|| {
        CommandError::new(
            CommandErrorKind::Unsupported,
            format!("{guest}: resolves to a path that is not UTF-8"),
        )
    })?;
    Ok(format!("/{resolved}"))
}

/// The host path of a resolved guest path.
fn host_path(root: &Path, resolved: &str) -> PathBuf {
    root.join(resolved.trim_start_matches('/'))
}

/// `execve(2)`'s permission check on a resolved file: a regular file with an
/// execute bit, else `EACCES` (Linux grants execute, even to root, only when
/// some execute bit is set).
fn check_executable(root: &Path, subject: &str, resolved: &str) -> Result<(), CommandError> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(host_path(root, resolved))
        .map_err(|error| CommandError::io(subject, &error))?;
    let why = if meta.is_dir() {
        "is a directory"
    } else if !meta.is_file() {
        "is not a regular file"
    } else if meta.permissions().mode() & 0o111 == 0 {
        "has no execute bit"
    } else {
        return Ok(());
    };
    Err(CommandError::new(
        CommandErrorKind::CannotExecute(LINUX_EACCES),
        format!("{subject} ({resolved}) {why}: permission denied (EACCES)"),
    ))
}

/// Find `argv[0]` the way a shell does: a name with a `/` is a path (relative
/// to `/`, the guest's working directory); a bare name is searched in `path`,
/// for the first executable regular file. A name found only without the
/// execute bit is `EACCES`, as a shell reports it. Returns the guest path as
/// found, before symlinks resolve.
pub fn find_command(root: &Path, name: &str, path: &str) -> Result<String, CommandError> {
    if name.is_empty() {
        return Err(CommandError::new(
            CommandErrorKind::NotFound,
            "empty command".to_owned(),
        ));
    }
    if name.contains('/') {
        return Ok(if name.starts_with('/') {
            name.to_owned()
        } else {
            format!("/{name}")
        });
    }
    let mut denied = None;
    for dir in path.split(':').filter(|dir| dir.starts_with('/')) {
        let candidate = format!("{}/{name}", dir.trim_end_matches('/'));
        let Ok(resolved) = resolve_guest_path(root, &candidate) else {
            continue;
        };
        if host_path(root, &resolved).is_dir() {
            continue;
        }
        match check_executable(root, &candidate, &resolved) {
            Ok(()) => return Ok(candidate),
            Err(error) => {
                denied.get_or_insert(error);
            }
        }
    }
    Err(denied.unwrap_or_else(|| {
        CommandError::new(
            CommandErrorKind::NotFound,
            format!("{name}: not found in the rootfs PATH {path}"),
        )
    }))
}

/// Resolve the command for `argv` inside `root`: the PATH search, symlinks,
/// the execute bit, and one `#!` line (`#!interpreter [one argument]`, as
/// Linux reads it).
pub fn resolve_command(
    root: &Path,
    argv: &[String],
    path: &str,
) -> Result<ResolvedCommand, CommandError> {
    let name = argv.first().ok_or_else(|| {
        CommandError::new(
            CommandErrorKind::NotFound,
            "an empty argv names no command".to_owned(),
        )
    })?;
    let found = find_command(root, name, path)?;
    let executable = resolve_guest_path(root, &found)?;
    check_executable(root, &found, &executable)?;
    let head = read_head(root, &found, &executable)?;
    if let Some(line) = head.strip_prefix(b"#!") {
        let line = line.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let line = std::str::from_utf8(line)
            .map_err(|_| {
                CommandError::new(
                    CommandErrorKind::Unsupported,
                    format!("{found}: #! line is not UTF-8"),
                )
            })?
            .trim();
        let (interpreter, argument) = match line.split_once([' ', '\t']) {
            Some((interpreter, argument)) => (interpreter, Some(argument.trim())),
            None => (line, None),
        };
        if interpreter.is_empty() {
            return Err(CommandError::new(
                CommandErrorKind::CannotExecute(LINUX_ENOEXEC),
                format!("{found}: #! names no interpreter (ENOEXEC)"),
            ));
        }
        let interpreter_path =
            resolve_guest_path(root, interpreter).map_err(CommandError::after_found)?;
        check_executable(root, interpreter, &interpreter_path)
            .map_err(CommandError::after_found)?;
        let interpreter_head = read_head(root, interpreter, &interpreter_path)?;
        if interpreter_head.starts_with(b"#!") {
            return Err(CommandError::new(
                CommandErrorKind::Unsupported,
                format!("{found}: #! interpreter {interpreter} is a script (one #! level only)"),
            ));
        }
        if !interpreter_head.starts_with(b"\x7fELF") {
            return Err(CommandError::new(
                CommandErrorKind::CannotExecute(LINUX_ENOEXEC),
                format!("{found}: #! interpreter {interpreter} is not an ELF (ENOEXEC)"),
            ));
        }
        let mut script_argv = vec![interpreter.to_owned()];
        script_argv.extend(argument.filter(|arg| !arg.is_empty()).map(str::to_owned));
        script_argv.push(found);
        script_argv.extend(argv[1..].iter().cloned());
        return Ok(ResolvedCommand {
            executable: interpreter_path,
            argv: script_argv,
        });
    }
    if !head.starts_with(b"\x7fELF") {
        return Err(CommandError::new(
            CommandErrorKind::CannotExecute(LINUX_ENOEXEC),
            format!("{found} ({executable}) is neither an ELF nor a #! script (ENOEXEC)"),
        ));
    }
    Ok(ResolvedCommand {
        executable,
        argv: argv.to_vec(),
    })
}

fn read_head(root: &Path, subject: &str, resolved: &str) -> Result<Vec<u8>, CommandError> {
    use std::io::Read as _;
    let mut head = Vec::with_capacity(256);
    std::fs::File::open(host_path(root, resolved))
        .and_then(|file| file.take(256).read_to_end(&mut head))
        .map_err(|error| CommandError::io(subject, &error).after_found())?;
    Ok(head)
}

/// The `PATH` of a `KEY=VALUE` environment, or [`DEFAULT_PATH`].
pub fn env_path(env: &[String]) -> &str {
    env.iter()
        .rev()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn rootfs() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in ["usr/bin", "usr/local/go/bin", "bin", "etc"] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        let elf = |path: &str| {
            let host = root.path().join(path);
            std::fs::write(&host, b"\x7fELF\x02\x01\x01").unwrap();
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        elf("usr/local/go/bin/go");
        elf("usr/bin/dash");
        // An absolute symlink must resolve inside the rootfs, never the host.
        symlink("/usr/local/go/bin/go", root.path().join("usr/bin/go")).unwrap();
        symlink("../usr/bin/dash", root.path().join("bin/sh")).unwrap();
        symlink("loop-b", root.path().join("etc/loop-a")).unwrap();
        symlink("loop-a", root.path().join("etc/loop-b")).unwrap();
        std::fs::write(root.path().join("etc/readme"), b"text").unwrap();
        let script = root.path().join("usr/bin/hello");
        std::fs::write(&script, b"#!/bin/sh -e\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        // An ELF without the execute bit, and a script whose interpreter is it.
        let noexec = root.path().join("usr/bin/noexec");
        std::fs::write(&noexec, b"\x7fELF\x02\x01\x01").unwrap();
        std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).unwrap();
        let badinterp = root.path().join("usr/bin/badinterp");
        std::fs::write(&badinterp, b"#!/usr/bin/noexec\n").unwrap();
        std::fs::set_permissions(&badinterp, std::fs::Permissions::from_mode(0o755)).unwrap();
        // An executable that is neither an ELF nor a script, and a script
        // whose interpreter is itself a script.
        for (path, body) in [
            ("usr/bin/text", b"plain text\n".as_slice()),
            ("usr/bin/nested", b"#!/usr/bin/hello\n"),
        ] {
            let host = root.path().join(path);
            std::fs::write(&host, body).unwrap();
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // A non-executable `go` ahead of the real one on a PATH.
        std::fs::write(root.path().join("etc/go"), b"\x7fELF\x02\x01\x01").unwrap();
        root
    }

    fn lookup_error(root: &Path, words: &[&str], path: &str) -> CommandError {
        resolve_command(root, &argv(words), path).unwrap_err()
    }

    #[test]
    fn a_path_or_an_interpreter_without_the_execute_bit_is_refused() {
        let root = rootfs();
        let denied = CommandErrorKind::CannotExecute(LINUX_EACCES);
        for words in [["/usr/bin/noexec"], ["usr/bin/noexec"], ["/usr/bin"]] {
            let error = lookup_error(root.path(), &words, DEFAULT_PATH);
            assert_eq!(error.kind, denied, "{words:?}: {error}");
        }
        let error = lookup_error(root.path(), &["badinterp"], "/usr/bin");
        assert_eq!(error.kind, denied, "{error}");
        assert!(error.message.contains("/usr/bin/noexec"), "{error}");
    }

    #[test]
    fn a_failed_lookup_exits_like_a_shell() {
        let root = rootfs();
        let status = |words: &[&str], path: &str| lookup_error(root.path(), words, path);
        // Not found: 127.
        for (words, path) in [
            (&["nope"][..], DEFAULT_PATH),
            (&["/usr/bin/missing"][..], DEFAULT_PATH),
            (&[""][..], DEFAULT_PATH),
        ] {
            let error = status(words, path);
            assert_eq!(error.kind, CommandErrorKind::NotFound, "{error}");
            assert_eq!(error.exit_status(), 127, "{error}");
        }
        // Found but not executable: 126, with execve's errno.
        for (words, path, errno) in [
            (&["/usr/bin/noexec"][..], DEFAULT_PATH, LINUX_EACCES),
            (&["readme"][..], "/etc", LINUX_EACCES),
            (&["/usr/bin/text"][..], DEFAULT_PATH, LINUX_ENOEXEC),
            (&["/etc/readme/x"][..], DEFAULT_PATH, LINUX_ENOTDIR),
            (&["/etc/loop-a"][..], DEFAULT_PATH, LINUX_ELOOP),
        ] {
            let error = status(words, path);
            assert_eq!(
                error.kind,
                CommandErrorKind::CannotExecute(errno),
                "{error}"
            );
            assert_eq!(error.exit_status(), 126, "{error}");
        }
        // A nested #! Linux would run but this lookup does not: a tool error.
        let error = status(&["nested"], "/usr/bin");
        assert_eq!(error.kind, CommandErrorKind::Unsupported, "{error}");
        assert_eq!(error.exit_status(), 125, "{error}");
        // A non-executable match is skipped when a later PATH entry has one.
        assert_eq!(
            resolve_command(root.path(), &argv(&["go"]), "/etc:/usr/local/go/bin")
                .unwrap()
                .executable,
            "/usr/local/go/bin/go"
        );
    }

    #[test]
    fn dot_dot_through_a_symlinked_directory_cannot_leave_the_rootfs() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        for dir in ["usr/local/go/bin", "usr/bin", "etc"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        // A host file beside the rootfs, which no guest path may reach.
        std::fs::write(outer.path().join("secret"), b"host").unwrap();
        std::fs::write(root.join("etc/readme"), b"text").unwrap();
        symlink("/usr/local/go/bin", root.join("usr/bin/godir")).unwrap();
        symlink("../../../../..", root.join("etc/up")).unwrap();
        // `..` after a symlinked directory is its target's parent ...
        assert_eq!(
            resolve_guest_path(&root, "/usr/bin/godir/..").unwrap(),
            "/usr/local/go"
        );
        // ... and every `..` stops at the rootfs root.
        assert_eq!(
            resolve_guest_path(&root, "/usr/bin/godir/../../../../../etc/readme").unwrap(),
            "/etc/readme"
        );
        assert_eq!(resolve_guest_path(&root, "/etc/up").unwrap(), "/");
        assert_eq!(
            resolve_guest_path(&root, "/etc/up/etc/readme").unwrap(),
            "/etc/readme"
        );
        assert!(resolve_guest_path(&root, "/etc/up/secret").is_err());
        assert!(resolve_guest_path(&root, "/usr/bin/godir/../../../../../secret").is_err());
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn symlinks_resolve_against_the_rootfs_root() {
        let root = rootfs();
        assert_eq!(
            resolve_guest_path(root.path(), "/usr/bin/go").unwrap(),
            "/usr/local/go/bin/go"
        );
        assert_eq!(
            resolve_guest_path(root.path(), "/bin/sh").unwrap(),
            "/usr/bin/dash"
        );
        assert_eq!(
            resolve_guest_path(root.path(), "/../../bin/./sh").unwrap(),
            "/usr/bin/dash"
        );
        let error = resolve_guest_path(root.path(), "/etc/loop-a").unwrap_err();
        assert_eq!(
            error.kind,
            CommandErrorKind::CannotExecute(LINUX_ELOOP),
            "{error}"
        );
        assert!(resolve_guest_path(root.path(), "/usr/bin/missing").is_err());
    }

    #[test]
    fn a_bare_name_is_searched_in_path_and_keeps_its_argv() {
        let root = rootfs();
        let command =
            resolve_command(root.path(), &argv(&["go", "version"]), DEFAULT_PATH).unwrap();
        assert_eq!(
            command,
            ResolvedCommand {
                executable: "/usr/local/go/bin/go".to_owned(),
                argv: argv(&["go", "version"]),
            }
        );
        assert_eq!(
            command.host_executable(root.path()),
            root.path().join("usr/local/go/bin/go")
        );
        // A PATH entry that holds a non-executable file of the name is skipped.
        assert!(resolve_command(root.path(), &argv(&["readme"]), "/etc").is_err());
        assert!(resolve_command(root.path(), &argv(&["nope"]), DEFAULT_PATH).is_err());
        assert_eq!(
            env_path(&argv(&["HOME=/root", "PATH=/usr/local/go/bin"])),
            "/usr/local/go/bin"
        );
        assert_eq!(env_path(&[]), DEFAULT_PATH);
    }

    #[test]
    fn a_script_runs_under_its_interpreter_with_one_argument() {
        let root = rootfs();
        let command =
            resolve_command(root.path(), &argv(&["hello", "a", "b"]), "/usr/bin").unwrap();
        assert_eq!(
            command,
            ResolvedCommand {
                executable: "/usr/bin/dash".to_owned(),
                argv: argv(&["/bin/sh", "-e", "/usr/bin/hello", "a", "b"]),
            }
        );
        // A path that is neither an ELF nor a script is refused.
        let error = lookup_error(root.path(), &["/usr/bin/text"], DEFAULT_PATH);
        assert!(error.message.contains("neither an ELF"), "{error}");
    }
}
