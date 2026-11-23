//! The program `execve` would load for an argv, inside a rootfs directory:
//! the soft single-process runner's command lookup (#1236, #1906).
//!
//! [`run_single_process`](crate::run_single_process) loads one ELF; a parity
//! row names a command (`pip --version`, `go version`). [`resolve_command`]
//! finds it the way `execve(2)` and a shell's `PATH` search do, inside the
//! rootfs: every symlink resolves against the rootfs root (never the host's),
//! and one `#!` interpreter line is honoured (`#!interpreter [one argument]`,
//! as `execve(2)` documents). `carrick debug soft-run` and the soft-CPU row
//! witnesses share it.

use std::path::{Path, PathBuf};

/// A shell's `PATH` when the environment names none.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Symlinks one lookup may follow before it is a loop (Linux's `ELOOP` bound).
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

/// Resolve `guest` (absolute, or relative to `/`) inside `root`, following
/// every symlink against `root`. Returns the resolved guest path.
pub fn resolve_guest_path(root: &Path, guest: &str) -> Result<String, String> {
    let mut pending: Vec<String> = guest.split('/').rev().map(str::to_owned).collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0usize;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        let mut host = root.to_path_buf();
        host.extend(&resolved);
        host.push(&part);
        let metadata = std::fs::symlink_metadata(&host).map_err(|error| {
            format!(
                "{guest}: /{} not in the rootfs: {error}",
                resolved_join(&resolved, &part)
            )
        })?;
        if metadata.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Err(format!(
                    "{guest}: more than {MAX_SYMLINK_HOPS} symlinks (ELOOP)"
                ));
            }
            let target = std::fs::read_link(&host)
                .map_err(|error| format!("read symlink {}: {error}", host.display()))?;
            let target = target
                .to_str()
                .ok_or_else(|| format!("{}: symlink target is not UTF-8", host.display()))?;
            if target.starts_with('/') {
                resolved.clear();
            }
            pending.extend(target.split('/').rev().map(str::to_owned));
        } else {
            resolved.push(part);
        }
    }
    Ok(format!("/{}", resolved.join("/")))
}

fn resolved_join(resolved: &[String], part: &str) -> String {
    let mut path = resolved.join("/");
    if !path.is_empty() {
        path.push('/');
    }
    path.push_str(part);
    path
}

/// The host path of a resolved guest path.
fn host_path(root: &Path, resolved: &str) -> PathBuf {
    root.join(resolved.trim_start_matches('/'))
}

/// Find `argv[0]` the way a shell does: a name with a `/` is a path (relative
/// to `/`, the guest's working directory); a bare name is searched in `path`.
/// Returns the guest path as found, before symlinks resolve.
pub fn find_command(root: &Path, name: &str, path: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("empty command".to_owned());
    }
    if name.contains('/') {
        return Ok(if name.starts_with('/') {
            name.to_owned()
        } else {
            format!("/{name}")
        });
    }
    for dir in path.split(':').filter(|dir| dir.starts_with('/')) {
        let candidate = format!("{}/{name}", dir.trim_end_matches('/'));
        let Ok(resolved) = resolve_guest_path(root, &candidate) else {
            continue;
        };
        if is_executable_file(&host_path(root, &resolved)) {
            return Ok(candidate);
        }
    }
    Err(format!("{name}: not found in the rootfs PATH {path}"))
}

fn is_executable_file(host: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(host)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Resolve the command for `argv` inside `root`: the PATH search, symlinks,
/// and one `#!` line (`#!interpreter [one argument]`, as Linux reads it).
pub fn resolve_command(
    root: &Path,
    argv: &[String],
    path: &str,
) -> Result<ResolvedCommand, String> {
    let name = argv
        .first()
        .ok_or_else(|| "an empty argv names no command".to_owned())?;
    let found = find_command(root, name, path)?;
    let executable = resolve_guest_path(root, &found)?;
    let head = read_head(&host_path(root, &executable))?;
    if let Some(line) = head.strip_prefix(b"#!") {
        let line = line.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let line = std::str::from_utf8(line)
            .map_err(|_| format!("{found}: #! line is not UTF-8"))?
            .trim();
        let (interpreter, argument) = match line.split_once([' ', '\t']) {
            Some((interpreter, argument)) => (interpreter, Some(argument.trim())),
            None => (line, None),
        };
        if !interpreter.starts_with('/') {
            return Err(format!(
                "{found}: #! interpreter {interpreter:?} is not an absolute path"
            ));
        }
        let interpreter_path = resolve_guest_path(root, interpreter)?;
        let interpreter_head = read_head(&host_path(root, &interpreter_path))?;
        if !interpreter_head.starts_with(b"\x7fELF") {
            return Err(format!(
                "{found}: #! interpreter {interpreter} is not an ELF (one #! level only)"
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
        return Err(format!(
            "{found} ({executable}) is neither an ELF nor a #! script"
        ));
    }
    Ok(ResolvedCommand {
        executable,
        argv: argv.to_vec(),
    })
}

fn read_head(host: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut head = Vec::with_capacity(256);
    std::fs::File::open(host)
        .map_err(|error| format!("open {}: {error}", host.display()))?
        .take(256)
        .read_to_end(&mut head)
        .map_err(|error| format!("read {}: {error}", host.display()))?;
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
        root
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
        assert!(error.contains("ELOOP"), "{error}");
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
        let error =
            resolve_command(root.path(), &argv(&["/etc/readme"]), DEFAULT_PATH).unwrap_err();
        assert!(error.contains("neither an ELF"), "{error}");
    }
}
