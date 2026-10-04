//! One portable, Rust-generated pruning body, shared by local and SSH execution.
use crate::host_lease::{DEFAULT_LOCK_PATH, HostLease};
use crate::remote_accept::shell_quote;
use crate::worktree_gc::{GcError, WorktreeGcArgs};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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

// lsof exit 1 with no output/warnings is the only evidence of idle. A regular
// file uses a file query, whereas +D includes recursive directory mappings.
const IDLE_CENSUS: &str = r#"
idle() {
    if [ -d "$1" ]; then set -- -F p +D "$1"; else set -- -F p "$1"; fi
    # The Perl parent owns only the target lock descriptors, never artifacts.
    if [ -n "${CARRICK_PRUNE_LOCK_PID:-}" ]; then set -- "$@" -a -p "^$CARRICK_PRUNE_LOCK_PID"; fi
    if [ "$uid" = 0 ]; then
        if "$lsof_bin" "$@" > "$state/use.out" 2> "$state/use.err"; then code=0; else code=$?; fi
    else
        if sudo -n -u root "$lsof_bin" "$@" > "$state/use.out" 2> "$state/use.err"; then code=0; else code=$?; fi
    fi
    [ "$code" = 1 ] && [ ! -s "$state/use.out" ] && [ ! -s "$state/use.err" ]
}
"#;

// find rounds mtime down to full days: +1 means at least two full days old.
// Checking every descendant also preserves new contents inside an old parent.
const AGE_QUERY: &str =
    r#"find "$entry" \( ! -mtime "$age" -o -type l -o \( -type f -links +1 \) \) -print"#;

const CANDIDATES: &str = r#"
for entry do
    if ! AGE_QUERY > "$state/age"; then exit 1; fi
    [ ! -s "$state/age" ] || continue
    if ! du -sk "$entry" > "$state/du"; then exit 1; fi
    allocated=$(awk '{printf "%.0f", $1 * 1024}' "$state/du") || exit 1
    case "$allocated" in ''|*[!0-9]*) printf 'target pruning: invalid byte accounting\n' >&2; exit 1;; esac
    if [ "$apply" = 1 ]; then
        idle "$entry" || continue
        # Recheck the descendant age proof after the census.
        if ! AGE_QUERY > "$state/age"; then exit 1; fi
        [ ! -s "$state/age" ] || continue
        printf '%s\n' "$allocated" >> "$state/bytes" || exit 1
        rm -rf -- "$entry" || exit 1
        action=pruned
    else
        printf '%s\n' "$allocated" >> "$state/bytes" || exit 1
        action=eligible
    fi
    printf '%s %s allocated bytes | %s\n' "$action" "$allocated" "$entry" || exit 1
done
"#;

// Cargo holds the profile's .cargo-lock while using artifacts. An exclusive
// lock excludes both older exclusive Cargo locks and newer shared Cargo locks.
// Keep the handles in this parent through the complete census/removal command.
const CARGO_TARGET_LOCKS: &str = r#"use Fcntl qw(:flock :DEFAULT);
use File::Path qw(make_path);
my $target = shift @ARGV;
my @locks;
for my $profile ('debug', 'release') {
    my $directory = "$target/$profile";
    next if -l $directory;
    make_path($directory);
    sysopen(my $lock, "$directory/.cargo-lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0666)
        or die "Cargo target lock open: $!\n";
    unless (flock($lock, LOCK_EX | LOCK_NB)) {
        print "keep target (Cargo lock is held) | $target\n";
        exit 0;
    }
    push @locks, $lock;
}
$ENV{CARRICK_PRUNE_LOCK_PID} = $$;
system(@ARGV);
die "target prune spawn: $!\n" if $? == -1;
exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);
"#;

fn pruning_body(targets: &[PathBuf], days: u64, apply: bool) -> Result<String, GcError> {
    let older_than = days
        .checked_sub(1)
        .filter(|_| days <= i32::MAX as u64)
        .ok_or_else(|| GcError::Census("artifact age must be 1..=2147483647 days".into()))?;
    let candidate = format!(
        "set -u\napply=$1; age=$2; state=$3; lsof_bin=$4; uid=$5; shift 5\n{IDLE_CENSUS}\n{}",
        CANDIDATES.replace("AGE_QUERY", AGE_QUERY)
    );
    let paths = targets
        .iter()
        .map(|path| {
            path.to_str()
                .map(shell_quote)
                .ok_or_else(|| GcError::Census("target path is not UTF-8".into()))
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let candidate = shell_quote(&candidate);
    let target_body = shell_quote(&format!(
        r#"set -u
target=$1; apply=$2; age=$3; state=$4; lsof_bin=$5; uid=$6
{IDLE_CENSUS}
if [ ! -x "$lsof_bin" ] || ! idle "$target"; then
    printf 'keep target (in use or unknown visibility) | %s\n' "$target"
    exit 0
fi
for profile in debug release; do
    [ ! -L "$target/$profile" ] || continue
    for kind in deps build .fingerprint; do
        directory="$target/$profile/$kind"
        [ -d "$directory" ] && [ ! -L "$directory" ] || continue
        find "$directory" -mindepth 1 -maxdepth 1 -exec /bin/sh -c {candidate} sh "$apply" "$age" "$state" "$lsof_bin" "$uid" {{}} + || exit 1
    done
done
"#
    ));
    let locks = shell_quote(CARGO_TARGET_LOCKS);
    let apply = u8::from(apply);
    Ok(format!(
        r#"set -u
apply={apply}
age=+{older_than}
for tool in find du awk mktemp rm id /bin/sh /usr/bin/perl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'target pruning: missing required utility: %s\n' "$tool" >&2
        exit 1
    fi
done
state=$(mktemp -d "${{TMPDIR:-/tmp}}/carrick-target-prune.XXXXXX") || exit 1
trap 'rm -rf -- "$state"' EXIT
: > "$state/bytes" || exit 1
lsof_bin=$(command -v lsof) || lsof_bin=
uid=$(id -u) || exit 1
set -- {paths}
for target do
    [ -d "$target" ] || continue
    if [ -L "$target" ]; then
        printf 'keep target (symlink) | %s\n' "$target"
        continue
    fi
    /usr/bin/perl -e {locks} "$target" /bin/sh -c {target_body} sh "$target" "$apply" "$age" "$state" "$lsof_bin" "$uid" || exit 1
done
if [ "$apply" = 1 ]; then action=freed; else action='would free'; fi
bytes=$(awk '{{total += $1}} END {{printf "%.0f", total}}' "$state/bytes") || exit 1
case "$bytes" in ''|*[!0-9]*) printf 'target pruning: invalid total accounting\n' >&2; exit 1;; esac
printf 'target pruning: %s %s allocated bytes (age >= {days} days)\n' "$action" "$bytes"
"#
    ))
}

/// Stock Perl supplies BSD flock on macOS, which ships no flock executable.
/// Keep its descriptor in the parent across system(), never unlink a live lease.
const REMOTE_LEASE: &str = r#"use Fcntl qw(:flock);
my $path = shift @ARGV;
open(my $lock, '>>', $path) or die "host lease open: $!\n";
chmod 0666, $path;
unless (flock($lock, LOCK_EX | LOCK_NB)) {
    print "target pruning skipped: host lease is held\n";
    exit 0;
}
system(@ARGV);
die "target pruning spawn: $!\n" if $? == -1;
exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);
"#;

pub(crate) fn remote_script(remote_root: &str) -> Result<String, GcError> {
    let lock = shell_quote(&format!("{remote_root}/gate-worktree.lock"));
    let env = shell_quote(&format!("{remote_root}/env.sh"));
    let target = PathBuf::from(format!("{remote_root}/gate-worktree/target"));
    let body = shell_quote(&pruning_body(&[target], 2, true)?);
    let perl = shell_quote(REMOTE_LEASE);
    Ok(format!(
        r#"set -u
if [ -f {env} ]; then . {env}; fi
lock={lock}
if ! mkdir "$lock"; then
    printf 'target pruning skipped: gate checkout lock is held\n'
    exit 0
fi
trap 'rm -f "$lock/run_id"; rmdir "$lock"' EXIT
printf 'target-prune-%s\n' "$$" > "$lock/run_id" || exit 1
/usr/bin/perl -e {perl} "${{CARRICK_HOST_LEASE_PATH:-{DEFAULT_LOCK_PATH}}}" /bin/sh -c {body}
"#
    ))
}

pub(crate) fn run(
    root: &Path,
    args: WorktreeGcArgs,
    writer: &mut impl Write,
) -> Result<(), GcError> {
    let dev = root
        .parent()
        .ok_or_else(|| GcError::Census("checkout has no parent directory".into()))?;
    let Some(_checkout) = CheckoutGuard::claim(&dev.join("gate-worktree.lock"))? else {
        writeln!(writer, "target pruning skipped: gate checkout lock is held")?;
        return Ok(());
    };
    let lease_path = std::env::var_os("CARRICK_HOST_LEASE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_PATH));
    let Some(_lease) = HostLease::try_exclusive(&lease_path)? else {
        writeln!(writer, "target pruning skipped: host lease is held")?;
        return Ok(());
    };
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
    let body = pruning_body(&targets, args.days, args.apply)?;
    let output = crate::command::run_checked("/bin/sh", ["-c", &body], None)?;
    writer.write_all(output.stdout.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_lease::HostLeaseMode;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use std::time::{Duration, SystemTime};

    fn utility_fixture(root: &Path, omit: &str) -> PathBuf {
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        for tool in [
            "find", "du", "awk", "mktemp", "rm", "id", "mkdir", "rmdir", "chmod",
        ] {
            if tool == omit {
                continue;
            }
            let output = Command::new("/bin/sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .unwrap();
            assert!(output.status.success());
            symlink(
                String::from_utf8(output.stdout).unwrap().trim(),
                bin.join(tool),
            )
            .unwrap();
        }
        fs::write(bin.join("lsof"), "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(bin.join("lsof"), fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    fn old_artifact(root: &Path) -> (PathBuf, PathBuf) {
        let target = root.join("target");
        let file = target.join("debug/deps/old-output");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "keep on failed accounting").unwrap();
        fs::File::open(&file)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_secs(4 * 86_400)),
            )
            .unwrap();
        (target, file)
    }

    #[test]
    fn native_cargo_lock_preserves_old_artifacts_despite_idle_census() {
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let bin = utility_fixture(temp.path(), "");
        let lock = fs::File::create(target.join("debug/.cargo-lock")).unwrap();
        lock.lock().unwrap();
        let body = pruning_body(&[target], 2, true)
            .unwrap()
            .replace(IDLE_CENSUS, "\nidle() { return 0; }\n");
        let output = Command::new("/bin/sh")
            .args(["-c", &body])
            .env("PATH", bin)
            .output()
            .unwrap();
        assert!(
            output.status.success() && artifact.exists(),
            "native Cargo lock must exclude pruning: exit={:?}, artifact_exists={}, stdout={}",
            output.status.code(),
            artifact.exists(),
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn concurrent_cargo_admission_is_excluded_through_deletion() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::process::Stdio;
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let bin = utility_fixture(temp.path(), "");
        let socket = temp.path().join("census.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sender.send(listener.accept()).unwrap();
        });
        let handshake = temp.path().join("census.pl");
        fs::write(&handshake, r#"use IO::Socket::UNIX; my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $ARGV[0]) or die $!; print $s "ready\n"; $s->flush; my $reply = <$s>; die "lost controller" unless defined $reply;"#).unwrap();
        let idle = format!(
            "\nidle() {{\nif [ ! -f \"{marker}\" ]; then\n: > \"{marker}\"\n/usr/bin/perl \"{handshake}\" \"{socket}\" || exit 1\nfi\nreturn 0\n}}\n",
            marker = temp.path().join("census.once").display(),
            handshake = handshake.display(),
            socket = socket.display()
        );
        let body = pruning_body(std::slice::from_ref(&target), 2, true)
            .unwrap()
            .replace(IDLE_CENSUS, &idle);
        let child = Command::new("/bin/sh")
            .args(["-c", &body])
            .env("PATH", bin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (mut peer, _) = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("pruning must reach its idle census")
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut ready = [0; 6];
        peer.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready\n");
        let lock = fs::File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(target.join("debug/.cargo-lock"))
            .unwrap();
        let admission = lock.try_lock();
        // Always release the fixture so the regression fails without hanging.
        peer.write_all(b"continue\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            matches!(admission, Err(std::fs::TryLockError::WouldBlock)),
            "Cargo admitted after idle census: {admission:?}; artifact_exists={}",
            artifact.exists()
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!artifact.exists());
        assert!(
            lock.try_lock().is_ok(),
            "Cargo must be admitted after deletion finishes"
        );
    }

    #[test]
    fn real_cargo_build_and_pruning_share_the_native_lock() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::process::Stdio;
        let temp = tempfile::tempdir().unwrap();
        let (target, artifact) = old_artifact(temp.path());
        let bin = utility_fixture(temp.path(), "");
        fs::write(temp.path().join("Cargo.toml"), "[package]\nname=\"native-lock-proof\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\n").unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(temp.path().join("build.rs"), r#"use std::io::{Read, Write}; fn main() { let mut s = std::os::unix::net::UnixStream::connect(std::env::var_os("BUILD_CENSUS_SOCKET").unwrap()).unwrap(); s.write_all(b"ready\n").unwrap(); let mut reply = [0]; s.read_exact(&mut reply).unwrap(); }"#).unwrap();
        let socket = temp.path().join("cargo.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sender.send(listener.accept()).unwrap();
        });
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
        let (mut peer, _) = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("Cargo build script must reach the barrier")
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut ready = [0; 6];
        peer.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready\n");
        let body = pruning_body(&[target], 2, true)
            .unwrap()
            .replace(IDLE_CENSUS, "\nidle() { return 0; }\n");
        let output = Command::new("/bin/sh")
            .args(["-c", &body])
            .env("PATH", bin)
            .output()
            .unwrap();
        peer.write_all(b"c").unwrap();
        let built = cargo.wait_with_output().unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        assert!(
            output.status.success() && artifact.exists(),
            "live Cargo build must exclude deletion: artifact_exists={}, stdout={}",
            artifact.exists(),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Cargo lock is held"));
    }

    #[test]
    fn missing_awk_fails_before_deleting_an_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let (target, file) = old_artifact(temp.path());
        let bin = utility_fixture(temp.path(), "awk");
        // Pin the external OS census to idle; exercise real find/du/deletion
        // and shell accounting with the reviewed missing-utility PATH.
        let body = pruning_body(&[target], 2, true)
            .unwrap()
            .replace(IDLE_CENSUS, "\nidle() { return 0; }\n");
        let output = Command::new("/bin/sh")
            .args(["-c", &body])
            .env("PATH", bin)
            .output()
            .unwrap();
        assert!(
            !output.status.success() && file.exists(),
            "missing awk must fail before deletion: exit={:?}, artifact_exists={}, stderr={}, stdout={}",
            output.status.code(),
            file.exists(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn failed_awk_accounting_preserves_the_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let (target, file) = old_artifact(temp.path());
        let bin = utility_fixture(temp.path(), "awk");
        fs::write(bin.join("awk"), "#!/bin/sh\nexit 75\n").unwrap();
        fs::set_permissions(bin.join("awk"), fs::Permissions::from_mode(0o755)).unwrap();
        let body = pruning_body(&[target], 2, true)
            .unwrap()
            .replace(IDLE_CENSUS, "\nidle() { return 0; }\n");
        let output = Command::new("/bin/sh")
            .args(["-c", &body])
            .env("PATH", bin)
            .output()
            .unwrap();
        assert!(
            !output.status.success() && file.exists(),
            "failed accounting must preserve the artifact: exit={:?}, artifact_exists={}",
            output.status.code(),
            file.exists()
        );
    }

    #[test]
    fn held_checkout_lock_skips_local_and_remote_pruning() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("main");
        fs::create_dir(&root).unwrap();
        let _guard = CheckoutGuard::claim(&temp.path().join("gate-worktree.lock"))
            .unwrap()
            .unwrap();
        assert!(
            CheckoutGuard::claim(&temp.path().join("gate-worktree.lock"))
                .unwrap()
                .is_none()
        );
        let mut output = Vec::new();
        run(
            &root,
            WorktreeGcArgs {
                apply: true,
                prune_targets: true,
                days: 2,
                target_dir: None,
            },
            &mut output,
        )
        .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("checkout lock is held")
        );
        let remote = Command::new("/bin/sh")
            .args(["-c", &remote_script(temp.path().to_str().unwrap()).unwrap()])
            .output()
            .unwrap();
        assert!(remote.status.success());
        assert!(
            String::from_utf8(remote.stdout)
                .unwrap()
                .contains("checkout lock is held")
        );
        assert!(temp.path().join("gate-worktree.lock/run_id").exists());
    }

    #[test]
    fn either_shared_or_exclusive_host_lease_prevents_local_and_remote_pruning() {
        // Isolate owned descriptors from concurrent fork-based tests: a fork
        // temporarily inherits their open descriptions even before exec.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "target_prune::tests::lock_guard_child_fixture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    #[ignore = "isolated process fixture invoked by the lock guard test"]
    fn lock_guard_child_fixture() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("host.lock");
        for mode in [HostLeaseMode::Carrick, HostLeaseMode::Gate] {
            let lease = HostLease::acquire_path(&path, mode).unwrap();
            assert!(HostLease::try_exclusive(&path).unwrap().is_none());
            let remote = Command::new("/bin/sh")
                .args(["-c", &remote_script(temp.path().to_str().unwrap()).unwrap()])
                .env("CARRICK_HOST_LEASE_PATH", &path)
                .output()
                .unwrap();
            assert!(
                remote.status.success(),
                "{}",
                String::from_utf8_lossy(&remote.stderr)
            );
            assert!(
                String::from_utf8(remote.stdout)
                    .unwrap()
                    .contains("host lease is held")
            );
            assert!(!temp.path().join("gate-worktree.lock").exists());
            drop(lease);
            assert!(HostLease::try_exclusive(&path).unwrap().is_some());
        }
    }

    fn rejected_by_find(entry: &Path) -> bool {
        let query = format!(
            "entry={}; age=+1; {AGE_QUERY}",
            shell_quote(entry.to_str().unwrap())
        );
        let output = Command::new("/bin/sh")
            .args(["-c", &query])
            .output()
            .unwrap();
        assert!(output.status.success());
        !output.stdout.is_empty()
    }

    #[test]
    fn generated_age_query_keeps_recent_future_descendants_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("artifact");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("output");
        fs::write(&file, "recent").unwrap();
        let old = SystemTime::now() - Duration::from_secs(4 * 86_400);
        let set_time = |path: &Path, time| {
            fs::File::open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(time))
                .unwrap()
        };
        set_time(&directory, old);
        assert!(rejected_by_find(&directory));
        set_time(&file, SystemTime::now() + Duration::from_secs(86_400));
        assert!(rejected_by_find(&file));
        set_time(&file, old);
        assert!(!rejected_by_find(&directory));
        fs::hard_link(&file, temp.path().join("other")).unwrap();
        assert!(rejected_by_find(&file));
        fs::remove_file(temp.path().join("other")).unwrap();
        symlink(&file, directory.join("link")).unwrap();
        set_time(&directory, old);
        assert!(rejected_by_find(&directory));
    }

    #[test]
    fn invalid_ages_fail_before_generating_a_prune_command() {
        assert!(pruning_body(&[], 0, true).is_err());
        assert!(pruning_body(&[], u64::MAX, true).is_err());
        assert!(pruning_body(&[], 2, false).is_ok());
    }

    #[test]
    fn remote_wrapper_uses_the_authoritative_host_lock_path_and_nonblocking_flock() {
        let script = remote_script("/dev/with spaces").unwrap();
        assert!(script.contains(&format!(
            "${{CARRICK_HOST_LEASE_PATH:-{DEFAULT_LOCK_PATH}}}"
        )));
        assert!(script.contains("LOCK_EX | LOCK_NB"));
        assert!(script.contains("/usr/bin/perl -e"));
        assert!(!script.contains("cargo run"));
    }

    #[test]
    fn missing_remote_perl_never_prunes_without_a_lease() {
        let temp = tempfile::tempdir().unwrap();
        let deps = temp.path().join("gate-worktree/target/debug/deps");
        fs::create_dir_all(&deps).unwrap();
        let file = deps.join("old-output");
        fs::write(&file, "keep").unwrap();
        fs::File::open(&file)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_secs(4 * 86_400)),
            )
            .unwrap();
        let script = remote_script(temp.path().to_str().unwrap())
            .unwrap()
            .replace("/usr/bin/perl", "/nonexistent/carrick-perl");
        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(file.exists());
        assert!(!temp.path().join("gate-worktree.lock").exists());
    }
}
