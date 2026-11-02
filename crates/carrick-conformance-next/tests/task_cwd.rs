//! Signed execution binding for #1392: every ring process owns its cwd.
//!
//! Two live sibling processes of one tree each `chdir` into their own
//! directory and run commands there; a child forked before the root's `cd`
//! keeps the old cwd; a child's `umask` reaches its file creation. On main
//! before #1392, the root's first `cd` made every later child `exec` ENOSYS.
//! Oracle: native ARM64 Docker, same image digest, same script.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_conformance_next::{PullPolicy, TestContainer};

const LTP_IMAGE: &str =
    "localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b";

// Each child does at most one exec and creates files only through `openat`:
// a child's own fork, `mkdir` and `utimensat` are separate gaps (#1335).
const SCRIPT: &str = "\
cd /tmp
(cd /etc && exec /bin/pwd > /tmp/a.pwd) & (cd /usr && exec /bin/pwd > /tmp/b.pwd) & wait
/bin/cat /tmp/a.pwd /tmp/b.pwd
cd /
(exec /bin/pwd) &
cd /tmp
wait
/bin/pwd
(umask 027; : > /tmp/m1392; exec /usr/bin/stat -c %a /tmp/m1392)
/bin/sh -c 'cd /etc && exec /bin/pwd'
(cd /etc && exec /bin/ls -d passwd)
";

/// `docker run --rm --platform linux/arm64 <LTP_IMAGE> /bin/sh -c "$SCRIPT"`
/// on native ARM64 Docker.
const ORACLE: &str = "\
/etc
/usr
/
/tmp
640
/etc
passwd
";

#[test]
fn sibling_processes_own_their_cwd_and_umask() {
    let result = TestContainer::new(LTP_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .run(["/bin/sh", "-c", SCRIPT])
        .expect("signed task-cwd execution")
        .ensure_success()
        .expect("task-cwd script exit status");
    assert_eq!(
        result.stdout_utf8(),
        ORACLE,
        "Linux per-process cwd and umask; stderr={}",
        result.stderr_utf8()
    );
}
