//! Lifetime of a signed gate's build checkout.
use std::path::Path;

pub fn run_name() -> String {
    format!(
        "{}-{}",
        std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| std::process::id().to_string()),
        std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".into())
    )
}

pub struct GateCheckout {
    directory: tempfile::TempDir,
}

impl GateCheckout {
    pub fn acquire(root: &Path, _run: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            directory: tempfile::tempdir_in(root)?,
        })
    }
    pub fn path(&self) -> &Path {
        self.directory.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn checkout_child() {
        let Some(root) = std::env::var_os("GATE_CHECKOUT_TEST_ROOT") else {
            return;
        };
        let checkout = GateCheckout::acquire(Path::new(&root), "killed-1").unwrap();
        std::fs::create_dir(checkout.path().join("checkout")).unwrap();
        println!("READY:{}", checkout.path().display());
        std::io::stdout().flush().unwrap();
        // Bounded even if the parent test fails before killing us.
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn killed_checkout_is_reaped_but_live_checkout_is_kept() {
        let root = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signed_gate::checkout::tests::checkout_child",
                "--nocapture",
            ])
            .env("GATE_CHECKOUT_TEST_ROOT", root.path())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if let Some(path) = line.strip_prefix("READY:") {
                    tx.send(PathBuf::from(path)).unwrap();
                    break;
                }
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(10));
        child.kill().unwrap();
        child.wait().unwrap();
        reader.join().unwrap();
        let stale = ready.unwrap();
        assert!(stale.join("checkout").exists());
        let live = GateCheckout::acquire(root.path(), "live-1").unwrap();
        let next = GateCheckout::acquire(root.path(), "next-1").unwrap();
        assert!(
            !stale.exists(),
            "killed gate checkout survived the next gate start"
        );
        assert!(live.path().exists(), "live checkout was reaped");
        let next_path = next.path().to_path_buf();
        drop(next);
        assert!(!next_path.exists(), "normal drop must remove checkout");
    }
}
