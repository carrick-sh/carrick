//! Test-facing conveniences: a reusable [`TestContainer`], the one-liner
//! [`run_in_container`], and [`ResultAssert`] for fluent assertions on a
//! [`ContainerResult`]. Guest-running uses of these belong in tests executed
//! by the signed `just test-embed` recipe.

use crate::{ContainerBuilder, ContainerResult, EmbedError, ImageStore};

/// One image, many commands: each [`Self::run`] builds a fresh
/// [`ContainerBuilder`] with captured stdio, so tests read the guest's bytes
/// from the returned [`ContainerResult`].
#[derive(Clone, Debug)]
pub struct TestContainer {
    image: String,
    env: Vec<(String, String)>,
    max_traps: Option<usize>,
    store: Option<ImageStore>,
}

impl TestContainer {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            env: Vec::new(),
            max_traps: None,
            store: None,
        }
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn max_traps(mut self, max_traps: usize) -> Self {
        self.max_traps = Some(max_traps);
        self
    }

    pub fn image_store(mut self, store: ImageStore) -> Self {
        self.store = Some(store);
        self
    }

    /// The builder one `run` would execute (exposed so request-level tests
    /// can check the lowering without a guest).
    pub fn builder<I, S>(&self, argv: I) -> ContainerBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut builder = ContainerBuilder::from_image(self.image.clone()).command(argv);
        for (key, value) in &self.env {
            builder = builder.env(key.clone(), value.clone());
        }
        if let Some(max_traps) = self.max_traps {
            builder = builder.max_traps(max_traps);
        }
        if let Some(store) = &self.store {
            builder = builder.image_store(store.clone());
        }
        builder
    }

    /// Run `argv` to completion (blocking; needs a signed executable).
    pub fn run<I, S>(&self, argv: I) -> Result<ContainerResult, EmbedError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.builder(argv).run_blocking()
    }
}

/// `ContainerBuilder::from_image(image).command(cmd).run_blocking()`.
pub fn run_in_container(image: &str, cmd: &[&str]) -> Result<ContainerResult, EmbedError> {
    ContainerBuilder::from_image(image)
        .command(cmd.iter().copied())
        .run_blocking()
}

/// Fluent assertions; each returns `&Self` so they chain.
pub trait ResultAssert {
    fn assert_success(&self) -> &Self;
    fn assert_exit_code(&self, code: i32) -> &Self;
    fn assert_stdout_contains(&self, needle: &str) -> &Self;
    fn assert_stderr_contains(&self, needle: &str) -> &Self;
}

impl ResultAssert for ContainerResult {
    fn assert_success(&self) -> &Self {
        assert!(
            self.success(),
            "expected a successful run; exit_code={} signal={:?} trap_limit_hit={} stderr={:?}",
            self.exit_code,
            self.signal,
            self.trap_limit_hit,
            self.stderr_utf8()
        );
        self
    }

    fn assert_exit_code(&self, code: i32) -> &Self {
        assert_eq!(
            self.exit_code,
            code,
            "unexpected exit code; stderr={:?}",
            self.stderr_utf8()
        );
        self
    }

    fn assert_stdout_contains(&self, needle: &str) -> &Self {
        let stdout = self.stdout_utf8();
        assert!(
            stdout.contains(needle),
            "stdout does not contain {needle:?}; stdout={stdout:?}"
        );
        self
    }

    fn assert_stderr_contains(&self, needle: &str) -> &Self {
        let stderr = self.stderr_utf8();
        assert!(
            stderr.contains(needle),
            "stderr does not contain {needle:?}; stderr={stderr:?}"
        );
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompatReport;

    fn result(exit_code: i32, stdout: &str, stderr: &str) -> ContainerResult {
        ContainerResult {
            exit_code,
            signal: None,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            trap_limit_hit: false,
            traps: 1,
            compat: CompatReport::default(),
            terminal_reason: None,
        }
    }

    #[test]
    fn assertions_chain_on_a_passing_result() {
        result(0, "hello world\n", "warn\n")
            .assert_success()
            .assert_exit_code(0)
            .assert_stdout_contains("hello")
            .assert_stderr_contains("warn");
    }

    #[test]
    #[should_panic(expected = "expected a successful run")]
    fn assert_success_panics_on_a_nonzero_exit() {
        result(3, "", "").assert_success();
    }

    #[test]
    #[should_panic(expected = "stdout does not contain")]
    fn assert_stdout_contains_panics_and_names_the_needle() {
        result(0, "abc", "").assert_stdout_contains("zzz");
    }

    #[test]
    fn test_container_builds_a_captured_request_per_run() {
        let container = TestContainer::new("ubuntu:24.04")
            .env("K", "v")
            .max_traps(9);
        let request = container.builder(["/bin/true"]).to_run_request().unwrap();
        assert_eq!(request.image_ref, "ubuntu:24.04");
        assert_eq!(request.args, vec!["/bin/true".to_string()]);
        assert_eq!(request.env_overrides, vec!["K=v".to_string()]);
        assert_eq!(request.max_traps, 9);
        assert_eq!(request.stdio, crate::StdioMode::Captured);
    }
}
