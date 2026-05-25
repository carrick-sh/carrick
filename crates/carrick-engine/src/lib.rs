//! High-level orchestration layer for Carrick run requests.
//!
//! The engine bridges CLI-facing run specs to image resolution, rootfs
//! composition, filesystem backend selection, and runtime execution.

use std::collections::HashMap;
use camino::Utf8PathBuf;

pub use carrick_spec::{RunSpec, FsBackendKind, Mount, ImageConfig};
pub use carrick_image::{ImageStore, ResolvedImage};
pub use carrick_runtime::runtime::RunResult;

#[derive(Debug, Clone)]
pub struct CliRunRequest {
    pub image_ref: String,
    pub args: Vec<String>,
    pub env_overrides: Vec<String>,
    pub mounts: Vec<Mount>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    pub entrypoint_override: Option<Vec<String>>,
    pub tty: bool,
    pub interactive: bool,
    pub rm: bool,
    pub name: Option<String>,
    pub max_traps: usize,
    pub debug_state_path: Option<String>,
    pub fs: Option<FsBackendKind>,
}

pub fn resolve_run_spec(
    req: CliRunRequest,
    image: ResolvedImage,
) -> Result<RunSpec, String> {
    // 1. Resolve argv (entrypoint + cmd overrides)
    let effective_entrypoint = match req.entrypoint_override {
        Some(overrides) => overrides,
        None => image.config.entrypoint.clone().unwrap_or_default(),
    };

    let effective_cmd = if !req.args.is_empty() {
        req.args.clone()
    } else {
        image.config.cmd.clone().unwrap_or_default()
    };

    let mut argv = Vec::new();
    argv.extend(effective_entrypoint);
    argv.extend(effective_cmd);

    if argv.is_empty() {
        return Err("no command specified".to_string());
    }

    let executable = argv[0].clone();

    // 2. Resolve env variables
    let mut env_map = HashMap::new();

    // Add image env
    for entry in &image.config.env {
        if let Some((k, v)) = entry.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    // Add baseline defaults ONLY if not already set by image config
    let baseline_defaults = [
        ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ("HOME", "/root"),
        ("TERM", "xterm-256color"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("PAGER", "cat"),
    ];
    for (k, v) in baseline_defaults {
        env_map.entry(k.to_string()).or_insert_with(|| v.to_string());
    }

    // Add env overrides (last-wins)
    for entry in &req.env_overrides {
        if let Some((k, v)) = entry.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    let mut envp: Vec<String> = env_map
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    envp.sort();

    // 3. Resolve working directory
    let cwd = match req.workdir {
        Some(w) => Some(Utf8PathBuf::from(w)),
        None => image.config.working_dir.clone(),
    }.or_else(|| Some(Utf8PathBuf::from("/")));

    // 4. Resolve user
    let _user = req.user.clone().or_else(|| image.config.user.clone());

    // 5. Select fs backend (fall back to case sensitivity probe)
    let fs_backend = req.fs.unwrap_or_else(|| {
        let probe = carrick_runtime::apfs::preferred_scratch_root()
            .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
        if std::fs::create_dir_all(&probe).is_err() {
            FsBackendKind::Memory
        } else if carrick_runtime::apfs::probe_case_sensitive(&probe) {
            FsBackendKind::Host
        } else {
            FsBackendKind::Memory
        }
    });

    let debug_state_path = req.debug_state_path.map(Utf8PathBuf::from);

    Ok(RunSpec {
        executable,
        argv,
        envp,
        cwd,
        rootfs_layers: image.layers,
        fs_backend,
        mounts: req.mounts,
        tty: req.tty,
        raw: true,
        interactive: req.interactive,
        max_traps: req.max_traps,
        debug_state_path,
    })
}

pub struct Engine {
    store: ImageStore,
}

impl Engine {
    pub fn new(store: ImageStore) -> Self {
        Self { store }
    }

    pub async fn run(&self, req: CliRunRequest) -> Result<RunResult, anyhow::Error> {
        let image_ref = carrick_spec::ImageReference::parse(&req.image_ref)
            .map_err(|e| anyhow::anyhow!("invalid image reference: {}", e))?;

        let resolved = self.store.resolve(&image_ref).await
            .map_err(|e| anyhow::anyhow!("failed to resolve image: {}", e))?;

        let run_spec = resolve_run_spec(req, resolved)
            .map_err(|e| anyhow::Error::msg(e))?;

        let result = carrick_runtime::Runtime::execute(&run_spec)?;
        Ok(result)
     }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_image(entrypoint: Option<Vec<String>>, cmd: Option<Vec<String>>, env: Vec<String>, working_dir: Option<Utf8PathBuf>) -> ResolvedImage {
        ResolvedImage {
            layers: vec![Utf8PathBuf::from("/layer1")],
            config: ImageConfig {
                entrypoint,
                cmd,
                env,
                working_dir,
                user: Some("root".to_string()),
                exposed_ports: None,
                labels: None,
            },
        }
    }

    #[test]
    fn test_merge_argv_no_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            args: vec![],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.executable, "/bin/sh");
        assert_eq!(spec.argv, vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_argv_cmd_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["/bin/sh", "/bin/ls"]);
    }

    #[test]
    fn test_merge_argv_entrypoint_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            args: vec![],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: Some(vec!["/bin/bash".to_string()]),
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["/bin/bash", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_env_variables() {
        let image = make_test_image(
            None,
            None,
            vec!["PATH=/image/bin".to_string(), "CUSTOM=1".to_string()],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec!["CUSTOM=2".to_string(), "USER_VAR=yes".to_string()],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
        };
        let spec = resolve_run_spec(req, image).unwrap();
        
        let env_map: HashMap<String, String> = spec.envp
            .iter()
            .map(|e| e.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())).unwrap())
            .collect();
        
        assert_eq!(env_map.get("PATH").unwrap(), "/image/bin"); // Image env wins over baseline defaults
        assert_eq!(env_map.get("CUSTOM").unwrap(), "2"); // Override wins over image env
        assert_eq!(env_map.get("USER_VAR").unwrap(), "yes");
        assert_eq!(env_map.get("HOME").unwrap(), "/root"); // Baseline default is set
    }

    #[test]
    fn test_merge_workdir() {
        let image = make_test_image(None, None, vec![], Some(Utf8PathBuf::from("/image/app")));
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: Some("/user/app".to_string()),
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.cwd.unwrap().as_str(), "/user/app");
    }
}
