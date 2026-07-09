use crate::runtime::RuntimeError;
use carrick_spec::{
    BackendCapabilities, ExecBackendRequest, HostExecution, NativePageGeometry, NativePageProfile,
    NativePageProfileRequest, RunSpec,
};

pub(crate) const DEFAULT_LINUX_PAGE_SIZE: u64 = carrick_abi::LINUX_PAGE_SIZE;
const DARWIN_NATIVE_PAGE_SIZE: u64 = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionBackend {
    Hvf,
    NativeDarwin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageGeometry {
    pub host_page_size: u64,
    pub linux_page_size: u64,
    pub native_profile: Option<NativePageProfile>,
}

impl PageGeometry {
    pub fn native_geometry(self) -> Option<NativePageGeometry> {
        Some(NativePageGeometry {
            host_page_size: self.host_page_size,
            linux_page_size: self.linux_page_size,
            profile: self.native_profile?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionPlan {
    pub backend: ExecutionBackend,
    pub page_geometry: PageGeometry,
    pub diagnostics: Vec<String>,
}

pub(crate) fn resolve_execution_plan(spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError> {
    if spec.exec_backend != ExecBackendRequest::Native
        && spec.native_page_profile != NativePageProfileRequest::Auto
    {
        return Err(RuntimeError::Unsupported(
            "native page profile requires --exec-backend=native".to_string(),
        ));
    }

    match spec.exec_backend {
        ExecBackendRequest::Auto | ExecBackendRequest::Hvf => Ok(ExecutionPlan {
            backend: ExecutionBackend::Hvf,
            page_geometry: PageGeometry {
                host_page_size: DEFAULT_LINUX_PAGE_SIZE,
                linux_page_size: DEFAULT_LINUX_PAGE_SIZE,
                native_profile: None,
            },
            diagnostics: Vec::new(),
        }),
        ExecBackendRequest::Native => {
            let host_isa = BackendCapabilities::current().host_isa;
            if BackendCapabilities::current().host_execution(spec.platform) != HostExecution::Native
            {
                return Err(RuntimeError::Unsupported(format!(
                    "native execution backend does not support cross-ISA guest platform {:?} on {:?} host",
                    spec.platform, host_isa
                )));
            }
            native_plan(spec.native_page_profile)
        }
    }
}

fn native_plan(request: NativePageProfileRequest) -> Result<ExecutionPlan, RuntimeError> {
    let host_page_size = host_page_size();
    let profile = match request {
        NativePageProfileRequest::Auto => {
            if host_page_size != DARWIN_NATIVE_PAGE_SIZE {
                return Err(RuntimeError::Unsupported(format!(
                    "native execution unsupported on host page size {host_page_size}"
                )));
            }
            NativePageProfile::Native16k
        }
        NativePageProfileRequest::Native16k => {
            if host_page_size != DARWIN_NATIVE_PAGE_SIZE {
                return Err(RuntimeError::Unsupported(format!(
                    "native16k requires host page size 16384, got {host_page_size}"
                )));
            }
            NativePageProfile::Native16k
        }
        NativePageProfileRequest::Linux4k => {
            if host_page_size != DARWIN_NATIVE_PAGE_SIZE {
                return Err(RuntimeError::Unsupported(format!(
                    "linux4k native page profile requires host page size 16384, got {host_page_size}"
                )));
            }
            NativePageProfile::Linux4kOn16k
        }
    };

    let linux_page_size = match profile {
        NativePageProfile::Native16k => host_page_size,
        NativePageProfile::Linux4kOn16k => DEFAULT_LINUX_PAGE_SIZE,
    };
    Ok(ExecutionPlan {
        backend: ExecutionBackend::NativeDarwin,
        page_geometry: PageGeometry {
            host_page_size,
            linux_page_size,
            native_profile: Some(profile),
        },
        diagnostics: vec![format!(
            "native page profile selected: profile={profile:?} host_page_size={host_page_size} linux_page_size={linux_page_size}"
        )],
    })
}

fn host_page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as u64
    } else {
        DEFAULT_LINUX_PAGE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    fn spec_with_platform(
        platform: carrick_spec::Platform,
        exec_backend: ExecBackendRequest,
        page: NativePageProfileRequest,
    ) -> RunSpec {
        RunSpec {
            executable: "/bin/sh".to_string(),
            argv: vec!["/bin/sh".to_string()],
            envp: Vec::new(),
            cwd: Some(Utf8PathBuf::from("/")),
            rootfs_layers: Vec::new(),
            fs_backend: carrick_spec::FsBackendKind::Host,
            mounts: Vec::new(),
            tty: false,
            raw: true,
            interactive: false,
            max_traps: 100,
            debug_state_path: None,
            platform,
            exec_backend,
            native_page_profile: page,
            pid: carrick_spec::PidMode::Private,
            hostname: None,
            network: carrick_spec::NetworkNamespaceSpec::default(),
            extra_hosts: Vec::new(),
            uid: 0,
            gid: 0,
        }
    }

    fn spec(exec_backend: ExecBackendRequest, page: NativePageProfileRequest) -> RunSpec {
        spec_with_platform(carrick_spec::Platform::Aarch64, exec_backend, page)
    }

    #[test]
    fn hvf_request_ignores_native_page_geometry() {
        let plan = resolve_execution_plan(&spec(
            ExecBackendRequest::Hvf,
            NativePageProfileRequest::Auto,
        ))
        .expect("hvf plan");
        assert_eq!(plan.backend, ExecutionBackend::Hvf);
        assert_eq!(
            plan.page_geometry.linux_page_size,
            carrick_abi::LINUX_PAGE_SIZE
        );
        assert_eq!(plan.page_geometry.native_profile, None);
        assert_eq!(plan.page_geometry.native_geometry(), None);
    }

    #[test]
    fn explicit_hvf_rejects_explicit_native_page_profile() {
        let err = resolve_execution_plan(&spec(
            ExecBackendRequest::Hvf,
            NativePageProfileRequest::Linux4k,
        ))
        .expect_err("explicit native page profile requires native backend");
        assert!(
            err.to_string()
                .contains("native page profile requires --exec-backend=native")
        );
    }

    #[test]
    fn native_backend_rejects_cross_isa_guest_platform() {
        let err = resolve_execution_plan(&spec_with_platform(
            carrick_spec::Platform::Amd64,
            ExecBackendRequest::Native,
            NativePageProfileRequest::Auto,
        ))
        .expect_err("native backend must reject cross-ISA guest requests");

        assert!(matches!(
            err,
            RuntimeError::Unsupported(message)
                if message.contains("cross-ISA")
                    && message.contains("Amd64")
                    && message.contains("Aarch64")
        ));
    }

    #[test]
    fn native_linux4k_plan_reports_4k_linux_on_16k_host() {
        let plan = resolve_execution_plan(&spec(
            ExecBackendRequest::Native,
            NativePageProfileRequest::Linux4k,
        ))
        .expect("linux4k native plan");

        assert_eq!(plan.backend, ExecutionBackend::NativeDarwin);
        assert_eq!(plan.page_geometry.host_page_size, 16_384);
        assert_eq!(
            plan.page_geometry.native_geometry(),
            Some(NativePageGeometry {
                host_page_size: 16_384,
                linux_page_size: carrick_abi::LINUX_PAGE_SIZE,
                profile: NativePageProfile::Linux4kOn16k,
            })
        );
    }
}
