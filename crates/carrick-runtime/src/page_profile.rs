use crate::runtime::RuntimeError;
use carrick_spec::{
    BackendCapabilities, ExecBackendRequest, HostExecution, HostOs, NativePageGeometry,
    NativePageProfile, NativePageProfileRequest, Platform, RunSpec,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPageState {
    Uniform16k,
    Composed16k,
    MixedGuarded(MixedPageReason),
    Unsupported(MixedPageReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixedPageReason {
    Permissions,
    Backing,
    ExecutableMixedPage,
    UnsupportedGeometry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingPolicyDecision {
    Supported {
        state: HostPageState,
        diagnostic: String,
    },
    Unsupported {
        reason: MixedPageReason,
        diagnostic: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageBacking {
    Anonymous,
    PrivateFile,
    SharedFile,
    Unmapped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePerms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl PagePerms {
    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
            exec: false,
        }
    }

    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            exec: false,
        }
    }

    pub const fn read_exec() -> Self {
        Self {
            read: true,
            write: false,
            exec: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubpageState {
    pub backing: PageBacking,
    pub perms: PagePerms,
}

impl SubpageState {
    pub const fn new(backing: PageBacking, perms: PagePerms) -> Self {
        Self { backing, perms }
    }
}

pub fn classify_host_page_state<const N: usize>(
    geometry: PageGeometry,
    subpages: [SubpageState; N],
) -> HostPageState {
    if geometry.host_page_size == geometry.linux_page_size {
        return HostPageState::Uniform16k;
    }
    if geometry.host_page_size != 16_384 || geometry.linux_page_size != 4096 || N != 4 {
        return HostPageState::Unsupported(MixedPageReason::UnsupportedGeometry);
    }

    let first = subpages[0];
    if subpages.iter().all(|state| *state == first) {
        return HostPageState::Uniform16k;
    }
    if subpages.iter().any(|state| state.perms.exec) {
        return HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage);
    }
    if subpages.iter().any(|state| state.backing != first.backing) {
        return HostPageState::Composed16k;
    }
    HostPageState::MixedGuarded(MixedPageReason::Permissions)
}

pub fn decide_linux4k_on_16k_mapping<const N: usize>(
    geometry: PageGeometry,
    subpages: [SubpageState; N],
) -> MappingPolicyDecision {
    let state = classify_host_page_state(geometry, subpages);
    match state {
        HostPageState::Uniform16k => MappingPolicyDecision::Supported {
            state,
            diagnostic: "linux4k-on-16k mapping supported: uniform 16K host page".to_string(),
        },
        HostPageState::Composed16k => {
            if subpages
                .iter()
                .any(|state| state.backing == PageBacking::SharedFile)
            {
                MappingPolicyDecision::Unsupported {
                    reason: MixedPageReason::Backing,
                    diagnostic: "native linux4k mapping unsupported: mixed shared-file backing requires alias/writeback coherence".to_string(),
                }
            } else {
                MappingPolicyDecision::Supported {
                    state,
                    diagnostic: "linux4k-on-16k mapping supported: composed private data page"
                        .to_string(),
                }
            }
        }
        HostPageState::MixedGuarded(MixedPageReason::Permissions) => {
            MappingPolicyDecision::Supported {
                state,
                diagnostic: "linux4k-on-16k mapping supported: guarded data page for mixed permissions".to_string(),
            }
        }
        HostPageState::MixedGuarded(reason) => MappingPolicyDecision::Unsupported {
            reason,
            diagnostic: format!("native linux4k mapping unsupported: mixed page reason {reason:?}"),
        },
        HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage) => {
            MappingPolicyDecision::Unsupported {
                reason: MixedPageReason::ExecutableMixedPage,
                diagnostic: "native linux4k mapping unsupported: executable mixed page requires instruction instrumentation".to_string(),
            }
        }
        HostPageState::Unsupported(MixedPageReason::UnsupportedGeometry) => {
            MappingPolicyDecision::Unsupported {
                reason: MixedPageReason::UnsupportedGeometry,
                diagnostic: format!(
                    "native linux4k mapping unsupported: requires 16K host pages and 4K Linux pages, got host_page_size={} linux_page_size={} subpages={N}",
                    geometry.host_page_size, geometry.linux_page_size
                ),
            }
        }
        HostPageState::Unsupported(reason) => MappingPolicyDecision::Unsupported {
            reason,
            diagnostic: format!("native linux4k mapping unsupported: mixed page reason {reason:?}"),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionPlan {
    pub backend: ExecutionBackend,
    pub page_geometry: PageGeometry,
    pub diagnostics: Vec<String>,
}

pub(crate) fn resolve_execution_plan(spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError> {
    resolve_execution_plan_for_request_for_host(
        spec.platform,
        spec.exec_backend,
        spec.native_page_profile,
        BackendCapabilities::current(),
        host_page_size(),
    )
}

pub(crate) fn resolve_execution_plan_for_request(
    platform: Platform,
    exec_backend: ExecBackendRequest,
    native_page_profile: NativePageProfileRequest,
) -> Result<ExecutionPlan, RuntimeError> {
    resolve_execution_plan_for_request_for_host(
        platform,
        exec_backend,
        native_page_profile,
        BackendCapabilities::current(),
        host_page_size(),
    )
}

#[cfg(test)]
fn resolve_execution_plan_for_host(
    spec: &RunSpec,
    host_caps: BackendCapabilities,
    host_page_size: u64,
) -> Result<ExecutionPlan, RuntimeError> {
    resolve_execution_plan_for_request_for_host(
        spec.platform,
        spec.exec_backend,
        spec.native_page_profile,
        host_caps,
        host_page_size,
    )
}

fn resolve_execution_plan_for_request_for_host(
    platform: Platform,
    exec_backend: ExecBackendRequest,
    native_page_profile: NativePageProfileRequest,
    host_caps: BackendCapabilities,
    host_page_size: u64,
) -> Result<ExecutionPlan, RuntimeError> {
    if exec_backend != ExecBackendRequest::Native
        && native_page_profile != NativePageProfileRequest::Auto
    {
        return Err(RuntimeError::Unsupported(
            "native page profile requires --exec-backend=native".to_string(),
        ));
    }

    match exec_backend {
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
            if host_caps.host_os != HostOs::Macos {
                return Err(RuntimeError::Unsupported(format!(
                    "native Darwin execution backend requires macOS host, got {:?}",
                    host_caps.host_os
                )));
            }
            if host_caps.host_execution(platform) != HostExecution::Native {
                return Err(RuntimeError::Unsupported(format!(
                    "native execution backend does not support cross-ISA guest platform {:?} on {:?} host",
                    platform, host_caps.host_isa
                )));
            }
            native_plan(native_page_profile, host_page_size)
        }
    }
}

fn native_plan(
    request: NativePageProfileRequest,
    host_page_size: u64,
) -> Result<ExecutionPlan, RuntimeError> {
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
    use carrick_spec::Platform;

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

    fn caps(host_os: HostOs, host_isa: Platform) -> BackendCapabilities {
        BackendCapabilities { host_os, host_isa }
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
        let err = resolve_execution_plan_for_host(
            &spec_with_platform(
                carrick_spec::Platform::Amd64,
                ExecBackendRequest::Native,
                NativePageProfileRequest::Auto,
            ),
            caps(HostOs::Macos, Platform::Aarch64),
            DARWIN_NATIVE_PAGE_SIZE,
        )
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
    fn native_backend_requires_macos_host() {
        let err = resolve_execution_plan_for_host(
            &spec(ExecBackendRequest::Native, NativePageProfileRequest::Auto),
            caps(HostOs::Linux, Platform::Aarch64),
            DARWIN_NATIVE_PAGE_SIZE,
        )
        .expect_err("native backend must reject non-macos hosts");

        assert!(matches!(
            err,
            RuntimeError::Unsupported(message)
                if message.contains("macOS") && message.contains("Linux")
        ));
    }

    #[test]
    fn native_linux4k_plan_reports_4k_linux_on_16k_host() {
        let result = resolve_execution_plan(&spec(
            ExecBackendRequest::Native,
            NativePageProfileRequest::Linux4k,
        ));

        let supported_current_lane = BackendCapabilities::current().host_os == HostOs::Macos
            && BackendCapabilities::current().host_isa == Platform::Aarch64
            && host_page_size() == DARWIN_NATIVE_PAGE_SIZE;

        if supported_current_lane {
            let plan = result.expect("linux4k native plan on Darwin 16K AArch64");
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
        } else {
            let err = result.expect_err("unsupported off the Darwin 16K native lane");
            assert!(matches!(err, RuntimeError::Unsupported(_)));
        }
    }

    #[test]
    fn classifies_uniform_16k_page_as_fast_path() {
        let state = classify_host_page_state(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            ],
        );
        assert_eq!(state, HostPageState::Uniform16k);
    }

    #[test]
    fn classifies_non_executable_mixed_permissions_as_guarded() {
        let state = classify_host_page_state(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::none()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            ],
        );
        assert_eq!(
            state,
            HostPageState::MixedGuarded(MixedPageReason::Permissions)
        );
    }

    #[test]
    fn rejects_executable_mixed_page_without_instruction_instrumentation() {
        let state = classify_host_page_state(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::none()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
            ],
        );
        assert_eq!(
            state,
            HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage)
        );
    }

    #[test]
    fn linux4k_policy_allows_composed_private_data_pages() {
        let decision = decide_linux4k_on_16k_mapping(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::PrivateFile, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::PrivateFile, PagePerms::read_write()),
            ],
        );

        assert_eq!(
            decision,
            MappingPolicyDecision::Supported {
                state: HostPageState::Composed16k,
                diagnostic: "linux4k-on-16k mapping supported: composed private data page"
                    .to_string(),
            }
        );
    }

    #[test]
    fn linux4k_policy_rejects_composed_shared_file_pages_with_diagnostic() {
        let decision = decide_linux4k_on_16k_mapping(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::SharedFile, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::SharedFile, PagePerms::read_write()),
            ],
        );

        assert_eq!(
            decision,
            MappingPolicyDecision::Unsupported {
                reason: MixedPageReason::Backing,
                diagnostic: "native linux4k mapping unsupported: mixed shared-file backing requires alias/writeback coherence".to_string(),
            }
        );
    }

    #[test]
    fn linux4k_policy_allows_guarded_data_permissions() {
        let decision = decide_linux4k_on_16k_mapping(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::none()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            ],
        );

        assert_eq!(
            decision,
            MappingPolicyDecision::Supported {
                state: HostPageState::MixedGuarded(MixedPageReason::Permissions),
                diagnostic:
                    "linux4k-on-16k mapping supported: guarded data page for mixed permissions"
                        .to_string(),
            }
        );
    }

    #[test]
    fn linux4k_policy_rejects_mixed_executable_pages_with_diagnostic() {
        let decision = decide_linux4k_on_16k_mapping(
            PageGeometry {
                host_page_size: 16_384,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::none()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_exec()),
            ],
        );

        assert_eq!(
            decision,
            MappingPolicyDecision::Unsupported {
                reason: MixedPageReason::ExecutableMixedPage,
                diagnostic: "native linux4k mapping unsupported: executable mixed page requires instruction instrumentation".to_string(),
            }
        );
    }

    #[test]
    fn linux4k_policy_rejects_unsupported_geometry_with_diagnostic() {
        let decision = decide_linux4k_on_16k_mapping(
            PageGeometry {
                host_page_size: 8192,
                linux_page_size: 4096,
                native_profile: Some(NativePageProfile::Linux4kOn16k),
            },
            [
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
                SubpageState::new(PageBacking::Anonymous, PagePerms::read_write()),
            ],
        );

        assert_eq!(
            decision,
            MappingPolicyDecision::Unsupported {
                reason: MixedPageReason::UnsupportedGeometry,
                diagnostic: "native linux4k mapping unsupported: requires 16K host pages and 4K Linux pages, got host_page_size=8192 linux_page_size=4096 subpages=2".to_string(),
            }
        );
    }
}
