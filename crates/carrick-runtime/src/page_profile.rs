//! Backend selection + page-geometry plumbing for a run.
//!
//! The neutral page-geometry VOCABULARY (`PageGeometry`, `HostPageState`,
//! `classify_host_page_state`, …) moved to `carrick_dsr::page_geometry` as
//! part of the staged native-DSR extraction; it is re-exported here so every
//! call site keeps its `crate::page_profile::*` path. What REMAINS here is
//! the runtime-side backend-selection gate: `ExecutionBackend`,
//! `ExecutionPlan`, and the `resolve_execution_plan*` policy that turns a
//! `RunSpec` request into a backend + geometry decision.

use crate::runtime::RuntimeError;
use carrick_spec::{
    BackendCapabilities, ExecBackendRequest, HostExecution, HostOs, NativePageProfile,
    NativePageProfileRequest, Platform, RunSpec,
};

use carrick_dsr::page_geometry::DARWIN_NATIVE_PAGE_SIZE;
pub(crate) use carrick_dsr::page_geometry::DEFAULT_LINUX_PAGE_SIZE;
pub use carrick_dsr::page_geometry::{
    HostPageState, MappingPolicyDecision, MixedPageReason, PageBacking, PageGeometry, PagePerms,
    SubpageState, classify_host_page_state, decide_linux4k_on_16k_mapping,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionBackend {
    Vmm,
    NativeDarwin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionPlan {
    pub backend: ExecutionBackend,
    pub page_geometry: PageGeometry,
    pub diagnostics: Vec<String>,
}

// Called only by the macOS `runtime` arm today (`run_oci`/`run_elf` planning);
// the non-macOS arms plan via `resolve_execution_plan_for_request` until M0.8
// wires the native run path on every host.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
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
        ExecBackendRequest::Vmm => Ok(ExecutionPlan {
            backend: ExecutionBackend::Vmm,
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
                    "native Darwin execution backend requires macOS host, got {:?}; pass --exec-backend vmm to request the platform VMM",
                    host_caps.host_os
                )));
            }
            if host_caps.host_execution(platform) != HostExecution::Native {
                return Err(RuntimeError::Unsupported(format!(
                    "native execution backend does not support cross-ISA guest platform {:?} on {:?} host; pass --exec-backend vmm to request the platform VMM",
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
                    "native execution unsupported on host page size {host_page_size}; pass --exec-backend vmm to request the platform VMM"
                )));
            }
            NativePageProfile::Native16k
        }
        NativePageProfileRequest::Native16k => {
            if host_page_size != DARWIN_NATIVE_PAGE_SIZE {
                return Err(RuntimeError::Unsupported(format!(
                    "native16k requires host page size 16384, got {host_page_size}; pass --exec-backend vmm to request the platform VMM"
                )));
            }
            NativePageProfile::Native16k
        }
        NativePageProfileRequest::Linux4k => {
            if host_page_size != DARWIN_NATIVE_PAGE_SIZE {
                return Err(RuntimeError::Unsupported(format!(
                    "linux4k native page profile requires host page size 16384, got {host_page_size}; pass --exec-backend vmm to request the platform VMM"
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
    use carrick_spec::{NativePageGeometry, Platform};

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
            seccomp_policy: carrick_spec::SeccompPolicy::ContainerDefault,
        }
    }

    fn spec(exec_backend: ExecBackendRequest, page: NativePageProfileRequest) -> RunSpec {
        spec_with_platform(carrick_spec::Platform::Aarch64, exec_backend, page)
    }

    fn caps(host_os: HostOs, host_isa: Platform) -> BackendCapabilities {
        BackendCapabilities { host_os, host_isa }
    }

    #[test]
    fn vmm_request_uses_linux_page_geometry() {
        let plan = resolve_execution_plan(&spec(
            ExecBackendRequest::Vmm,
            NativePageProfileRequest::Auto,
        ))
        .expect("vmm plan");
        assert_eq!(plan.backend, ExecutionBackend::Vmm);
        assert_eq!(
            plan.page_geometry.linux_page_size,
            carrick_abi::LINUX_PAGE_SIZE
        );
        assert_eq!(plan.page_geometry.native_profile, None);
        assert_eq!(plan.page_geometry.native_geometry(), None);
    }

    #[test]
    fn explicit_vmm_rejects_explicit_native_page_profile() {
        let err = resolve_execution_plan(&spec(
            ExecBackendRequest::Vmm,
            NativePageProfileRequest::Linux4k,
        ))
        .expect_err("explicit native page profile requires native backend");
        assert!(
            err.to_string()
                .contains("native page profile requires --exec-backend=native")
        );
    }

    #[test]
    fn omitted_backend_resolves_native_on_macos_aarch64() {
        let plan = resolve_execution_plan_for_host(
            &spec(
                ExecBackendRequest::default(),
                NativePageProfileRequest::Auto,
            ),
            caps(HostOs::Macos, Platform::Aarch64),
            DARWIN_NATIVE_PAGE_SIZE,
        )
        .expect("default backend should resolve to native");

        assert_eq!(plan.backend, ExecutionBackend::NativeDarwin);
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
                    && message.contains("--exec-backend vmm")
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
                if message.contains("macOS")
                    && message.contains("Linux")
                    && message.contains("--exec-backend vmm")
        ));
    }

    #[test]
    fn native16k_plan_has_no_instruction_vehicle_policy() {
        let plan = native_plan(NativePageProfileRequest::Native16k, DARWIN_NATIVE_PAGE_SIZE)
            .expect("native16k plan");
        assert_eq!(plan.backend, ExecutionBackend::NativeDarwin);
        assert_eq!(
            plan.page_geometry.native_profile,
            Some(NativePageProfile::Native16k)
        );
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
}
