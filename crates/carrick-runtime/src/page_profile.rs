//! Backend selection + page-geometry plumbing for a run.

use crate::runtime::RuntimeError;
use carrick_spec::{
    BackendCapabilities, ExecBackendRequest, HostOs, NativePageProfileRequest, Platform, RunSpec,
};

pub(crate) use carrick_dsr::page_geometry::DEFAULT_LINUX_PAGE_SIZE;
pub use carrick_dsr::page_geometry::{
    HostPageState, MappingPolicyDecision, MixedPageReason, PageBacking, PageGeometry, PagePerms,
    SubpageState, classify_host_page_state, decide_linux4k_on_16k_mapping,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionBackend {
    /// HVF execution with static text patched to enter in-guest syscall
    /// islands. This lane is intentionally limited to macOS/AArch64.
    HvPatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionPlan {
    pub backend: ExecutionBackend,
    pub page_geometry: PageGeometry,
    pub diagnostics: Vec<String>,
}

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
    _host_page_size: u64,
) -> Result<ExecutionPlan, RuntimeError> {
    if native_page_profile != NativePageProfileRequest::Auto {
        return Err(RuntimeError::Unsupported(
            "native page profile is not supported (native backend retired)".to_string(),
        ));
    }

    match exec_backend {
        ExecBackendRequest::HvPatch => {
            if host_caps.host_os != HostOs::Macos
                || host_caps.host_isa != Platform::Aarch64
                || platform != Platform::Aarch64
            {
                return Err(RuntimeError::Unsupported(format!(
                    "hvpatch requires macOS/AArch64 host and AArch64 guest; got host={:?}/{:?} guest={platform:?}",
                    host_caps.host_os, host_caps.host_isa
                )));
            }
            Ok(ExecutionPlan {
                backend: ExecutionBackend::HvPatch,
                page_geometry: PageGeometry {
                    host_page_size: DEFAULT_LINUX_PAGE_SIZE,
                    linux_page_size: DEFAULT_LINUX_PAGE_SIZE,
                    native_profile: None,
                },
                diagnostics: Vec::new(),
            })
        }
    }
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
    use carrick_dsr::page_geometry::DARWIN_NATIVE_PAGE_SIZE;
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
            uid: carrick_abi::NsUid::ROOT,
            gid: carrick_abi::NsGid::ROOT,
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
    fn hvpatch_request_uses_linux_geometry_on_macos_aarch64() {
        let plan = resolve_execution_plan_for_host(
            &spec(ExecBackendRequest::HvPatch, NativePageProfileRequest::Auto),
            caps(HostOs::Macos, Platform::Aarch64),
            DARWIN_NATIVE_PAGE_SIZE,
        )
        .expect("macOS/AArch64 hvpatch plan");

        assert_eq!(plan.backend, ExecutionBackend::HvPatch);
        assert_eq!(plan.page_geometry.host_page_size, DEFAULT_LINUX_PAGE_SIZE);
        assert_eq!(plan.page_geometry.linux_page_size, DEFAULT_LINUX_PAGE_SIZE);
        assert_eq!(plan.page_geometry.native_profile, None);
    }

    #[test]
    fn hvpatch_request_rejects_non_hvf_hosts_and_cross_isa_guests() {
        for (host_os, host_isa, guest) in [
            (HostOs::Linux, Platform::Aarch64, Platform::Aarch64),
            (HostOs::Macos, Platform::Amd64, Platform::Amd64),
            (HostOs::Macos, Platform::Aarch64, Platform::Amd64),
        ] {
            let error = resolve_execution_plan_for_host(
                &spec_with_platform(
                    guest,
                    ExecBackendRequest::HvPatch,
                    NativePageProfileRequest::Auto,
                ),
                caps(host_os, host_isa),
                DARWIN_NATIVE_PAGE_SIZE,
            )
            .expect_err("hvpatch must be scoped to macOS/AArch64 host and guest");
            assert!(
                error.to_string().contains("hvpatch requires macOS/AArch64"),
                "unexpected hvpatch capability error: {error}"
            );
        }
    }

    #[test]
    fn explicit_native_page_profile_rejected() {
        let err = resolve_execution_plan(&spec(
            ExecBackendRequest::HvPatch,
            NativePageProfileRequest::Linux4k,
        ))
        .expect_err("explicit native page profile rejected");
        assert!(
            err.to_string()
                .contains("native page profile is not supported")
        );
    }
}
