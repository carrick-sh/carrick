//! Neutral page-geometry vocabulary for the native (DSR) execution backend.
//!
//! Peeled out of `carrick-runtime/src/page_profile.rs` (which retains
//! `ExecutionPlan` and `resolve_execution_plan*`). Everything here is pure data
//! + classification policy; the runtime re-exports these names under
//! `crate::page_profile` so its call sites read unchanged.

use carrick_guest_mem::{NativePageGeometry, NativePageProfile};

pub const DEFAULT_LINUX_PAGE_SIZE: u64 = carrick_abi::LINUX_PAGE_SIZE;
pub const DARWIN_NATIVE_PAGE_SIZE: u64 = 16_384;

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

#[cfg(test)]
mod tests {
    use super::*;

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
