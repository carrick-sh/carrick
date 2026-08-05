//! Versioned kernel-backed handoff for a native fork-child host self-exec.

use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CAPSULE_MAGIC: [u8; 8] = *b"CRKNEXE\0";
const CONSUMED_MAGIC: [u8; 8] = [0; 8];
const CAPSULE_VERSION: u16 = 1;
const HEADER_LEN: usize = 68;
const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;
const MAX_VECTOR_ITEMS: usize = 4096;
const MAX_ITEM_LEN: usize = 1024 * 1024;
const MAX_PATH_LEN: usize = 4096;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type NativeLiveArenaAuthority<'a> = Option<&'a carrick_native_darwin::live_arena::DarwinLiveArena>;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
type NativeLiveArenaAuthority<'a> = Option<&'a ()>;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type NativeRegisteredPortExecPlan = carrick_native_darwin::live_arena::RegisteredPortExecPlan;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
type NativeRegisteredPortExecPlan = ();

/// First schema carried by the native host-self-exec transport.
///
/// Process, filesystem, and descriptor records are added to this typed payload
/// as their snapshot APIs land. These launch fields are sufficient to prove the
/// transport and PID-preserving host exec without making the framing generic or
/// exposing an untyped byte-bag at its trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeExecCapsuleV1 {
    pub(crate) producer_pid: u32,
    pub(crate) purpose: NativeExecCapsulePurposeV1,
    pub(crate) host_executable_path: Vec<u8>,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) env: Vec<Vec<u8>>,
    pub(crate) guest_exec: Option<NativeGuestExecV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NativeExecCapsulePurposeV1 {
    PidProbe,
    GuestExec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeGuestExecV1 {
    pub(crate) resolved_path: String,
    pub(crate) executable_digest: [u8; 32],
    pub(crate) rootfs: crate::fs_backend::HostFsReexecAuthority,
    pub(crate) cwd: String,
    pub(crate) stream_stdio: bool,
    pub(crate) exec_host_fs_fallback: bool,
    pub(crate) max_traps: u64,
    pub(crate) native_page_profile: carrick_spec::NativePageProfileRequest,
    #[serde(deserialize_with = "deserialize_present_live_arena")]
    pub(crate) live_arena: Option<NativeReexecLiveArenaV1>,
    #[serde(default)]
    pub(crate) kernel_arena: Option<NativeReexecKernelArenaV1>,
    #[serde(default)]
    pub(crate) shared_futex_waiters: Option<NativeReexecWaiterTableV1>,
    #[serde(default)]
    pub(crate) artifact_spike: Option<NativeReexecArtifactSpikeV1>,
    #[serde(default)]
    pub(crate) aot_cache: Option<NativeReexecAotCacheV1>,
    #[serde(default)]
    pub(crate) bind_mounts: Vec<crate::vfs::bind::NativeReexecBindMountV1>,
    pub(crate) fd_table: crate::dispatch::fd_table::NativeReexecFdTableV1,
    pub(crate) xsig: NativeReexecXsigV1,
    pub(crate) process_state: NativeReexecProcessStateV1,
    pub(crate) prepared_image: Option<crate::native_prepared_image::NativePreparedImageV1>,
    /// The pre-exec image's claimed startup gauge (NATIVEPERF attribution).
    /// The host self-reexec preserves the pid, and one pid publishes exactly
    /// one startup window: the post-exec image republishes this claim
    /// verbatim instead of measuring a second window.
    #[serde(default)]
    pub(crate) profile_startup: Option<NativeReexecProfileStartupV1>,
    /// Bounded identity for the guest image's profiling epoch. The exact site
    /// catalog remains process-local and is never added to this capsule.
    #[serde(default)]
    pub(crate) profile_exec_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecLiveArenaV1 {
    pub(crate) schema: u32,
    pub(crate) code_len: u64,
    pub(crate) control_len: u64,
    pub(crate) nonce: [u8; 16],
}

fn deserialize_present_live_arena<'de, D>(
    deserializer: D,
) -> Result<Option<NativeReexecLiveArenaV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::deserialize(deserializer)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<carrick_native_darwin::live_arena::LiveArenaTransitV1> for NativeReexecLiveArenaV1 {
    fn from(value: carrick_native_darwin::live_arena::LiveArenaTransitV1) -> Self {
        Self {
            schema: value.schema,
            code_len: value.code_len,
            control_len: value.control_len,
            nonce: value.nonce,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<NativeReexecLiveArenaV1> for carrick_native_darwin::live_arena::LiveArenaTransitV1 {
    fn from(value: NativeReexecLiveArenaV1) -> Self {
        Self {
            schema: value.schema,
            code_len: value.code_len,
            control_len: value.control_len,
            nonce: value.nonce,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecProfileStartupV1 {
    pub(crate) startup_wall_ns: u64,
    pub(crate) startup_cpu_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecKernelArenaV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) host_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecWaiterTableV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) host_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecArtifactSpikeV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) host_size: u64,
    pub(crate) authority_nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecAotCacheV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) path: std::path::PathBuf,
    pub(crate) creator_pid: i32,
    pub(crate) authority_nonce: [u8; 16],
    pub(crate) translator_abi: u32,
}

impl From<carrick_native_darwin::aot_cache::ContainerCacheReexecConfig> for NativeReexecAotCacheV1 {
    fn from(config: carrick_native_darwin::aot_cache::ContainerCacheReexecConfig) -> Self {
        Self {
            host_fd: config.host_fd,
            original_host_fd_flags: config.original_host_fd_flags,
            host_device: config.host_device,
            host_inode: config.host_inode,
            path: config.path,
            creator_pid: config.creator_pid,
            authority_nonce: config.authority_nonce,
            translator_abi: config.translator_abi,
        }
    }
}

impl From<&NativeReexecAotCacheV1>
    for carrick_native_darwin::aot_cache::ContainerCacheReexecConfig
{
    fn from(snapshot: &NativeReexecAotCacheV1) -> Self {
        Self {
            host_fd: snapshot.host_fd,
            original_host_fd_flags: snapshot.original_host_fd_flags,
            host_device: snapshot.host_device,
            host_inode: snapshot.host_inode,
            path: snapshot.path.clone(),
            creator_pid: snapshot.creator_pid,
            authority_nonce: snapshot.authority_nonce,
            translator_abi: snapshot.translator_abi,
        }
    }
}

// The artifact-spike authority itself moved to `carrick-dsr-aarch64`, which
// speaks the plain `ArtifactSpikeReexecConfig` carrier; the V1 capsule
// schema stays here (it is the serialized re-exec wire format). These two
// mappings are the ONLY place the pairing is spelled out.
impl From<carrick_dsr_aarch64::artifact_spike::ArtifactSpikeReexecConfig>
    for NativeReexecArtifactSpikeV1
{
    fn from(config: carrick_dsr_aarch64::artifact_spike::ArtifactSpikeReexecConfig) -> Self {
        Self {
            host_fd: config.host_fd,
            original_host_fd_flags: config.original_host_fd_flags,
            host_device: config.host_device,
            host_inode: config.host_inode,
            host_size: config.host_size,
            authority_nonce: config.authority_nonce,
        }
    }
}

impl From<&NativeReexecArtifactSpikeV1>
    for carrick_dsr_aarch64::artifact_spike::ArtifactSpikeReexecConfig
{
    fn from(snapshot: &NativeReexecArtifactSpikeV1) -> Self {
        Self {
            host_fd: snapshot.host_fd,
            original_host_fd_flags: snapshot.original_host_fd_flags,
            host_device: snapshot.host_device,
            host_inode: snapshot.host_inode,
            host_size: snapshot.host_size,
            authority_nonce: snapshot.authority_nonce,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecXsigV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) host_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecProcessStateV1 {
    pub(crate) credentials: NativeReexecCredentialsV1,
    pub(crate) supplementary_groups_override: Option<Vec<u32>>,
    pub(crate) ignored_signals: u64,
    pub(crate) nofile_soft: u64,
    pub(crate) rlimit_overrides: Vec<Option<NativeReexecRlimitV1>>,
    #[serde(default = "native_reexec_unconfined_seccomp_policy")]
    pub(crate) seccomp_policy: carrick_spec::SeccompPolicy,
    #[serde(default)]
    pub(crate) ptrace_traceme: bool,
}

fn native_reexec_unconfined_seccomp_policy() -> carrick_spec::SeccompPolicy {
    // Prior V1 capsules did not carry launch policy. Preserve their historical
    // decode meaning instead of silently enabling the container default.
    carrick_spec::SeccompPolicy::Unconfined
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecCredentialsV1 {
    pub(crate) ruid: u32,
    pub(crate) euid: u32,
    pub(crate) suid: u32,
    pub(crate) rgid: u32,
    pub(crate) egid: u32,
    pub(crate) sgid: u32,
    pub(crate) fsuid: u32,
    pub(crate) fsgid: u32,
    pub(crate) umask: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecRlimitV1 {
    pub(crate) current: u64,
    pub(crate) maximum: u64,
}

impl NativeExecCapsuleV1 {
    fn validate(&self) -> Result<(), NativeExecCapsuleError> {
        if self.host_executable_path.is_empty() || self.host_executable_path.len() > MAX_PATH_LEN {
            return Err(NativeExecCapsuleError::InvalidField("host_executable_path"));
        }
        validate_byte_vector("argv", &self.argv)?;
        validate_byte_vector("env", &self.env)?;
        match (self.purpose, &self.guest_exec) {
            (NativeExecCapsulePurposeV1::PidProbe, None) => {}
            (NativeExecCapsulePurposeV1::GuestExec, Some(guest)) => guest.validate()?,
            _ => return Err(NativeExecCapsuleError::InvalidField("purpose")),
        }
        Ok(())
    }
}

impl NativeGuestExecV1 {
    fn validate(&self) -> Result<(), NativeExecCapsuleError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let live_arena_invalid = self.live_arena.is_some_and(|arena| {
            arena.schema != 1 || arena.code_len == 0 || arena.control_len == 0
        });
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let live_arena_invalid = self.live_arena.is_some();
        if self.resolved_path.is_empty()
            || self.resolved_path.len() > MAX_PATH_LEN
            || self.cwd.is_empty()
            || self.cwd.len() > MAX_PATH_LEN
            || self.rootfs.root_path.is_empty()
            || self.rootfs.root_path.len() > MAX_PATH_LEN
            || self.max_traps == 0
            || live_arena_invalid
            || self.kernel_arena.is_some_and(|arena| {
                arena.host_fd < 0
                    || arena.host_size
                        != std::mem::size_of::<carrick_kernel::arena::ArenaLayout>() as u64
            })
            || self
                .shared_futex_waiters
                .is_some_and(|waiters| waiters.host_fd < 0 || waiters.host_size == 0)
            || self
                .artifact_spike
                .is_some_and(|artifact| artifact.host_fd < 0 || artifact.host_size == 0)
            || self.aot_cache.as_ref().is_some_and(|cache| {
                cache.host_fd < 0
                    || cache.creator_pid <= 0
                    || cache.path.as_os_str().is_empty()
                    || cache.path.as_os_str().as_bytes().len() > MAX_PATH_LEN
                    || !cache.path.is_absolute()
                    || cache.translator_abi
                        != carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT
            })
            || (self.process_state.ptrace_traceme && self.kernel_arena.is_none())
            || self.bind_mounts.len() > MAX_VECTOR_ITEMS
            || self.fd_table.files.len() > MAX_VECTOR_ITEMS
            || self.fd_table.descriptions.len() > MAX_VECTOR_ITEMS
            || self.fd_table.close_on_exec_host_fds.len() > MAX_VECTOR_ITEMS
            || self.xsig.host_fd < 0
            || self
                .process_state
                .supplementary_groups_override
                .as_ref()
                .is_some_and(|groups| groups.len() > 65_536)
            || self.process_state.credentials.umask & !0o777 != 0
            || self.process_state.rlimit_overrides.len() != 16
        {
            return Err(NativeExecCapsuleError::InvalidField("guest_exec"));
        }
        let mut mount_points = std::collections::HashSet::new();
        for mount in &self.bind_mounts {
            if mount.mount_point.is_empty()
                || mount.mount_point.len() > MAX_PATH_LEN
                || !std::path::Path::new(&mount.mount_point).is_absolute()
                || mount.host_path.as_os_str().is_empty()
                || mount.host_path.as_os_str().as_bytes().len() > MAX_PATH_LEN
                || !mount.host_path.is_absolute()
                || !mount_points.insert(mount.mount_point.as_str())
            {
                return Err(NativeExecCapsuleError::InvalidField("bind_mounts"));
            }
        }
        Ok(())
    }
}

pub(crate) fn begin_pid_probe() -> anyhow::Result<()> {
    let executable = std::env::current_exe()?;
    let executable_bytes = executable.as_os_str().as_bytes().to_vec();
    let producer_pid = unsafe { libc::getpid() as u32 };
    let payload = NativeExecCapsuleV1 {
        producer_pid,
        purpose: NativeExecCapsulePurposeV1::PidProbe,
        host_executable_path: executable_bytes,
        argv: Vec::new(),
        env: Vec::new(),
        guest_exec: None,
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("generate native exec capsule nonce: {error}"))?;
    exec_capsule(payload, nonce, None, None)
}

// This function's only caller is `native_darwin.rs`, which is itself gated
// to `cfg(target_os = "macos", target_arch = "aarch64")` (its own lane) —
// see `lib.rs`'s module-decl comment. Gated the same way so it doesn't
// become a newly-dead cross-reference (an unconditional call into a module
// that no longer exists off that lane) when built elsewhere.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_guest_exec(
    dispatcher: &crate::dispatch::SyscallDispatcher,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    exec_backing: Option<crate::native_prepared_image::PreparedExecutableBacking>,
    resolved_path: String,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    executable_digest: [u8; 32],
    max_traps: usize,
    plan: &crate::page_profile::ExecutionPlan,
    live_arena: NativeLiveArenaAuthority<'_>,
) -> anyhow::Result<()> {
    emit_lifecycle(
        unsafe { libc::getpid() },
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecCapsulePrepareBegin,
    );
    crate::exec_stamps::stamp(crate::exec_stamps::ExecStampPhase::CapsulePrepare);
    let executable = std::env::current_exe()?;
    let native_page_profile = match plan.page_geometry.native_profile {
        Some(carrick_spec::NativePageProfile::Native16k) => {
            carrick_spec::NativePageProfileRequest::Native16k
        }
        Some(carrick_spec::NativePageProfile::Linux4kOn16k) => {
            carrick_spec::NativePageProfileRequest::Linux4k
        }
        None => anyhow::bail!("native guest exec has no native page profile"),
    };
    let rootfs = dispatcher
        .native_fs_reexec_authority()
        .map_err(|error| anyhow::anyhow!("native guest exec rootfs is ineligible: {error:?}"))?;
    let fd_table = dispatcher
        .snapshot_native_reexec_fd_table()
        .map_err(|error| anyhow::anyhow!("native guest exec fd table is ineligible: {error}"))?;
    let xsig = snapshot_xsig()?;
    let process_state = dispatcher.snapshot_native_reexec_process_state();
    let bind_mounts = dispatcher.snapshot_native_reexec_bind_mounts();
    let kernel_arena = carrick_kernel::arena::KernelArena::global()
        .reexec_authority()
        .map(|authority| NativeReexecKernelArenaV1 {
            host_fd: authority.fd,
            original_host_fd_flags: authority.original_fd_flags,
            host_device: authority.device,
            host_inode: authority.inode,
            host_size: authority.size,
        })?;
    let shared_futex_waiters = crate::ulock::waiter_table_reexec_authority().map(|authority| {
        NativeReexecWaiterTableV1 {
            host_fd: authority.fd,
            original_host_fd_flags: authority.original_fd_flags,
            host_device: authority.device,
            host_inode: authority.inode,
            host_size: authority.size,
        }
    })?;
    let artifact_spike = crate::native_darwin::artifact_spike_authority_snapshot_if_enabled()?;
    let aot_cache = crate::native_darwin::aot_cache_authority_snapshot()?;
    let mut payload = NativeExecCapsuleV1 {
        producer_pid: unsafe { libc::getpid() as u32 },
        purpose: NativeExecCapsulePurposeV1::GuestExec,
        host_executable_path: executable.as_os_str().as_bytes().to_vec(),
        argv,
        env,
        guest_exec: Some(NativeGuestExecV1 {
            resolved_path,
            executable_digest,
            rootfs,
            cwd: dispatcher.cwd(),
            stream_stdio: dispatcher.stream_stdio_enabled(),
            exec_host_fs_fallback: dispatcher.exec_host_fs_fallback(),
            max_traps: u64::try_from(max_traps)?,
            native_page_profile,
            live_arena: live_arena.map(|arena| arena.transit_v1().into()),
            kernel_arena: Some(kernel_arena),
            shared_futex_waiters: Some(shared_futex_waiters),
            artifact_spike,
            aot_cache,
            bind_mounts,
            fd_table,
            xsig,
            process_state,
            prepared_image: None,
            profile_startup: crate::native_darwin::claimed_native_process_startup().map(
                |(startup_wall_ns, startup_cpu_ns)| NativeReexecProfileStartupV1 {
                    startup_wall_ns,
                    startup_cpu_ns,
                },
            ),
            profile_exec_epoch: crate::native_darwin::next_native_profile_exec_epoch_for_reexec(),
        }),
    };
    let prepared_artifact = attach_prepared_image(
        &mut payload,
        image,
        relative_relocations,
        exec_backing,
        plan.page_geometry.host_page_size,
    );
    // Pay for the digest only if the guard that reads it will actually run.
    //
    // The child compares digests ONLY on the legacy resume path, i.e. when no
    // prepared image is attached; with one attached it validates that artifact's
    // checksum instead and never looks at this field. The parent could not know
    // which case it was in at load time, so it hashed unconditionally - a full
    // walk of a ~20 MB binary on all ~61 execs of a cold `go build`, and 6.99%
    // of all CPU. By here the answer is known, so hash exactly when it matters.
    //
    // This does NOT weaken the guard: on the legacy path both sides now compute
    // a real digest, exactly as before. `ExecDigestPolicy::Required` covers the
    // child, and an armed consumer (shared translation, artifact spike, census)
    // still forces the eager hash because those mint an identity from it.
    if let Some(guest) = payload.guest_exec.as_mut()
        && guest.prepared_image.is_none()
        && guest.executable_digest == crate::native_darwin::DEFERRED_EXEC_DIGEST
    {
        guest.executable_digest =
            crate::native_darwin::exec_file_digest(dispatcher, &guest.resolved_path).ok_or_else(
                || anyhow::anyhow!("hash guest executable for legacy self-reexec resume"),
            )?;
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("generate native exec capsule nonce: {error}"))?;
    exec_capsule(payload, nonce, prepared_artifact, live_arena)
}

// This whole cluster (the failpoint enum, `attach_prepared_image`, and
// `attach_prepared_image_inner`) is reached in production only from
// `begin_guest_exec` (lane-gated to macOS/aarch64); this crate's own
// `#[cfg(test)]` fixtures (`attach_prepared_image_with_failpoint` and the
// direct `attach_prepared_image` calls in `mod tests`) exercise it on every
// host, hence the `test` arm.
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedImageFailpoint {
    #[cfg(test)]
    Ineligible,
    #[cfg(test)]
    ArtifactCreation,
    #[cfg(test)]
    PreExecValidation,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn attach_prepared_image(
    payload: &mut NativeExecCapsuleV1,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    exec_backing: Option<crate::native_prepared_image::PreparedExecutableBacking>,
    host_page_size: u64,
) -> Option<crate::native_prepared_image::PreparedImageArtifact> {
    attach_prepared_image_inner(
        payload,
        image,
        relative_relocations,
        exec_backing,
        host_page_size,
        None,
    )
}

#[cfg(test)]
fn attach_prepared_image_with_failpoint(
    payload: &mut NativeExecCapsuleV1,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    host_page_size: u64,
    failpoint: PreparedImageFailpoint,
) -> Option<crate::native_prepared_image::PreparedImageArtifact> {
    attach_prepared_image_inner(
        payload,
        image,
        relative_relocations,
        None,
        host_page_size,
        Some(failpoint),
    )
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn attach_prepared_image_inner(
    payload: &mut NativeExecCapsuleV1,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    exec_backing: Option<crate::native_prepared_image::PreparedExecutableBacking>,
    host_page_size: u64,
    failpoint: Option<PreparedImageFailpoint>,
) -> Option<crate::native_prepared_image::PreparedImageArtifact> {
    #[cfg(not(test))]
    let _ = failpoint;
    emit_lifecycle(
        unsafe { libc::getpid() },
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedBuildBegin,
    );
    #[cfg(test)]
    if failpoint == Some(PreparedImageFailpoint::ArtifactCreation) {
        tracing::warn!(
            error = "test artifact creation failpoint",
            "native prepared image construction failed; using legacy self-reexec reload"
        );
        return None;
    }
    #[cfg(test)]
    let preparation = if failpoint == Some(PreparedImageFailpoint::Ineligible) {
        Ok(
            crate::native_prepared_image::PreparedImageDisposition::Ineligible(
                crate::native_prepared_image::PreparedImageIneligibleReason::SharedRegion {
                    index: 0,
                },
            ),
        )
    } else {
        crate::native_prepared_image::prepare(
            image,
            relative_relocations,
            host_page_size,
            exec_backing,
        )
    };
    #[cfg(not(test))]
    let preparation = crate::native_prepared_image::prepare(
        image,
        relative_relocations,
        host_page_size,
        exec_backing,
    );
    let disposition = match preparation {
        Ok(disposition) => disposition,
        Err(error) => {
            tracing::warn!(
                %error,
                "native prepared image construction failed; using legacy self-reexec reload"
            );
            return None;
        }
    };
    emit_lifecycle(
        unsafe { libc::getpid() },
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedBuildEnd,
    );
    let artifact = match disposition {
        crate::native_prepared_image::PreparedImageDisposition::Prepared(artifact) => *artifact,
        crate::native_prepared_image::PreparedImageDisposition::Ineligible(reason) => {
            tracing::debug!(
                ?reason,
                "native prepared image is ineligible; using legacy self-reexec reload"
            );
            return None;
        }
    };
    #[cfg(test)]
    if failpoint == Some(PreparedImageFailpoint::PreExecValidation) {
        let artifact_fd = artifact.file.as_raw_fd();
        let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
        let identity_ok = unsafe { libc::fstat(artifact_fd, identity.as_mut_ptr()) } == 0;
        let identity = identity_ok.then(|| unsafe { identity.assume_init() });
        tracing::warn!(
            error = "test pre-exec validation failpoint",
            "native prepared image self-validation failed; using legacy self-reexec reload"
        );
        drop(artifact);
        let artifact_was_closed = identity.is_some_and(|identity| {
            fd_no_longer_refers_to(artifact_fd, identity.st_dev as u64, identity.st_ino)
        });
        LAST_PREEXEC_VALIDATION_ARTIFACT
            .with(|captured| captured.set(Some((artifact_fd, artifact_was_closed))));
        return None;
    }
    let Some(guest) = payload.guest_exec.as_mut() else {
        tracing::warn!(
            "native prepared image has no guest capsule owner; using legacy self-reexec reload"
        );
        return None;
    };
    tracing::debug!(
        executable_file_backed = artifact.record.maps_from_executable_file(),
        "native prepared image attached to exec capsule"
    );
    guest.prepared_image = Some(artifact.record.clone());
    Some(artifact)
}

fn exec_capsule(
    payload: NativeExecCapsuleV1,
    nonce: [u8; 16],
    prepared_artifact: Option<crate::native_prepared_image::PreparedImageArtifact>,
    live_arena: NativeLiveArenaAuthority<'_>,
) -> anyhow::Result<()> {
    exec_capsule_with(
        payload,
        nonce,
        prepared_artifact,
        live_arena,
        |request, registered_ports| {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if let Some(registered_ports) = registered_ports {
                return unsafe {
                    registered_ports.replace_process(
                        request.executable.as_ptr(),
                        request.argv.as_ptr().cast_mut().cast(),
                        request.env.as_ptr().cast_mut().cast(),
                    )
                };
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            let _ = registered_ports;
            unsafe {
                libc::execve(
                    request.executable.as_ptr(),
                    request.argv.as_ptr(),
                    request.env.as_ptr(),
                );
            }
            std::io::Error::last_os_error()
        },
    )
}

struct HostExecRequest<'a> {
    executable: &'a CStr,
    argv: &'a [*const libc::c_char],
    env: &'a [*const libc::c_char],
    #[cfg(test)]
    capsule_fd: RawFd,
}

fn exec_capsule_with<F>(
    payload: NativeExecCapsuleV1,
    nonce: [u8; 16],
    prepared_artifact: Option<crate::native_prepared_image::PreparedImageArtifact>,
    live_arena: NativeLiveArenaAuthority<'_>,
    invoke_exec: F,
) -> anyhow::Result<()>
where
    F: FnOnce(HostExecRequest<'_>, Option<&NativeRegisteredPortExecPlan>) -> std::io::Error,
{
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let payload_live_arena = payload
            .guest_exec
            .as_ref()
            .and_then(|guest| guest.live_arena);
        let owned_live_arena =
            live_arena.map(|arena| NativeReexecLiveArenaV1::from(arena.transit_v1()));
        if payload_live_arena != owned_live_arena {
            anyhow::bail!("native live arena capsule metadata has no matching authority owner");
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let _ = live_arena;
    #[cfg(feature = "alloc-owner-census")]
    let next_allocation_exec_epoch = payload
        .guest_exec
        .as_ref()
        .map(|guest| guest.profile_exec_epoch);
    let payload_prepared_record = payload
        .guest_exec
        .as_ref()
        .and_then(|guest| guest.prepared_image.as_ref());
    let owned_prepared_record = prepared_artifact.as_ref().map(|artifact| &artifact.record);
    if payload_prepared_record != owned_prepared_record {
        anyhow::bail!("native prepared image capsule record has no matching fd owner");
    }
    let capsule = tempfile::tempfile()?;
    write_capsule(capsule.as_raw_fd(), nonce, &payload)?;

    let nonce_hex = encode_nonce(nonce);
    let fd_arg = capsule.as_raw_fd().to_string();
    let executable_c = CString::new(payload.host_executable_path.clone())?;
    let argv = [
        executable_c.clone(),
        CString::new("__native-exec-resume")?,
        CString::new("--capsule-fd")?,
        CString::new(fd_arg)?,
        CString::new("--nonce")?,
        CString::new(nonce_hex)?,
    ];
    let argv_ptrs = argv
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let env = std::env::vars_os()
        .filter(|(key, _)| {
            #[cfg(feature = "alloc-owner-census")]
            {
                key.as_os_str().as_bytes()
                    != carrick_dsr_aarch64::alloc_owner_census::EXEC_EPOCH_ENV.as_bytes()
            }
            #[cfg(not(feature = "alloc-owner-census"))]
            {
                let _ = key;
                true
            }
        })
        .map(|(key, value)| {
            let mut entry = key.as_os_str().as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(entry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let base_env_ptrs = env
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    #[cfg(not(feature = "alloc-owner-census"))]
    let env_ptrs = base_env_ptrs;
    #[cfg(feature = "alloc-owner-census")]
    let (env_ptrs, _allocation_exec_epoch_entry) = {
        let mut env_ptrs = base_env_ptrs;
        let entry = if let Some(next_exec_epoch) = next_allocation_exec_epoch {
            let _observer = carrick_dsr_aarch64::alloc_owner_census::observer_pause();
            let entry = CString::new(format!(
                "{}={next_exec_epoch}",
                carrick_dsr_aarch64::alloc_owner_census::EXEC_EPOCH_ENV
            ))?;
            let Some(null) = env_ptrs.pop() else {
                anyhow::bail!("host environment pointer vector has no terminator");
            };
            if !null.is_null() {
                anyhow::bail!("host environment pointer vector has an invalid terminator");
            }
            env_ptrs.reserve(1);
            env_ptrs.push(entry.as_ptr());
            env_ptrs.push(std::ptr::null());
            Some(entry)
        } else {
            None
        };
        (env_ptrs, entry)
    };

    let mut prepared_host_fds = HostFdFlagTransaction::default();
    if let Some(guest) = &payload.guest_exec {
        if let Some(arena) = guest.kernel_arena {
            prepared_host_fds.prepare(
                arena.host_fd,
                arena.original_host_fd_flags,
                arena.original_host_fd_flags & !libc::FD_CLOEXEC,
            )?;
        }
        if let Some(waiters) = guest.shared_futex_waiters {
            prepared_host_fds.prepare(
                waiters.host_fd,
                waiters.original_host_fd_flags,
                waiters.original_host_fd_flags & !libc::FD_CLOEXEC,
            )?;
        }
        if let Some(artifact) = guest.artifact_spike {
            prepared_host_fds.prepare(
                artifact.host_fd,
                artifact.original_host_fd_flags,
                artifact.original_host_fd_flags & !libc::FD_CLOEXEC,
            )?;
        }
        if let Some(cache) = &guest.aot_cache {
            prepared_host_fds.prepare(
                cache.host_fd,
                cache.original_host_fd_flags,
                cache.original_host_fd_flags & !libc::FD_CLOEXEC,
            )?;
        }
        prepared_host_fds.prepare(
            guest.xsig.host_fd,
            guest.xsig.original_host_fd_flags,
            guest.xsig.original_host_fd_flags & !libc::FD_CLOEXEC,
        )?;
        for (fd, expected_flags) in guest.fd_table.survivor_host_fds() {
            prepared_host_fds.prepare(fd, expected_flags, expected_flags & !libc::FD_CLOEXEC)?;
        }
        for fd in &guest.fd_table.close_on_exec_host_fds {
            let flags = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
            if flags < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            prepared_host_fds.prepare(*fd, flags, flags | libc::FD_CLOEXEC)?;
        }
    }

    let old_flags = unsafe { libc::fcntl(capsule.as_raw_fd(), libc::F_GETFD) };
    if old_flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    prepared_host_fds.prepare(
        capsule.as_raw_fd(),
        old_flags,
        old_flags & !libc::FD_CLOEXEC,
    )?;
    if let Some(artifact) = &prepared_artifact {
        let (fd, flags) = artifact.transport_fd_snapshot();
        prepared_host_fds.prepare(fd, flags, flags & !libc::FD_CLOEXEC)?;
        // The guest-executable fd (when regions map from it) crosses the
        // execve exactly like the artifact fd: clear CLOEXEC for transit;
        // the resumed process re-checks identity + flags and re-closes it.
        if let Some((exec_fd, exec_flags)) = artifact.transport_executable_fd_snapshot() {
            prepared_host_fds.prepare(exec_fd, exec_flags, exec_flags & !libc::FD_CLOEXEC)?;
        }
    }

    emit_lifecycle(
        unsafe { libc::getpid() },
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecBegin,
    );
    crate::exec_stamps::stamp(crate::exec_stamps::ExecStampPhase::PreExec);
    #[cfg(feature = "alloc-owner-census")]
    let _allocation_attempt = next_allocation_exec_epoch
        .map(carrick_dsr_aarch64::alloc_owner_census::begin_host_exec_attempt)
        .transpose()?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let registered_ports = live_arena
        .map(carrick_native_darwin::live_arena::RegisteredPortExecPlan::install)
        .transpose()?;
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let registered_ports: Option<NativeRegisteredPortExecPlan> = None;
    let exec_error = invoke_exec(
        HostExecRequest {
            executable: &executable_c,
            argv: &argv_ptrs,
            env: &env_ptrs,
            #[cfg(test)]
            capsule_fd: capsule.as_raw_fd(),
        },
        registered_ports.as_ref(),
    );
    Err(exec_error.into())
}

#[derive(Default)]
struct HostFdFlagTransaction {
    prepared: Vec<(RawFd, i32)>,
}

impl HostFdFlagTransaction {
    fn prepare(
        &mut self,
        fd: RawFd,
        expected_flags: i32,
        desired_flags: i32,
    ) -> anyhow::Result<()> {
        prepare_host_fd_flags(fd, expected_flags, desired_flags, &mut self.prepared)
    }
}

impl Drop for HostFdFlagTransaction {
    fn drop(&mut self) {
        restore_host_fd_flags(&self.prepared);
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_ARTIFACT_FD_FLAG_PREPARATION: std::cell::Cell<Option<RawFd>> = const {
        std::cell::Cell::new(None)
    };
    static LAST_PREEXEC_VALIDATION_ARTIFACT: std::cell::Cell<Option<(RawFd, bool)>> = const {
        std::cell::Cell::new(None)
    };
    static NATIVE_EXEC_CAPSULE_LIFECYCLE_CAPTURE:
        std::cell::RefCell<Option<Vec<crate::probes::DsrCacheLifecyclePhase>>> = const {
            std::cell::RefCell::new(None)
        };
}

#[cfg(test)]
fn set_native_exec_capsule_lifecycle_capture(enabled: bool) {
    NATIVE_EXEC_CAPSULE_LIFECYCLE_CAPTURE.with(|slot| {
        *slot.borrow_mut() = enabled.then(Vec::new);
    });
}

#[cfg(test)]
fn take_native_exec_capsule_lifecycle_capture() -> Vec<crate::probes::DsrCacheLifecyclePhase> {
    NATIVE_EXEC_CAPSULE_LIFECYCLE_CAPTURE.with(|slot| slot.borrow_mut().take().unwrap_or_default())
}

#[cfg(test)]
fn fail_next_artifact_fd_flag_preparation(fd: RawFd) {
    FAIL_ARTIFACT_FD_FLAG_PREPARATION.with(|failpoint| failpoint.set(Some(fd)));
}

#[cfg(test)]
fn take_last_preexec_validation_artifact() -> Option<(RawFd, bool)> {
    LAST_PREEXEC_VALIDATION_ARTIFACT.with(std::cell::Cell::take)
}

#[cfg(test)]
fn fd_no_longer_refers_to(fd: RawFd, expected_device: u64, expected_inode: u64) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return true;
    }
    let stat = unsafe { stat.assume_init() };
    stat.st_dev as u64 != expected_device || stat.st_ino != expected_inode
}

fn prepare_host_fd_flags(
    fd: i32,
    expected_flags: i32,
    desired_flags: i32,
    prepared: &mut Vec<(i32, i32)>,
) -> anyhow::Result<()> {
    #[cfg(test)]
    if FAIL_ARTIFACT_FD_FLAG_PREPARATION.with(|failpoint| {
        if failpoint.get() == Some(fd) {
            failpoint.take();
            true
        } else {
            false
        }
    }) {
        anyhow::bail!("test artifact fd flag preparation failpoint for fd {fd}");
    }
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if current != expected_flags {
        anyhow::bail!("native reexec host fd {fd} flags changed during preparation");
    }
    if current != desired_flags {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, desired_flags) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        prepared.push((fd, current));
    }
    Ok(())
}

fn restore_host_fd_flags(prepared: &[(i32, i32)]) {
    for (fd, flags) in prepared.iter().rev() {
        unsafe {
            libc::fcntl(*fd, libc::F_SETFD, *flags);
        }
    }
}

pub(crate) fn resume(fd: RawFd, nonce_hex: &str) -> anyhow::Result<crate::NativeSelfReexecOutcome> {
    crate::exec_stamps::stamp(crate::exec_stamps::ExecStampPhase::ResumeEntry);
    let current_pid = unsafe { libc::getpid() };
    emit_lifecycle(
        current_pid,
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecEnd,
    );
    emit_lifecycle(
        current_pid,
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecCapsuleBegin,
    );
    let nonce = decode_nonce(nonce_hex)?;
    let payload = read_capsule_once(fd, nonce)?;
    let current_pid = current_pid as u32;
    if payload.producer_pid != current_pid {
        anyhow::bail!(
            "native self-reexec changed PID from {} to {}",
            payload.producer_pid,
            current_pid
        );
    }
    let current_executable = std::env::current_exe()?;
    if current_executable.as_os_str().as_bytes() != payload.host_executable_path {
        anyhow::bail!("native self-reexec resumed through a different executable");
    }
    unsafe {
        libc::close(fd);
    }
    // Re-stamp the scoped-cleanup proctitle. The self-reexec REPLACED this
    // process image, and an `execve` resets the title: `ps` shows the raw
    // `carrick __native-exec-resume --capsule-fd N --nonce …` argv, which
    // carries neither the `carrick:<run-id>:` title nor `--name <run-id>`. Both
    // scoped reapers — `scripts/sudo/kill.sh` and the conformance engine's
    // `kill_scoped` — match ONLY that title, so every resumed guest was
    // invisible to cleanup and leaked: 27 survived a single 1175-suite
    // conformance run, reparented to init and still alive 26 minutes later.
    // Leaked guests then drive box load up and spuriously TIMEOUT *other*
    // concurrent suites, which is precisely the failure engine.rs's own comment
    // warns about ("turning a clean ~33 CRASH_TIMEOUT baseline into 160+") and
    // is what made a healthy `kill10` time out at ~suite 1000 while being
    // unreproducible under five controlled pressure models.
    //
    // `run_id()` inside the setter reads `CARRICK_RUN_ID`, which survives the
    // execve in the inherited environment (the capsule exec copies
    // `std::env::vars_os`), so the id is still available here.
    {
        let name_bytes: &[u8] = payload
            .argv
            .first()
            .map(Vec::as_slice)
            .filter(|argv0| !argv0.is_empty())
            .unwrap_or(payload.host_executable_path.as_slice());
        // Basename only: the title's job is to be greppable, not to reproduce a
        // full path in a fixed-width argv buffer.
        let basename = name_bytes
            .rsplit(|&b| b == b'/')
            .next()
            .unwrap_or(name_bytes);
        crate::dispatch::set_host_process_name(basename);
    }
    emit_lifecycle(
        current_pid as i32,
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecCapsuleEnd,
    );
    match payload.purpose {
        NativeExecCapsulePurposeV1::PidProbe => Ok(crate::NativeSelfReexecOutcome::PidProbe {
            before: payload.producer_pid,
            after: current_pid,
        }),
        // Only `native_darwin.rs`'s `begin_guest_exec` ever produces a
        // `GuestExec`-purpose capsule (its only caller, gated to
        // `cfg(target_os = "macos", target_arch = "aarch64")` — see
        // `lib.rs`'s module-decl comment), so this arm's `native_darwin::`
        // calls are gated the same way rather than left as newly-dead
        // cross-references off that lane.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        NativeExecCapsulePurposeV1::GuestExec => {
            let guest = payload
                .guest_exec
                .ok_or_else(|| anyhow::anyhow!("native guest exec capsule has no guest state"))?;
            let live_arena =
                carrick_native_darwin::live_arena::DarwinLiveArena::adopt_optional_registered(
                    guest.live_arena.map(Into::into),
                )?;
            if let Some(artifact) = &guest.artifact_spike {
                crate::native_darwin::adopt_artifact_spike_for_resume(artifact)?;
            }
            if let Some(cache) = &guest.aot_cache {
                crate::native_darwin::adopt_aot_cache_for_resume(cache)?;
            }
            adopt_xsig(&guest.xsig)?;
            emit_lifecycle(
                current_pid as i32,
                crate::probes::DsrCacheLifecyclePhase::HostSelfReexecRestoreBegin,
            );
            let exit_code = crate::native_darwin::resume_guest_from_capsule(
                guest,
                payload.argv,
                payload.env,
                live_arena,
            )?;
            Ok(crate::NativeSelfReexecOutcome::GuestExit(exit_code))
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        NativeExecCapsulePurposeV1::GuestExec => {
            anyhow::bail!(
                "native guest-exec self-reexec resume is only wired on macOS/aarch64 \
                 (the only lane that ever produces a GuestExec-purpose capsule)"
            )
        }
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn native_exec_live_arena_resume_hook(
    arena: Option<&carrick_native_darwin::live_arena::DarwinLiveArena>,
) -> anyhow::Result<Option<i32>> {
    tests::native_exec_live_arena::resume_hook(arena)
}

fn emit_lifecycle(tid: i32, phase: crate::probes::DsrCacheLifecyclePhase) {
    #[cfg(test)]
    NATIVE_EXEC_CAPSULE_LIFECYCLE_CAPTURE.with(|slot| {
        if let Some(phases) = slot.borrow_mut().as_mut() {
            phases.push(phase);
        }
    });
    crate::probes::dsr_cache_lifecycle(tid, phase, 0, 0, 0);
}

// Called only from `begin_guest_exec` (lane-gated to macOS/aarch64); no
// test exercises the real xsig-ring transport directly.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn snapshot_xsig() -> anyhow::Result<NativeReexecXsigV1> {
    let host_fd = carrick_signal_core::xsig::xsig_reexec_fd()
        .ok_or_else(|| anyhow::anyhow!("native guest exec has no xsignal ring backing fd"))?;
    let original_host_fd_flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
    if original_host_fd_flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    Ok(NativeReexecXsigV1 {
        host_fd,
        original_host_fd_flags,
        host_device: stat.st_dev as u64,
        host_inode: stat.st_ino,
        host_size: stat.st_size as u64,
    })
}

// Called only from `resume()`'s `GuestExec` arm (lane-gated to
// macOS/aarch64, since that's the only capsule purpose that ever carries a
// real xsig snapshot).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn adopt_xsig(snapshot: &NativeReexecXsigV1) -> anyhow::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(snapshot.host_fd, stat.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_dev as u64 != snapshot.host_device
        || stat.st_ino != snapshot.host_inode
        || stat.st_size as u64 != snapshot.host_size
    {
        anyhow::bail!("native xsignal ring backing identity changed across self-reexec");
    }
    if unsafe {
        libc::fcntl(
            snapshot.host_fd,
            libc::F_SETFD,
            snapshot.original_host_fd_flags,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if !carrick_signal_core::xsig::xsig_adopt_reexec_fd(snapshot.host_fd) {
        anyhow::bail!("native xsignal ring backing could not be adopted after self-reexec");
    }
    Ok(())
}

fn encode_nonce(nonce: [u8; 16]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(32);
    for byte in nonce {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_nonce(encoded: &str) -> anyhow::Result<[u8; 16]> {
    if encoded.len() != 32 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("native exec capsule nonce must contain exactly 32 hex digits");
    }
    let mut nonce = [0_u8; 16];
    for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let digits = std::str::from_utf8(chunk)?;
        nonce[index] = u8::from_str_radix(digits, 16)?;
    }
    Ok(nonce)
}

fn validate_byte_vector(
    field: &'static str,
    values: &[Vec<u8>],
) -> Result<(), NativeExecCapsuleError> {
    if values.len() > MAX_VECTOR_ITEMS || values.iter().any(|value| value.len() > MAX_ITEM_LEN) {
        return Err(NativeExecCapsuleError::InvalidField(field));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeExecCapsuleError {
    #[error("native exec capsule fd is not a regular file")]
    NotRegular,
    #[error("native exec capsule has an invalid or consumed magic value")]
    InvalidMagic,
    #[error("native exec capsule version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("native exec capsule nonce does not match the resume request")]
    NonceMismatch,
    #[error("native exec capsule payload length is invalid")]
    InvalidLength,
    #[error("native exec capsule checksum does not match")]
    ChecksumMismatch,
    #[error("native exec capsule field {0} exceeds its bound")]
    InvalidField(&'static str),
    #[error("native exec capsule payload is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("native exec capsule I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn write_capsule(
    fd: RawFd,
    nonce: [u8; 16],
    payload: &NativeExecCapsuleV1,
) -> Result<(), NativeExecCapsuleError> {
    payload.validate()?;
    let encoded = serde_json::to_vec(payload)?;
    if encoded.len() > MAX_PAYLOAD_LEN {
        return Err(NativeExecCapsuleError::InvalidLength);
    }

    let file = duplicate_regular_file(fd)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| NativeExecCapsuleError::InvalidLength)?;
    let total_len = HEADER_LEN
        .checked_add(encoded.len())
        .ok_or(NativeExecCapsuleError::InvalidLength)?;
    file.set_len(u64::try_from(total_len).map_err(|_| NativeExecCapsuleError::InvalidLength)?)?;

    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(&CAPSULE_MAGIC);
    header[8..10].copy_from_slice(&CAPSULE_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&encoded_len.to_le_bytes());
    header[20..52].copy_from_slice(&Sha256::digest(&encoded));
    header[52..68].copy_from_slice(&nonce);
    write_all_at(&file, &header, 0)?;
    write_all_at(&file, &encoded, HEADER_LEN as u64)?;
    Ok(())
}

pub(crate) fn read_capsule_once(
    fd: RawFd,
    expected_nonce: [u8; 16],
) -> Result<NativeExecCapsuleV1, NativeExecCapsuleError> {
    let file = duplicate_regular_file(fd)?;
    let mut header = [0_u8; HEADER_LEN];
    read_exact_at(&file, &mut header, 0)?;
    if header[..8] != CAPSULE_MAGIC {
        return Err(NativeExecCapsuleError::InvalidMagic);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != CAPSULE_VERSION {
        return Err(NativeExecCapsuleError::UnsupportedVersion(version));
    }
    if header[52..68] != expected_nonce {
        return Err(NativeExecCapsuleError::NonceMismatch);
    }
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| NativeExecCapsuleError::InvalidLength)?,
    );
    let payload_len =
        usize::try_from(payload_len).map_err(|_| NativeExecCapsuleError::InvalidLength)?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(NativeExecCapsuleError::InvalidLength);
    }
    let expected_file_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(NativeExecCapsuleError::InvalidLength)?;
    if file.metadata()?.len()
        != u64::try_from(expected_file_len).map_err(|_| NativeExecCapsuleError::InvalidLength)?
    {
        return Err(NativeExecCapsuleError::InvalidLength);
    }

    let mut encoded = vec![0_u8; payload_len];
    read_exact_at(&file, &mut encoded, HEADER_LEN as u64)?;
    if header[20..52] != Sha256::digest(&encoded)[..] {
        return Err(NativeExecCapsuleError::ChecksumMismatch);
    }
    let payload: NativeExecCapsuleV1 = serde_json::from_slice(&encoded)?;
    payload.validate()?;

    // Invalidate only after the complete payload has passed framing, checksum,
    // schema, and semantic validation. A failed attempt can be diagnosed or
    // retried by the same fresh process, while a successful adoption is one-shot.
    write_all_at(&file, &CONSUMED_MAGIC, 0)?;
    Ok(payload)
}

fn duplicate_regular_file(fd: RawFd) -> Result<std::fs::File, NativeExecCapsuleError> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(duplicated) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(NativeExecCapsuleError::NotRegular);
    }
    Ok(file)
}

fn write_all_at(file: &std::fs::File, mut bytes: &[u8], mut offset: u64) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = file.write_at(bytes, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "native exec capsule write made no progress",
            ));
        }
        bytes = &bytes[written..];
        offset = offset.saturating_add(written as u64);
    }
    Ok(())
}

fn read_exact_at(
    file: &std::fs::File,
    mut bytes: &mut [u8],
    mut offset: u64,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let read = file.read_at(bytes, offset)?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let (_, rest) = bytes.split_at_mut(read);
        bytes = rest;
        offset = offset.saturating_add(read as u64);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::FileExt;

    use super::{
        HEADER_LEN, MAX_ITEM_LEN, NativeExecCapsulePurposeV1, NativeExecCapsuleV1,
        NativeGuestExecV1, PreparedImageFailpoint, attach_prepared_image,
        attach_prepared_image_with_failpoint, exec_capsule_with,
        fail_next_artifact_fd_flag_preparation, fd_no_longer_refers_to, read_capsule_once,
        set_native_exec_capsule_lifecycle_capture, take_last_preexec_validation_artifact,
        take_native_exec_capsule_lifecycle_capture, write_capsule,
    };

    #[cfg(feature = "alloc-owner-census")]
    use carrick_dsr_aarch64::alloc_owner_census::test_support as allocation_census;

    const HOST_PAGE_SIZE: u64 = 16 * 1024;

    /// The prepared-artifact fixtures encode the 16 KiB host page geometry,
    /// and a prepared record is BOUND to the running host's page size by
    /// design (`validate_record` in `carrick_dsr_aarch64::prepared_image`
    /// rejects any record whose `host_page_size` differs from the live
    /// `sysconf` value). On a 4 KiB-page host the fixtures can never
    /// validate; the geometry-bound tests skip rather than fake the kernel's
    /// page size, and run unchanged on any 16 KiB host.
    fn host_page_geometry_matches_fixtures() -> bool {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 == HOST_PAGE_SIZE }
    }

    fn sample() -> NativeExecCapsuleV1 {
        NativeExecCapsuleV1 {
            producer_pid: 42,
            purpose: NativeExecCapsulePurposeV1::GuestExec,
            host_executable_path: b"/bin/probe".to_vec(),
            argv: vec![b"probe".to_vec(), b"stage2".to_vec()],
            env: vec![b"A=B".to_vec()],
            guest_exec: Some(NativeGuestExecV1 {
                resolved_path: "/bin/probe".to_owned(),
                executable_digest: [0x11; 32],
                rootfs: crate::fs_backend::HostFsReexecAuthority {
                    root_path: b"/tmp/root".to_vec(),
                    device: 1,
                    inode: 2,
                    cleanup_on_drop: false,
                },
                cwd: "/".to_owned(),
                stream_stdio: true,
                exec_host_fs_fallback: false,
                max_traps: 100,
                native_page_profile: carrick_spec::NativePageProfileRequest::Native16k,
                live_arena: None,
                kernel_arena: None,
                shared_futex_waiters: None,
                artifact_spike: None,
                aot_cache: None,
                bind_mounts: Vec::new(),
                fd_table: crate::dispatch::fd_table::NativeReexecFdTableV1 {
                    files: Vec::new(),
                    descriptions: Vec::new(),
                    close_on_exec_host_fds: Vec::new(),
                    closed_stdio: [false; 3],
                },
                xsig: super::NativeReexecXsigV1 {
                    host_fd: 7,
                    original_host_fd_flags: libc::FD_CLOEXEC,
                    host_device: 1,
                    host_inode: 2,
                    host_size: 4096,
                },
                process_state: super::NativeReexecProcessStateV1 {
                    credentials: super::NativeReexecCredentialsV1 {
                        ruid: 1,
                        euid: 2,
                        suid: 3,
                        rgid: 4,
                        egid: 5,
                        sgid: 6,
                        fsuid: 7,
                        fsgid: 8,
                        umask: 0o027,
                    },
                    supplementary_groups_override: Some(vec![9, 10]),
                    ignored_signals: 1 << 12,
                    nofile_soft: 1024,
                    rlimit_overrides: vec![None; 16],
                    seccomp_policy: carrick_spec::SeccompPolicy::ContainerDefault,
                    ptrace_traceme: false,
                },
                prepared_image: None,
                profile_startup: Some(super::NativeReexecProfileStartupV1 {
                    startup_wall_ns: 11,
                    startup_cpu_ns: 5,
                }),
                profile_exec_epoch: 7,
            }),
        }
    }

    fn synthetic_elf() -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const EM_AARCH64: u16 = 183;
        const PT_LOAD: u32 = 1;
        const PF_R_X: u32 = 5;
        let mut elf = vec![0_u8; 0x1000];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&PF_R_X.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
        let file_len = elf.len() as u64;
        elf[ph + 32..ph + 40].copy_from_slice(&file_len.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&0x4000_u64.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[0x800..0x810].copy_from_slice(b"capsule-payload!");
        elf
    }

    fn synthetic_image() -> crate::memory::AddressSpace {
        crate::memory::AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
            &synthetic_elf(),
            &|_| None,
            0x400000,
            HOST_PAGE_SIZE,
        )
        .expect("load synthetic executable")
        .with_linux_initial_stack_page_size(
            [b"prepared-capsule".as_slice()],
            [b"MODE=test".as_slice()],
            HOST_PAGE_SIZE,
        )
        .expect("build synthetic stack")
    }

    fn set_fd_flags(fd: RawFd, flags: i32) {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags) }, 0);
    }

    fn fd_flags(fd: RawFd) -> i32 {
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    fn host_identity(fd: RawFd) -> libc::stat {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
        unsafe { stat.assume_init() }
    }

    fn install_transport_fds(
        payload: &mut NativeExecCapsuleV1,
        xsig: &std::fs::File,
        survivor: &std::fs::File,
        close_on_exec: &std::fs::File,
    ) {
        use crate::dispatch::fd_table::{NativeReexecDescriptionV1, NativeReexecFdV1};

        set_fd_flags(xsig.as_raw_fd(), libc::FD_CLOEXEC);
        set_fd_flags(survivor.as_raw_fd(), libc::FD_CLOEXEC);
        set_fd_flags(close_on_exec.as_raw_fd(), 0);
        let xsig_stat = host_identity(xsig.as_raw_fd());
        let survivor_stat = host_identity(survivor.as_raw_fd());
        let guest = payload.guest_exec.as_mut().expect("guest payload");
        guest.xsig = super::NativeReexecXsigV1 {
            host_fd: xsig.as_raw_fd(),
            original_host_fd_flags: libc::FD_CLOEXEC,
            host_device: xsig_stat.st_dev as u64,
            host_inode: xsig_stat.st_ino,
            host_size: xsig_stat.st_size as u64,
        };
        guest.fd_table.files = vec![NativeReexecFdV1 {
            guest_fd: 9,
            fd_flags: 0,
            description_id: 0,
        }];
        guest.fd_table.descriptions = vec![NativeReexecDescriptionV1::File {
            host_fd: survivor.as_raw_fd(),
            original_host_fd_flags: libc::FD_CLOEXEC,
            host_device: survivor_stat.st_dev as u64,
            host_inode: survivor_stat.st_ino,
            host_mode: survivor_stat.st_mode as u32,
            status_flags: 0,
            guest_path: b"/tmp/survivor".to_vec(),
            guest_mode: 0o600,
            guest_size: survivor_stat.st_size as u64,
            writable: false,
        }];
        guest.fd_table.close_on_exec_host_fds = vec![close_on_exec.as_raw_fd()];
    }

    #[test]
    fn prepared_record_round_trips_without_embedding_payload_bytes() {
        if !host_page_geometry_matches_fixtures() {
            return;
        }
        let mut payload = sample();
        let artifact =
            attach_prepared_image(&mut payload, &synthetic_image(), &[], None, HOST_PAGE_SIZE)
                .expect("eligible prepared artifact");
        let artifact_len = artifact.file.metadata().expect("artifact metadata").len();
        let capsule = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x44; 16];
        write_capsule(capsule.as_raw_fd(), nonce, &payload).expect("write capsule");
        let capsule_len = capsule.metadata().expect("capsule metadata").len();

        let decoded = read_capsule_once(capsule.as_raw_fd(), nonce).expect("read capsule");
        assert_eq!(decoded, payload);
        assert!(
            decoded
                .guest_exec
                .expect("guest payload")
                .prepared_image
                .is_some()
        );
        assert!(capsule_len < artifact_len / 8);
    }

    #[test]
    fn bind_mount_snapshot_round_trips_in_capsule_order() {
        let mut payload = sample();
        let mounts = vec![
            crate::vfs::bind::NativeReexecBindMountV1 {
                mount_point: "/tmp/deeper/p".to_owned(),
                host_path: "/host/deeper-probe".into(),
                readonly: true,
            },
            crate::vfs::bind::NativeReexecBindMountV1 {
                mount_point: "/tmp".to_owned(),
                host_path: "/host/tmp".into(),
                readonly: false,
            },
        ];
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .bind_mounts = mounts.clone();
        let capsule = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x29; 16];
        write_capsule(capsule.as_raw_fd(), nonce, &payload).expect("write capsule");

        let decoded = read_capsule_once(capsule.as_raw_fd(), nonce).expect("read capsule");
        assert_eq!(
            decoded.guest_exec.expect("guest payload").bind_mounts,
            mounts
        );
    }

    #[test]
    fn legacy_v1_payload_without_bind_mounts_defaults_to_empty() {
        let payload = sample();
        let mut value = serde_json::to_value(payload).expect("serialize capsule");
        value
            .get_mut("guest_exec")
            .and_then(serde_json::Value::as_object_mut)
            .expect("guest payload")
            .remove("bind_mounts");

        let decoded: NativeExecCapsuleV1 =
            serde_json::from_value(value).expect("decode prior V1 payload");
        assert!(
            decoded
                .guest_exec
                .expect("guest payload")
                .bind_mounts
                .is_empty()
        );
    }

    #[test]
    fn v1_payload_requires_explicit_live_arena_field() {
        let payload = sample();
        let mut value = serde_json::to_value(payload).expect("serialize capsule");
        value
            .get_mut("guest_exec")
            .and_then(serde_json::Value::as_object_mut)
            .expect("guest payload")
            .remove("live_arena");

        let error = serde_json::from_value::<NativeExecCapsuleV1>(value)
            .expect_err("missing live arena field must reject V1 capsule");
        assert!(error.to_string().contains("live_arena"));
    }

    #[test]
    fn legacy_v1_process_state_defaults_to_unconfined_and_untraced() {
        let payload = sample();
        let mut value = serde_json::to_value(payload).expect("serialize capsule");
        let process_state = value
            .get_mut("guest_exec")
            .and_then(|guest| guest.get_mut("process_state"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("process state");
        process_state.remove("seccomp_policy");
        process_state.remove("ptrace_traceme");

        let decoded: NativeExecCapsuleV1 =
            serde_json::from_value(value).expect("decode prior V1 payload");
        let process_state = decoded.guest_exec.expect("guest payload").process_state;
        assert_eq!(
            process_state.seccomp_policy,
            carrick_spec::SeccompPolicy::Unconfined
        );
        assert!(!process_state.ptrace_traceme);
    }

    #[test]
    fn legacy_v1_payload_without_shared_authorities_keeps_legacy_attach_path() {
        let payload = sample();
        let mut value = serde_json::to_value(payload).expect("serialize capsule");
        let guest = value
            .get_mut("guest_exec")
            .and_then(serde_json::Value::as_object_mut)
            .expect("guest payload");
        guest.remove("kernel_arena");
        guest.remove("shared_futex_waiters");

        let decoded: NativeExecCapsuleV1 =
            serde_json::from_value(value).expect("decode prior V1 payload");
        let guest = decoded.guest_exec.expect("guest payload");
        assert!(guest.kernel_arena.is_none());
        assert!(guest.shared_futex_waiters.is_none());
    }

    #[test]
    fn legacy_v1_payload_without_profile_startup_defaults_to_none() {
        let payload = sample();
        let mut value = serde_json::to_value(payload).expect("serialize capsule");
        value
            .get_mut("guest_exec")
            .and_then(serde_json::Value::as_object_mut)
            .expect("guest payload")
            .remove("profile_startup");

        let decoded: NativeExecCapsuleV1 =
            serde_json::from_value(value).expect("decode prior V1 payload");
        let guest = decoded.guest_exec.expect("guest payload");
        assert!(guest.profile_startup.is_none());
    }

    #[test]
    fn legacy_v1_payload_without_profile_exec_epoch_defaults_to_zero() {
        let payload = sample();
        let mut value = serde_json::to_value(payload).expect("serialize capsule");
        value
            .get_mut("guest_exec")
            .and_then(serde_json::Value::as_object_mut)
            .expect("guest payload")
            .remove("profile_exec_epoch");

        let decoded: NativeExecCapsuleV1 =
            serde_json::from_value(value).expect("decode prior V1 payload");
        assert_eq!(
            decoded
                .guest_exec
                .expect("guest payload")
                .profile_exec_epoch,
            0
        );
    }

    #[test]
    fn invalid_bind_mount_is_rejected_before_host_exec() {
        let mut payload = sample();
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .bind_mounts = vec![crate::vfs::bind::NativeReexecBindMountV1 {
            mount_point: "relative/path".to_owned(),
            host_path: "/host/probe".into(),
            readonly: true,
        }];

        let result = exec_capsule_with(payload, [0x31; 16], None, None, |_, _| {
            panic!("invalid bind mount must not reach host exec")
        });
        assert!(result.is_err());
    }

    #[test]
    fn pid_probe_capsule_remains_valid_without_guest_mount_state() {
        let payload = NativeExecCapsuleV1 {
            producer_pid: 42,
            purpose: NativeExecCapsulePurposeV1::PidProbe,
            host_executable_path: b"/bin/probe".to_vec(),
            argv: Vec::new(),
            env: Vec::new(),
            guest_exec: None,
        };
        assert!(payload.validate().is_ok());
    }

    #[test]
    fn artifact_ineligibility_and_preexec_errors_select_legacy_before_host_exec() {
        if !host_page_geometry_matches_fixtures() {
            return;
        }
        for failpoint in [
            PreparedImageFailpoint::Ineligible,
            PreparedImageFailpoint::ArtifactCreation,
            PreparedImageFailpoint::PreExecValidation,
        ] {
            let mut payload = sample();
            let artifact = attach_prepared_image_with_failpoint(
                &mut payload,
                &synthetic_image(),
                &[],
                HOST_PAGE_SIZE,
                failpoint,
            );
            assert!(artifact.is_none());
            assert!(
                payload
                    .guest_exec
                    .as_ref()
                    .expect("guest payload")
                    .prepared_image
                    .is_none()
            );
            if failpoint == PreparedImageFailpoint::PreExecValidation {
                let (_artifact_fd, artifact_was_closed) = take_last_preexec_validation_artifact()
                    .expect("captured failed validation artifact");
                assert!(artifact_was_closed);
            }
        }
    }

    #[test]
    fn normal_prepared_ineligibility_completes_the_build_lifecycle_pair() {
        set_native_exec_capsule_lifecycle_capture(true);
        let mut payload = sample();
        let artifact = attach_prepared_image_with_failpoint(
            &mut payload,
            &synthetic_image(),
            &[],
            HOST_PAGE_SIZE,
            PreparedImageFailpoint::Ineligible,
        );
        assert!(artifact.is_none());
        assert_eq!(
            take_native_exec_capsule_lifecycle_capture(),
            vec![
                crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedBuildBegin,
                crate::probes::DsrCacheLifecyclePhase::HostSelfReexecPreparedBuildEnd,
            ]
        );
    }

    #[test]
    fn fallback_capsule_reaches_host_exec_without_a_prepared_record() {
        let mut payload = sample();
        assert!(
            attach_prepared_image_with_failpoint(
                &mut payload,
                &synthetic_image(),
                &[],
                HOST_PAGE_SIZE,
                PreparedImageFailpoint::Ineligible,
            )
            .is_none()
        );
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        let nonce = [0x66; 16];

        let result = exec_capsule_with(payload, nonce, None, None, |request, _| {
            let decoded =
                read_capsule_once(request.capsule_fd, nonce).expect("read fallback capsule");
            assert!(
                decoded
                    .guest_exec
                    .expect("guest payload")
                    .prepared_image
                    .is_none()
            );
            std::io::Error::from_raw_os_error(libc::ENOENT)
        });

        assert!(result.is_err());
    }

    #[cfg(feature = "alloc-owner-census")]
    #[test]
    fn native_exec_capsule_drains_at_invoke_and_replaces_the_owner_epoch_environment() {
        use carrick_dsr_aarch64::alloc_owner_wire::AllocationOwner;
        use std::ffi::CStr;

        const EXEC_EPOCH_ENV: &str = "CARRICK_ALLOC_OWNER_EXEC_EPOCH";

        let _census = allocation_census::lock();
        let output_dir = std::env::temp_dir().join(format!(
            "carrick-alloc-owner-census-tests-{}",
            std::process::id()
        ));
        match std::fs::remove_dir_all(&output_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove allocation census test directory: {error}"),
        }
        std::fs::create_dir_all(&output_dir).expect("create allocation census test directory");
        allocation_census::configure_output_dir(&output_dir);
        allocation_census::reset_and_arm(6, 0);
        allocation_census::record(AllocationOwner::PublicationMap, 41);

        let prior_epoch = std::env::var_os(EXEC_EPOCH_ENV);
        unsafe { std::env::set_var(EXEC_EPOCH_ENV, "stale") };

        let mut payload = sample();
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        let mut invoke_state = None;
        let mut matching_epoch_entries = Vec::new();

        let result = exec_capsule_with(payload, [0x67; 16], None, None, |request, _| {
            invoke_state = Some(allocation_census::state());
            matching_epoch_entries = request
                .env
                .iter()
                .copied()
                .take_while(|entry| !entry.is_null())
                .map(|entry| unsafe { CStr::from_ptr(entry) }.to_bytes().to_vec())
                .filter(|entry| entry.starts_with(format!("{EXEC_EPOCH_ENV}=").as_bytes()))
                .collect();
            std::io::Error::from_raw_os_error(libc::ENOENT)
        });

        unsafe {
            match prior_epoch {
                Some(value) => std::env::set_var(EXEC_EPOCH_ENV, value),
                None => std::env::remove_var(EXEC_EPOCH_ENV),
            }
        }

        assert!(result.is_err());
        assert_eq!(invoke_state, Some(allocation_census::State::Transition));
        assert_eq!(
            matching_epoch_entries,
            [b"CARRICK_ALLOC_OWNER_EXEC_EPOCH=7"]
        );
        assert_eq!(allocation_census::state(), allocation_census::State::Armed);
        assert_eq!(allocation_census::identity(), (6, 1));
        assert!(!allocation_census::lifecycle_error());
        allocation_census::reset_disabled();
    }

    #[test]
    fn artifact_authority_survives_capsule_exec() {
        let authority = tempfile::tempfile().expect("artifact authority");
        authority
            .set_len(256 * 1024 * 1024)
            .expect("size artifact authority");
        let nonce = [0x5a; 16];
        authority
            .write_all_at(&nonce, 0)
            .expect("write authority nonce");
        let fd = authority.as_raw_fd();
        let original_flags = fd_flags(fd);
        let identity = host_identity(fd);
        let mut payload = sample();
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .artifact_spike = Some(super::NativeReexecArtifactSpikeV1 {
            host_fd: fd,
            original_host_fd_flags: original_flags,
            host_device: identity.st_dev as u64,
            host_inode: identity.st_ino,
            host_size: identity.st_size as u64,
            authority_nonce: nonce,
        });

        let result = exec_capsule_with(payload, [0x44; 16], None, None, |_, _| {
            assert_eq!(fd_flags(fd) & libc::FD_CLOEXEC, 0);
            std::io::Error::from_raw_os_error(libc::ENOEXEC)
        });
        assert!(result.is_err());
        assert_eq!(fd_flags(fd), original_flags);
    }

    #[test]
    fn container_cache_authority_survives_capsule_exec() {
        let cache = tempfile::tempdir().expect("cache directory");
        let directory = std::fs::File::open(cache.path()).expect("open cache directory");
        let fd = directory.as_raw_fd();
        let original_flags = fd_flags(fd);
        let identity = host_identity(fd);
        let mut payload = sample();
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .aot_cache = Some(super::NativeReexecAotCacheV1 {
            host_fd: fd,
            original_host_fd_flags: original_flags,
            host_device: identity.st_dev as u64,
            host_inode: identity.st_ino,
            path: cache.path().to_path_buf(),
            creator_pid: unsafe { libc::getpid() },
            authority_nonce: [0x6b; 16],
            translator_abi: carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT,
        });

        let result = exec_capsule_with(payload, [0x45; 16], None, None, |_, _| {
            assert_eq!(fd_flags(fd) & libc::FD_CLOEXEC, 0);
            std::io::Error::from_raw_os_error(libc::ENOEXEC)
        });
        assert!(result.is_err());
        assert_eq!(fd_flags(fd), original_flags);
    }

    #[test]
    fn capsule_rejects_previous_container_cache_translator_abi() {
        let cache = tempfile::tempdir().expect("cache directory");
        let directory = std::fs::File::open(cache.path()).expect("open cache directory");
        let fd = directory.as_raw_fd();
        let identity = host_identity(fd);
        let mut payload = sample();
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .aot_cache = Some(super::NativeReexecAotCacheV1 {
            host_fd: fd,
            original_host_fd_flags: fd_flags(fd),
            host_device: identity.st_dev as u64,
            host_inode: identity.st_ino,
            path: cache.path().to_path_buf(),
            creator_pid: unsafe { libc::getpid() },
            authority_nonce: [0x6c; 16],
            translator_abi: 2,
        });

        assert!(matches!(
            payload.validate(),
            Err(super::NativeExecCapsuleError::InvalidField("guest_exec"))
        ));
    }

    #[test]
    fn capsule_validation_failure_keeps_artifact_cloexec_and_closes_owner() {
        if !host_page_geometry_matches_fixtures() {
            return;
        }
        let mut payload = sample();
        let artifact =
            attach_prepared_image(&mut payload, &synthetic_image(), &[], None, HOST_PAGE_SIZE)
                .expect("eligible prepared artifact");
        let artifact_fd = artifact.file.as_raw_fd();
        let artifact_flags = fd_flags(artifact_fd);
        let artifact_identity = host_identity(artifact_fd);
        payload.argv = vec![vec![0; MAX_ITEM_LEN + 1]];

        let result = exec_capsule_with(payload, [0x77; 16], Some(artifact), None, |_, _| {
            panic!("invalid capsule must not reach host exec")
        });

        assert!(result.is_err());
        assert_ne!(artifact_flags & libc::FD_CLOEXEC, 0);
        assert!(fd_no_longer_refers_to(
            artifact_fd,
            artifact_identity.st_dev as u64,
            artifact_identity.st_ino,
        ));
    }

    #[test]
    fn fd_flag_transaction_restores_capsule_style_descriptor() {
        let capsule = tempfile::tempfile().expect("capsule file");
        set_fd_flags(capsule.as_raw_fd(), libc::FD_CLOEXEC);
        {
            let mut transaction = super::HostFdFlagTransaction::default();
            transaction
                .prepare(capsule.as_raw_fd(), libc::FD_CLOEXEC, 0)
                .expect("prepare capsule flags");
            assert_eq!(fd_flags(capsule.as_raw_fd()), 0);
        }
        assert_eq!(fd_flags(capsule.as_raw_fd()), libc::FD_CLOEXEC);
    }

    #[test]
    fn returned_host_exec_restores_every_fd_flag_and_closes_artifact() {
        if !host_page_geometry_matches_fixtures() {
            return;
        }
        let mut payload = sample();
        let artifact =
            attach_prepared_image(&mut payload, &synthetic_image(), &[], None, HOST_PAGE_SIZE)
                .expect("eligible prepared artifact");
        let artifact_fd = artifact.file.as_raw_fd();
        let artifact_original_flags = fd_flags(artifact_fd);
        let artifact_identity = host_identity(artifact_fd);
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        let arena = tempfile::tempfile().expect("kernel arena file");
        arena
            .set_len(std::mem::size_of::<carrick_kernel::arena::ArenaLayout>() as u64)
            .expect("size kernel arena");
        set_fd_flags(arena.as_raw_fd(), libc::FD_CLOEXEC);
        let arena_identity = host_identity(arena.as_raw_fd());
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .kernel_arena = Some(super::NativeReexecKernelArenaV1 {
            host_fd: arena.as_raw_fd(),
            original_host_fd_flags: libc::FD_CLOEXEC,
            host_device: arena_identity.st_dev as u64,
            host_inode: arena_identity.st_ino,
            host_size: arena_identity.st_size as u64,
        });
        let waiters = tempfile::tempfile().expect("shared futex waiter file");
        waiters.set_len(4096).expect("size waiter table");
        set_fd_flags(waiters.as_raw_fd(), libc::FD_CLOEXEC);
        let waiter_identity = host_identity(waiters.as_raw_fd());
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .shared_futex_waiters = Some(super::NativeReexecWaiterTableV1 {
            host_fd: waiters.as_raw_fd(),
            original_host_fd_flags: libc::FD_CLOEXEC,
            host_device: waiter_identity.st_dev as u64,
            host_inode: waiter_identity.st_ino,
            host_size: waiter_identity.st_size as u64,
        });
        let mut saw_exec = false;

        let result = exec_capsule_with(payload, [0x33; 16], Some(artifact), None, |request, _| {
            saw_exec = true;
            assert_eq!(fd_flags(request.capsule_fd), 0);
            assert_eq!(
                fd_flags(artifact_fd),
                artifact_original_flags & !libc::FD_CLOEXEC
            );
            assert_eq!(fd_flags(xsig.as_raw_fd()), 0);
            assert_eq!(fd_flags(survivor.as_raw_fd()), 0);
            assert_eq!(fd_flags(close_on_exec.as_raw_fd()), libc::FD_CLOEXEC);
            assert_eq!(fd_flags(arena.as_raw_fd()), 0);
            assert_eq!(fd_flags(waiters.as_raw_fd()), 0);
            std::io::Error::from_raw_os_error(libc::ENOENT)
        });

        assert!(saw_exec);
        assert!(result.is_err());
        assert!(fd_no_longer_refers_to(
            artifact_fd,
            artifact_identity.st_dev as u64,
            artifact_identity.st_ino,
        ));
        assert_eq!(fd_flags(xsig.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(survivor.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(close_on_exec.as_raw_fd()), 0);
        assert_eq!(fd_flags(arena.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(waiters.as_raw_fd()), libc::FD_CLOEXEC);
    }

    #[test]
    fn artifact_flag_failure_rolls_back_prior_flags_and_closes_artifact() {
        if !host_page_geometry_matches_fixtures() {
            return;
        }
        let mut payload = sample();
        let artifact =
            attach_prepared_image(&mut payload, &synthetic_image(), &[], None, HOST_PAGE_SIZE)
                .expect("eligible prepared artifact");
        let artifact_fd = artifact.file.as_raw_fd();
        let artifact_identity = host_identity(artifact_fd);
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        fail_next_artifact_fd_flag_preparation(artifact_fd);

        let result = exec_capsule_with(payload, [0x22; 16], Some(artifact), None, |_, _| {
            panic!("host exec must not run after artifact flag failure")
        });

        assert!(result.is_err());
        assert!(fd_no_longer_refers_to(
            artifact_fd,
            artifact_identity.st_dev as u64,
            artifact_identity.st_ino,
        ));
        assert_eq!(fd_flags(xsig.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(survivor.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(close_on_exec.as_raw_fd()), 0);
    }

    #[test]
    fn prepared_record_survives_capsule_read_for_resume_adoption() {
        if !host_page_geometry_matches_fixtures() {
            return;
        }
        let mut payload = sample();
        let artifact =
            attach_prepared_image(&mut payload, &synthetic_image(), &[], None, HOST_PAGE_SIZE)
                .expect("eligible prepared artifact");
        let inherited_fd = unsafe { libc::fcntl(artifact.file.as_raw_fd(), libc::F_DUPFD, 0) };
        assert!(inherited_fd >= 0);
        let inherited_identity = host_identity(inherited_fd);
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .prepared_image = Some(artifact.record.with_artifact_fd_for_test(inherited_fd));
        let capsule = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x45; 16];
        write_capsule(capsule.as_raw_fd(), nonce, &payload).expect("write prepared capsule");
        let decoded = read_capsule_once(capsule.as_raw_fd(), nonce).expect("read prepared capsule");

        assert!(
            decoded
                .guest_exec
                .as_ref()
                .and_then(|guest| guest.prepared_image.as_ref())
                .is_some()
        );
        assert!(!fd_no_longer_refers_to(
            inherited_fd,
            inherited_identity.st_dev as u64,
            inherited_identity.st_ino,
        ));
        assert_eq!(unsafe { libc::close(inherited_fd) }, 0);
    }

    #[test]
    fn native_exec_capsule_round_trips_once() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        write_capsule(file.as_raw_fd(), nonce, &sample()).expect("write capsule");

        let decoded = read_capsule_once(file.as_raw_fd(), nonce).expect("read capsule");
        assert_eq!(decoded, sample());
        assert!(read_capsule_once(file.as_raw_fd(), nonce).is_err());
    }

    #[test]
    fn profile_exec_epoch_is_bounded_and_authenticated() {
        let mut low = sample();
        low.guest_exec
            .as_mut()
            .expect("guest payload")
            .profile_exec_epoch = 0;
        let mut high = low.clone();
        high.guest_exec
            .as_mut()
            .expect("guest payload")
            .profile_exec_epoch = u64::MAX;
        let nonce = [0x71; 16];
        let low_file = tempfile::tempfile().expect("low epoch capsule");
        let high_file = tempfile::tempfile().expect("high epoch capsule");
        write_capsule(low_file.as_raw_fd(), nonce, &low).expect("write low epoch capsule");
        write_capsule(high_file.as_raw_fd(), nonce, &high).expect("write high epoch capsule");
        let mut low_header = [0_u8; HEADER_LEN];
        let mut high_header = [0_u8; HEADER_LEN];
        low_file
            .read_exact_at(&mut low_header, 0)
            .expect("read low epoch header");
        high_file
            .read_exact_at(&mut high_header, 0)
            .expect("read high epoch header");

        assert!(
            low_file
                .metadata()
                .expect("low metadata")
                .len()
                .abs_diff(high_file.metadata().expect("high metadata").len())
                <= 24,
            "the scalar epoch must add only a constant-size encoding"
        );
        assert_ne!(
            &low_header[20..52],
            &high_header[20..52],
            "the authenticated payload digest must cover exec_epoch"
        );
        assert_eq!(
            read_capsule_once(high_file.as_raw_fd(), nonce)
                .expect("read high epoch capsule")
                .guest_exec
                .expect("guest payload")
                .profile_exec_epoch,
            u64::MAX
        );
    }

    #[test]
    fn native_exec_capsule_rejects_wrong_nonce_without_consuming() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        write_capsule(file.as_raw_fd(), nonce, &sample()).expect("write capsule");

        assert!(read_capsule_once(file.as_raw_fd(), [0x6b; 16]).is_err());
        assert_eq!(
            read_capsule_once(file.as_raw_fd(), nonce).expect("read with correct nonce"),
            sample()
        );
    }

    #[test]
    fn native_exec_capsule_rejects_corruption_and_trailing_data() {
        let nonce = [0x5a; 16];
        let corrupted = tempfile::tempfile().expect("temporary capsule");
        write_capsule(corrupted.as_raw_fd(), nonce, &sample()).expect("write capsule");
        corrupted
            .write_at(&[0xff], HEADER_LEN as u64)
            .expect("corrupt payload");
        assert!(read_capsule_once(corrupted.as_raw_fd(), nonce).is_err());

        let trailing = tempfile::tempfile().expect("temporary capsule");
        write_capsule(trailing.as_raw_fd(), nonce, &sample()).expect("write capsule");
        trailing
            .write_at(&[0xaa], trailing.metadata().expect("metadata").len())
            .expect("append byte");
        assert!(read_capsule_once(trailing.as_raw_fd(), nonce).is_err());
    }

    #[test]
    fn native_exec_capsule_rejects_bad_version_and_non_regular_fd() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        write_capsule(file.as_raw_fd(), nonce, &sample()).expect("write capsule");
        file.write_at(&2_u16.to_le_bytes(), 8)
            .expect("replace version");
        assert!(read_capsule_once(file.as_raw_fd(), nonce).is_err());

        let (socket, _peer) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        assert!(write_capsule(socket.as_raw_fd(), nonce, &sample()).is_err());
    }

    #[test]
    fn native_exec_capsule_rejects_oversized_nested_values() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        let mut payload = sample();
        payload.argv = vec![vec![0; MAX_ITEM_LEN + 1]];
        assert!(write_capsule(file.as_raw_fd(), nonce, &payload).is_err());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) mod native_exec_live_arena {
        use super::*;
        use carrick_dsr::host::NativeHostJit;
        use carrick_dsr_aarch64::live_arena::LiveArenaCapacities;
        use carrick_native_darwin::live_arena::{
            DarwinLiveArena, LiveArenaHostJit, LiveArenaTransitV1, RegisteredPortExecPlan,
        };
        use mach2::kern_return::KERN_SUCCESS;
        use mach2::mach_port::{
            mach_port_allocate, mach_port_deallocate, mach_port_destroy, mach_port_insert_right,
        };
        use mach2::message::MACH_MSG_TYPE_MAKE_SEND;
        use mach2::port::{MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE, mach_port_t};
        use mach2::task::{mach_ports_lookup, mach_ports_register};
        use mach2::traps::mach_task_self;
        use mach2::vm::{mach_vm_allocate, mach_vm_deallocate};
        use mach2::vm_statistics::VM_FLAGS_FIXED;

        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        use crate::native_exec_capsule::{
            NativeReexecLiveArenaV1, NativeReexecXsigV1, decode_nonce, encode_nonce,
        };

        const CHILD_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_CHILD";
        const CHILD_CAPSULE_FD_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_CAPSULE_FD";
        const CHILD_NONCE_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_NONCE";
        const CHILD_PARENT_RANGES_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_PARENT_RANGES";
        const CHILD_RECEIPT_FD_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_RECEIPT_FD";
        const OWNER_RESUME_STAGE_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_OWNER_RESUME";
        const OWNER_PID_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_OWNER_PID";
        const LIVE_TRANSIT_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_TRANSIT";
        const PUBLISH_COMMAND_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_PUBLISH_COMMAND";
        const PUBLISH_ACK_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_PUBLISH_ACK";
        const PUBLISH_PID_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_PUBLISH_PID";
        const PUBLISHER_ENV: &str = "CARRICK_TEST_NATIVE_LIVE_ARENA_PUBLISHER";
        const CHILD_TEST_NAME: &str =
            "native_exec_capsule::tests::native_exec_live_arena::exec_successor_child";
        const RESUME_RECEIPT: u8 = 0xa1;
        const FRESH_RECEIPT: u8 = 0xf1;
        static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        static LIFECYCLE_RECEIPT: std::sync::OnceLock<LifecycleReceipt> =
            std::sync::OnceLock::new();

        #[derive(Clone, Copy)]
        struct LifecycleReceipt {
            fresh: bool,
            first: u8,
            second: u8,
            child_status: i32,
        }

        fn test_lock() -> std::sync::MutexGuard<'static, ()> {
            TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        struct PortSnapshot(Vec<mach_port_t>);

        impl PortSnapshot {
            fn lookup() -> Self {
                let mut raw = std::ptr::null_mut();
                let mut count = 0;
                assert_eq!(
                    unsafe { mach_ports_lookup(mach_task_self(), &mut raw, &mut count) },
                    KERN_SUCCESS,
                    "lookup registered ports"
                );
                let names = if raw.is_null() {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(raw, count as usize) }.to_vec()
                };
                if !raw.is_null() {
                    assert_eq!(
                        unsafe {
                            mach_vm_deallocate(
                                mach_task_self(),
                                raw as u64,
                                u64::from(count) * std::mem::size_of::<mach_port_t>() as u64,
                            )
                        },
                        KERN_SUCCESS,
                        "deallocate registered-port OOL array"
                    );
                }
                Self(names)
            }

            fn normalized(&self) -> [mach_port_t; 3] {
                assert!(self.0.len() <= 3);
                let mut normalized = [MACH_PORT_NULL; 3];
                normalized[..self.0.len()].copy_from_slice(&self.0);
                normalized
            }
        }

        impl Drop for PortSnapshot {
            fn drop(&mut self) {
                for name in &self.0 {
                    if *name != MACH_PORT_NULL {
                        unsafe { mach_port_deallocate(mach_task_self(), *name) };
                    }
                }
            }
        }

        fn register(names: &[mach_port_t]) {
            assert!(names.len() <= 3);
            assert_eq!(
                unsafe {
                    mach_ports_register(
                        mach_task_self(),
                        names.as_ptr().cast_mut(),
                        names.len() as u32,
                    )
                },
                KERN_SUCCESS,
                "register task ports"
            );
        }

        struct RegisteredPortsGuard {
            original: PortSnapshot,
        }

        impl RegisteredPortsGuard {
            fn replace(names: &[mach_port_t]) -> Self {
                let original = PortSnapshot::lookup();
                register(names);
                Self { original }
            }
        }

        impl Drop for RegisteredPortsGuard {
            fn drop(&mut self) {
                register(&self.original.0);
            }
        }

        struct TestPort(mach_port_t);

        impl TestPort {
            fn new() -> Self {
                let mut name = MACH_PORT_NULL;
                assert_eq!(
                    unsafe {
                        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut name)
                    },
                    KERN_SUCCESS,
                    "allocate test receive right"
                );
                assert_eq!(
                    unsafe {
                        mach_port_insert_right(
                            mach_task_self(),
                            name,
                            name,
                            MACH_MSG_TYPE_MAKE_SEND,
                        )
                    },
                    KERN_SUCCESS,
                    "insert test send right"
                );
                Self(name)
            }
        }

        impl Drop for TestPort {
            fn drop(&mut self) {
                unsafe { mach_port_destroy(mach_task_self(), self.0) };
            }
        }

        fn arena() -> DarwinLiveArena {
            let page = unsafe { mach2::vm_page_size::vm_page_size };
            DarwinLiveArena::new(LiveArenaCapacities::new(
                page as u64,
                page as u64,
                page as u64,
            ))
            .expect("live arena")
        }

        fn bind_real_xsig(payload: &mut NativeExecCapsuleV1, file: &std::fs::File) {
            let fd = file.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0);
            let metadata = file.metadata().expect("xsig metadata");
            let guest = payload.guest_exec.as_mut().expect("guest");
            guest.xsig = NativeReexecXsigV1 {
                host_fd: fd,
                original_host_fd_flags: flags,
                host_device: metadata.dev(),
                host_inode: metadata.ino(),
                host_size: metadata.len(),
            };
        }

        fn return_immediate(value: u16) -> [u8; 8] {
            let mov_w0 = 0x5280_0000_u32 | (u32::from(value) << 5);
            let ret = 0xd65f_03c0_u32;
            let mut code = [0_u8; 8];
            code[..4].copy_from_slice(&mov_w0.to_le_bytes());
            code[4..].copy_from_slice(&ret.to_le_bytes());
            code
        }

        fn write_code(arena: &DarwinLiveArena, value: u16) {
            let region = arena.jit_region(0..8).expect("live code region");
            unsafe {
                std::ptr::copy_nonoverlapping(
                    return_immediate(value).as_ptr(),
                    region.write_base().as_ptr(),
                    8,
                );
            }
        }

        fn execute_code(arena: &DarwinLiveArena) -> u32 {
            let region = arena.jit_region(0..8).expect("live code region");
            let executable = unsafe { region.exec_base().as_ptr() };
            LiveArenaHostJit.flush_icache(executable, 8);
            let entry: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(executable) };
            unsafe { entry() }
        }

        fn pipe() -> [libc::c_int; 2] {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "create pipe");
            fds
        }

        fn close_fd(fd: libc::c_int) {
            assert_eq!(unsafe { libc::close(fd) }, 0, "close fd {fd}");
        }

        fn write_byte(fd: libc::c_int, byte: u8) -> anyhow::Result<()> {
            let mut written = 0;
            while written == 0 {
                let result = unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
                if result == 1 {
                    written = 1;
                } else if result < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                } else {
                    anyhow::bail!("write lifecycle byte: {}", std::io::Error::last_os_error());
                }
            }
            Ok(())
        }

        fn read_byte(fd: libc::c_int) -> anyhow::Result<u8> {
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            loop {
                let result = unsafe { libc::poll(&mut poll_fd, 1, 15_000) };
                if result > 0 {
                    break;
                }
                if result < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                anyhow::bail!("timed out waiting for live-arena child receipt");
            }
            let mut byte = 0;
            loop {
                let result = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
                if result == 1 {
                    return Ok(byte);
                }
                if result < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                if result == 0 {
                    anyhow::bail!("live-arena child closed its receipt pipe");
                }
                anyhow::bail!(
                    "read live-arena child receipt: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        fn format_ranges(ranges: &[std::ops::Range<usize>; 3]) -> String {
            ranges
                .iter()
                .map(|range| format!("{:x}-{:x}", range.start, range.end))
                .collect::<Vec<_>>()
                .join(",")
        }

        fn parse_ranges(encoded: &str) -> anyhow::Result<[std::ops::Range<usize>; 3]> {
            let ranges = encoded
                .split(',')
                .map(|encoded_range| {
                    let (start, end) = encoded_range
                        .split_once('-')
                        .ok_or_else(|| anyhow::anyhow!("invalid encoded live-arena range"))?;
                    Ok(usize::from_str_radix(start, 16)?..usize::from_str_radix(end, 16)?)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            ranges
                .try_into()
                .map_err(|_| anyhow::anyhow!("live-arena range vector does not have three entries"))
        }

        struct FixedReservations(Vec<std::ops::Range<usize>>);

        impl FixedReservations {
            fn reserve(ranges: &[std::ops::Range<usize>; 3]) -> anyhow::Result<Self> {
                let mut reserved = Vec::new();
                for range in ranges {
                    let mut address = range.start as u64;
                    let result = unsafe {
                        mach_vm_allocate(
                            mach_task_self(),
                            &mut address,
                            range.len() as u64,
                            VM_FLAGS_FIXED,
                        )
                    };
                    if result == KERN_SUCCESS {
                        if address != range.start as u64 {
                            anyhow::bail!(
                                "fixed parent live-arena reservation moved from {:#x} to {address:#x}",
                                range.start
                            );
                        }
                        reserved.push(range.clone());
                    }
                    // A fixed allocation failure means the fresh process image
                    // already occupies part of this exact old range. That is
                    // equally strong anti-reuse authority: the adopted mapping
                    // cannot be placed at the parent's old base.
                }
                Ok(Self(reserved))
            }
        }

        impl Drop for FixedReservations {
            fn drop(&mut self) {
                for range in self.0.drain(..) {
                    unsafe {
                        mach_vm_deallocate(
                            mach_task_self(),
                            range.start as u64,
                            range.len() as u64,
                        );
                    }
                }
            }
        }

        struct ChildGuard(Option<libc::pid_t>);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if let Some(pid) = self.0 {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                }
            }
        }

        fn lifecycle_receipt() -> LifecycleReceipt {
            *LIFECYCLE_RECEIPT.get_or_init(|| run_lifecycle_proof().expect("real lifecycle proof"))
        }

        fn run_lifecycle_proof() -> anyhow::Result<LifecycleReceipt> {
            let executable = std::env::current_exe()?;
            let receipt = pipe();
            let argv = [
                CString::new(executable.as_os_str().as_bytes())?,
                CString::new("--exact")?,
                CString::new(CHILD_TEST_NAME)?,
                CString::new("--nocapture")?,
                CString::new("--test-threads=1")?,
            ];
            let argv_ptrs = argv
                .iter()
                .map(|entry| entry.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let mut env = std::env::vars_os()
                .filter(|(key, _)| {
                    !key.as_os_str()
                        .as_bytes()
                        .starts_with(b"CARRICK_TEST_NATIVE_LIVE_ARENA_")
                })
                .map(|(key, value)| {
                    let mut entry = key.as_os_str().as_bytes().to_vec();
                    entry.push(b'=');
                    entry.extend_from_slice(value.as_os_str().as_bytes());
                    CString::new(entry)
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (key, value) in [
                (CHILD_ENV, "1".to_owned()),
                (CHILD_RECEIPT_FD_ENV, receipt[1].to_string()),
            ] {
                env.push(CString::new(format!("{key}={value}"))?);
            }
            let env_ptrs = env
                .iter()
                .map(|entry| entry.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let receipt_flags = unsafe { libc::fcntl(receipt[1], libc::F_GETFD) };
            assert!(receipt_flags >= 0 && receipt_flags & libc::FD_CLOEXEC == 0);

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if pid == 0 {
                unsafe {
                    libc::close(receipt[0]);
                    libc::execve(argv[0].as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
                    libc::_exit(127);
                }
            }
            close_fd(receipt[1]);
            let mut child_guard = ChildGuard(Some(pid));

            let resume_byte = read_byte(receipt[0])?;
            if resume_byte != RESUME_RECEIPT {
                anyhow::bail!(
                    "successor bypassed production resume entry: receipt={resume_byte:#x}"
                );
            }
            let fresh_byte = read_byte(receipt[0])?;
            if fresh_byte != FRESH_RECEIPT {
                anyhow::bail!("successor did not publish fresh-address receipt");
            }
            let fresh = true;
            let first = read_byte(receipt[0])?;
            let second = read_byte(receipt[0])?;
            close_fd(receipt[0]);

            let mut child_status = 0;
            if unsafe { libc::waitpid(pid, &mut child_status, 0) } != pid {
                anyhow::bail!(
                    "wait for lifecycle child: {}",
                    std::io::Error::last_os_error()
                );
            }
            child_guard.0 = None;
            Ok(LifecycleReceipt {
                fresh,
                first,
                second,
                child_status,
            })
        }

        pub(crate) fn resume_hook(arena: Option<&DarwinLiveArena>) -> anyhow::Result<Option<i32>> {
            if std::env::var_os(CHILD_ENV).is_none() {
                return Ok(None);
            }
            let arena = arena.ok_or_else(|| anyhow::anyhow!("child did not adopt live arena"))?;
            let parent_ranges = parse_ranges(&std::env::var(CHILD_PARENT_RANGES_ENV)?)?;
            let adopted_ranges = unsafe { arena.local_mapping_ranges_for_transport_proof()? };
            let fresh = adopted_ranges.iter().all(|adopted| {
                parent_ranges
                    .iter()
                    .all(|parent| adopted.end <= parent.start || parent.end <= adopted.start)
            });
            let receipt_fd: libc::c_int = std::env::var(CHILD_RECEIPT_FD_ENV)?.parse()?;
            write_byte(receipt_fd, RESUME_RECEIPT)?;
            write_byte(receipt_fd, if fresh { FRESH_RECEIPT } else { 0 })?;
            write_byte(receipt_fd, u8::try_from(execute_code(arena))?)?;
            let publish_command: libc::c_int = std::env::var(PUBLISH_COMMAND_ENV)?.parse()?;
            let publish_ack: libc::c_int = std::env::var(PUBLISH_ACK_ENV)?.parse()?;
            write_byte(publish_command, 43)?;
            if read_byte(publish_ack)? != 43 {
                anyhow::bail!("publisher returned invalid live-arena acknowledgement");
            }
            write_byte(receipt_fd, u8::try_from(execute_code(arena))?)?;
            let publisher_pid: libc::pid_t = std::env::var(PUBLISH_PID_ENV)?.parse()?;
            let mut status = 0;
            if unsafe { libc::waitpid(publisher_pid, &mut status, 0) } != publisher_pid {
                return Err(std::io::Error::last_os_error().into());
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                anyhow::bail!("live-arena publisher exited with status {status:#x}");
            }
            Ok(Some(0))
        }

        fn run_owning_process_lifecycle() -> anyhow::Result<()> {
            let receipt_fd: libc::c_int = std::env::var(CHILD_RECEIPT_FD_ENV)?.parse()?;
            let arena = arena();
            write_code(&arena, 42);
            let publish_command = pipe();
            let publish_ack = pipe();
            let _clean_ports =
                RegisteredPortsGuard::replace(&[MACH_PORT_NULL, MACH_PORT_NULL, MACH_PORT_NULL]);
            let plan = RegisteredPortExecPlan::install(&arena)?;

            let executable = std::env::current_exe()?;
            let argv = [
                CString::new(executable.as_os_str().as_bytes())?,
                CString::new("--exact")?,
                CString::new(CHILD_TEST_NAME)?,
                CString::new("--nocapture")?,
                CString::new("--test-threads=1")?,
            ];
            let argv_ptrs = argv
                .iter()
                .map(|entry| entry.as_ptr().cast_mut())
                .chain(std::iter::once(std::ptr::null_mut()))
                .collect::<Vec<_>>();
            let publisher_transit = arena.transit_v1();
            let mut publisher_env = std::env::vars_os()
                .filter(|(key, _)| {
                    !key.as_os_str()
                        .as_bytes()
                        .starts_with(b"CARRICK_TEST_NATIVE_LIVE_ARENA_")
                })
                .map(|(key, value)| {
                    let mut entry = key.as_os_str().as_bytes().to_vec();
                    entry.push(b'=');
                    entry.extend_from_slice(value.as_os_str().as_bytes());
                    CString::new(entry)
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (key, value) in [
                (CHILD_ENV, "1".to_owned()),
                (PUBLISHER_ENV, "1".to_owned()),
                (PUBLISH_COMMAND_ENV, publish_command[0].to_string()),
                (PUBLISH_ACK_ENV, publish_ack[1].to_string()),
                (
                    LIVE_TRANSIT_ENV,
                    format!(
                        "{}:{}:{}:{}",
                        publisher_transit.schema,
                        publisher_transit.code_len,
                        publisher_transit.control_len,
                        encode_nonce(publisher_transit.nonce),
                    ),
                ),
            ] {
                publisher_env.push(CString::new(format!("{key}={value}"))?);
            }
            let publisher_env_ptrs = publisher_env
                .iter()
                .map(|entry| entry.as_ptr().cast_mut())
                .chain(std::iter::once(std::ptr::null_mut()))
                .collect::<Vec<_>>();
            let publisher_pid = unsafe {
                plan.spawn_process(
                    argv[0].as_ptr(),
                    argv_ptrs.as_ptr(),
                    publisher_env_ptrs.as_ptr(),
                )?
            };
            let _publisher_guard = ChildGuard(Some(publisher_pid));
            assert_eq!(read_byte(publish_ack[0])?, 1);
            close_fd(publish_command[0]);
            close_fd(publish_ack[1]);
            let old_mapping_ranges = unsafe { arena.local_mapping_ranges_for_transport_proof()? };
            drop(plan);

            carrick_signal_core::xsig::xsig_init();
            let mut payload = sample();
            payload.producer_pid = unsafe { libc::getpid() as u32 };
            payload.host_executable_path = executable.as_os_str().as_bytes().to_vec();
            let guest = payload.guest_exec.as_mut().expect("guest payload");
            guest.live_arena = Some(arena.transit_v1().into());
            guest.xsig = crate::native_exec_capsule::snapshot_xsig()?;
            let nonce = [0x9d; 16];
            exec_capsule_with(
                payload,
                nonce,
                None,
                Some(&arena),
                |request, registered_ports| {
                    let mut env = std::env::vars_os()
                        .filter(|(key, _)| {
                            !key.as_os_str()
                                .as_bytes()
                                .starts_with(b"CARRICK_TEST_NATIVE_LIVE_ARENA_")
                        })
                        .map(|(key, value)| {
                            let mut entry = key.as_os_str().as_bytes().to_vec();
                            entry.push(b'=');
                            entry.extend_from_slice(value.as_os_str().as_bytes());
                            CString::new(entry).expect("successor environment entry")
                        })
                        .collect::<Vec<_>>();
                    for (key, value) in [
                        (CHILD_ENV, "1".to_owned()),
                        (OWNER_RESUME_STAGE_ENV, "1".to_owned()),
                        (OWNER_PID_ENV, unsafe { libc::getpid() }.to_string()),
                        (CHILD_CAPSULE_FD_ENV, request.capsule_fd.to_string()),
                        (CHILD_NONCE_ENV, encode_nonce(nonce)),
                        (CHILD_RECEIPT_FD_ENV, receipt_fd.to_string()),
                        (CHILD_PARENT_RANGES_ENV, format_ranges(&old_mapping_ranges)),
                        (PUBLISH_COMMAND_ENV, publish_command[1].to_string()),
                        (PUBLISH_ACK_ENV, publish_ack[0].to_string()),
                        (PUBLISH_PID_ENV, publisher_pid.to_string()),
                    ] {
                        env.push(
                            CString::new(format!("{key}={value}"))
                                .expect("successor test environment"),
                        );
                    }
                    let env_ptrs = env
                        .iter()
                        .map(|entry| entry.as_ptr().cast_mut())
                        .chain(std::iter::once(std::ptr::null_mut()))
                        .collect::<Vec<_>>();
                    for fd in [receipt_fd, publish_command[1], publish_ack[0]] {
                        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                        assert!(flags >= 0 && flags & libc::FD_CLOEXEC == 0);
                    }
                    let registered_ports =
                        registered_ports.expect("live arena registered-port exec plan");
                    unsafe {
                        registered_ports.replace_process(
                            request.executable.as_ptr(),
                            argv_ptrs.as_ptr(),
                            env_ptrs.as_ptr(),
                        )
                    }
                },
            )
        }

        #[test]
        fn registered_port_transaction_preserves_all_three_slots() {
            let _serial = test_lock();
            let startup = PortSnapshot::lookup();
            let startup = startup.normalized();
            assert_eq!(startup[1], MACH_PORT_NULL);
            assert_eq!(startup[2], MACH_PORT_NULL);
            let third = TestPort::new();
            let _guard = RegisteredPortsGuard::replace(&[third.0, MACH_PORT_NULL, MACH_PORT_NULL]);
            let arena = arena();
            let plan =
                RegisteredPortExecPlan::install(&arena).expect("prepare registered-port exec plan");
            let installed = PortSnapshot::lookup();
            let installed = installed.normalized();
            assert_eq!(installed[0], third.0);
            assert_eq!(installed[1], MACH_PORT_NULL);
            assert_eq!(installed[2], MACH_PORT_NULL);
            drop(plan);
            assert_eq!(
                PortSnapshot::lookup().normalized(),
                [third.0, MACH_PORT_NULL, MACH_PORT_NULL]
            );
        }

        #[test]
        fn failed_exec_restores_original_registered_port_vector() {
            let _serial = test_lock();
            let third = TestPort::new();
            let _guard = RegisteredPortsGuard::replace(&[third.0, MACH_PORT_NULL, MACH_PORT_NULL]);
            let arena = arena();
            let mut payload = sample();
            payload.producer_pid = unsafe { libc::getpid() as u32 };
            payload.host_executable_path = std::env::current_exe()
                .expect("current executable")
                .as_os_str()
                .as_bytes()
                .to_vec();
            payload.guest_exec.as_mut().expect("guest").live_arena =
                Some(NativeReexecLiveArenaV1::from(arena.transit_v1()));
            let xsig = tempfile::tempfile().expect("xsig tempfile");
            xsig.set_len(4096).expect("size xsig");
            bind_real_xsig(&mut payload, &xsig);
            let result = exec_capsule_with(payload, [0x71; 16], None, Some(&arena), |_, _| {
                std::io::Error::from_raw_os_error(libc::ENOEXEC)
            });
            assert!(result.is_err());
            assert_eq!(
                PortSnapshot::lookup().normalized(),
                [third.0, MACH_PORT_NULL, MACH_PORT_NULL]
            );
        }

        #[test]
        fn resume_rejects_missing_swapped_or_extra_arena_rights() {
            let _serial = test_lock();
            let expected = arena().transit_v1();
            assert!(DarwinLiveArena::adopt_registered(expected).is_err());

            let preserved = TestPort::new();
            let wrong_code = TestPort::new();
            let wrong_control = TestPort::new();
            let _guard =
                RegisteredPortsGuard::replace(&[preserved.0, wrong_control.0, wrong_code.0]);
            assert!(DarwinLiveArena::adopt_registered(expected).is_err());

            register(&[preserved.0, wrong_code.0, wrong_control.0]);
            assert!(DarwinLiveArena::adopt_optional_registered(None).is_err());

            register(&[preserved.0, wrong_code.0, MACH_PORT_NULL]);
            assert!(DarwinLiveArena::adopt_registered(expected).is_err());
        }

        #[test]
        fn fork_exec_successor_maps_arena_at_fresh_addresses() {
            let _serial = test_lock();
            let receipt = lifecycle_receipt();
            assert!(
                receipt.fresh,
                "all three successor mappings must use fresh VAs"
            );
            assert!(libc::WIFEXITED(receipt.child_status));
            assert_eq!(libc::WEXITSTATUS(receipt.child_status), 0);
        }

        #[test]
        fn fork_exec_successor_observes_parent_code_publication() {
            let _serial = test_lock();
            let receipt = lifecycle_receipt();
            assert_eq!(receipt.first, 42);
            assert_eq!(receipt.second, 43);
            assert!(libc::WIFEXITED(receipt.child_status));
            assert_eq!(libc::WEXITSTATUS(receipt.child_status), 0);
        }

        #[test]
        #[allow(unreachable_code)]
        fn exec_successor_child() {
            if std::env::var_os(CHILD_ENV).is_none() {
                return;
            }
            if std::env::var_os(PUBLISHER_ENV).is_some() {
                let transit = std::env::var(LIVE_TRANSIT_ENV).expect("publisher transit metadata");
                let mut fields = transit.split(':');
                let expected = LiveArenaTransitV1 {
                    schema: fields
                        .next()
                        .expect("schema")
                        .parse()
                        .expect("parse schema"),
                    code_len: fields.next().expect("code").parse().expect("parse code"),
                    control_len: fields
                        .next()
                        .expect("control")
                        .parse()
                        .expect("parse control"),
                    nonce: decode_nonce(fields.next().expect("nonce")).expect("parse nonce"),
                };
                let arena = DarwinLiveArena::adopt_registered(expected)
                    .expect("publisher adopts registered arena");
                let command: libc::c_int = std::env::var(PUBLISH_COMMAND_ENV)
                    .expect("publisher command")
                    .parse()
                    .expect("parse publisher command");
                let ack: libc::c_int = std::env::var(PUBLISH_ACK_ENV)
                    .expect("publisher ack")
                    .parse()
                    .expect("parse publisher ack");
                write_byte(ack, 1).expect("publisher ready");
                assert_eq!(read_byte(command).expect("publication command"), 43);
                write_code(&arena, 43);
                write_byte(ack, 43).expect("publication complete");
                return;
            }
            if std::env::var_os(OWNER_RESUME_STAGE_ENV).is_some() {
                let old_ranges = parse_ranges(
                    &std::env::var(CHILD_PARENT_RANGES_ENV).expect("old mapping ranges"),
                )
                .expect("parse old mapping ranges");
                let _reservations =
                    FixedReservations::reserve(&old_ranges).expect("reserve old mapping ranges");
                let before_pid: libc::pid_t = std::env::var(OWNER_PID_ENV)
                    .expect("owner PID")
                    .parse()
                    .expect("parse owner PID");
                assert_eq!(before_pid, unsafe { libc::getpid() });
                let capsule_fd: libc::c_int = std::env::var(CHILD_CAPSULE_FD_ENV)
                    .expect("successor capsule fd")
                    .parse()
                    .expect("parse successor capsule fd");
                let nonce = std::env::var(CHILD_NONCE_ENV).expect("successor capsule nonce");
                match crate::native_exec_capsule::resume(capsule_fd, &nonce)
                    .expect("resume production native exec capsule")
                {
                    crate::NativeSelfReexecOutcome::GuestExit(0) => {}
                    crate::NativeSelfReexecOutcome::GuestExit(code) => {
                        panic!("live-arena resume returned exit code {code}")
                    }
                    crate::NativeSelfReexecOutcome::PidProbe { .. } => {
                        panic!("live-arena guest capsule resumed as PID probe")
                    }
                }
                return;
            }
            run_owning_process_lifecycle().expect("run owning-process live arena lifecycle");
            unreachable!("SETEXEC must replace the process image");
        }
    }
}
