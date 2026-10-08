//! One-way launch custody for a private native kernel. The source graph is
//! bootstrap authority only; exported identities cannot be allocated there.
use std::sync::Arc;

use carrick_sched_core::process::identity_allocator::{
    TransferredNamespaceState, TransferredSerialAllocator, VisibleIdentity, VisibleNamespace,
};

use super::objects::{Credentials, FileTable, FsContext, TaskIdentity, TaskKey, ThreadKey};
use super::{Container, ContainerId, FileTableId, MmId};

/// Backend-owned VM incarnation. Primitive integers cannot satisfy this
/// boundary; backends implement it for their privately issued VM identity.
pub trait BootVmIdentity: Copy + Eq {}

/// A local identity always travels with its receiving VM's exact incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmLocal<V, I> {
    pub vm: V,
    pub local: I,
}

/// Real resources admitted before export. Files retain their exact table and
/// descriptions; the mount service is the resolved launch service.
pub struct BootLaunchResources {
    pub(crate) namespace: Arc<Container>,
    pub(crate) rootfs: Arc<carrick_vfs::RootFsVfs>,
    pub(crate) mounts: Arc<carrick_vfs::VfsMounts>,
    pub(crate) files: Arc<FileTable>,
    pub(crate) fs_context: Arc<FsContext>,
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) argv: Vec<String>,
    pub(crate) env: Vec<Vec<u8>>,
}
impl std::fmt::Debug for BootLaunchResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootLaunchResources")
            .field("file_table", &self.files.id())
            .finish_non_exhaustive()
    }
}
impl BootLaunchResources {
    pub fn namespace(&self) -> &Arc<Container> {
        &self.namespace
    }
    pub fn rootfs(&self) -> &Arc<carrick_vfs::RootFsVfs> {
        &self.rootfs
    }
    pub fn mounts(&self) -> &Arc<carrick_vfs::VfsMounts> {
        &self.mounts
    }
    pub fn file_table_id(&self) -> FileTableId {
        self.files.id()
    }
    pub fn fs_context(&self) -> &FsContext {
        &self.fs_context
    }
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
    pub fn env(&self) -> &[Vec<u8>] {
        &self.env
    }
}

#[derive(Debug)]
pub struct BootIdentity<V> {
    pub task: VmLocal<V, TaskKey>,
    pub thread: VmLocal<V, ThreadKey>,
    pub mm: VmLocal<V, MmId>,
    pub container: ContainerId,
    pub revision: super::TaskRevision,
    pub affinity: carrick_hal::CpuAffinity,
    pub identity: TaskIdentity,
    pub namespace: VisibleNamespace,
    pub namespace_pid: VisibleIdentity,
    pub namespace_tid: VisibleIdentity,
    pub namespace_process_group: VisibleIdentity,
    pub namespace_session: VisibleIdentity,
    pub diagnostic_name: String,
}

/// Non-Clone custody removed from one source. Only consuming this value can
/// hand the allocator and actual resources to the native boot transport.
#[derive(Debug)]
pub struct BootLaunchExport<V> {
    pub identity: BootIdentity<V>,
    pub namespaces: TransferredNamespaceState,
    pub serials: VmLocal<V, TransferredSerialAllocator>,
    pub resources: BootLaunchResources,
}

#[derive(Debug, Default)]
pub(super) struct BootLaunchAuthority {
    pub(super) state: BootLaunchState,
    pub(super) exports: u64,
    pub(super) refused: u64,
    pub(super) semantic_refused: u64,
}
#[derive(Debug, Default)]
pub(super) enum BootLaunchState {
    #[default]
    Unadopted,
    Adopted(BootLaunchResources),
    Exported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootExportReceipt {
    pub exports: u64,
    pub refused: Option<u64>,
    pub semantic_refusals: Option<u64>,
    pub namespace_refusals: Option<u64>,
    pub object_refusals: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BootExportError {
    #[error("launch resources have not been adopted")]
    Unadopted,
    #[error("launch resources were already adopted or exported")]
    AlreadyAdopted,
    #[error("launch identity authority was already exported")]
    AlreadyExported,
    #[error("boot transfer requires the exact sole private launch root")]
    RootScope,
    #[error("bootstrap allocation authority was transferred separately")]
    AllocatorTransferred,
}
