//! Host graph adapter for the shared prepared descriptor cutover protocol.
//! Task lifecycle admission is retained by PreparedExec; this owner retains
//! the file-table freeze and physical obligations through graph publication.
use std::sync::Arc;

use carrick_abi::{LINUX_EBADF, LINUX_ENOMEM, LINUX_ESRCH, LinuxErrno};
use carrick_fd_core::Fd;
use carrick_fd_core::exec::{
    CloseOnExecStage, ExecDescriptor, PreparationError, PrepareError, TableCustody,
};

use super::core::{FileCloseBatch, FileCloseDisposition, FileCloseEvent, Kernel, KernelContext};
use super::objects::{FileDescriptionFdLease, FileTable, FileTableExecFreeze, TaskKey};

/// Exact host graph table custody. Only the lifecycle owner can capture it;
/// callers cannot manufacture a binding from a `TaskKey` and an `Arc<FileTable>`.
pub struct HostTableCustody {
    kernel: Arc<Kernel>,
    task: TaskKey,
    files: Arc<FileTable>,
}

#[derive(Debug)]
pub enum HostPrepareError {
    StaleTask,
    Draining,
    NoMemory,
}

pub fn prepare_errno(error: &PreparationError<HostPrepareError>) -> LinuxErrno {
    match error {
        PreparationError::WrongTask | PreparationError::Venue(HostPrepareError::StaleTask) => {
            LINUX_ESRCH
        }
        PreparationError::Venue(HostPrepareError::Draining) => LINUX_EBADF,
        PreparationError::Venue(HostPrepareError::NoMemory) => LINUX_ENOMEM,
    }
}

impl HostTableCustody {
    pub(super) fn capture(
        kernel: &Arc<Kernel>,
        context: &KernelContext,
    ) -> Result<Self, HostPrepareError> {
        if !Arc::ptr_eq(kernel, &context.kernel) {
            return Err(HostPrepareError::StaleTask);
        }
        let custody = Self {
            kernel: Arc::clone(kernel),
            task: context.task.key(),
            files: context.resources.files(),
        };
        custody.validate()?;
        Ok(custody)
    }

    fn validate(&self) -> Result<(), HostPrepareError> {
        let state = self.kernel.registry().settled().read();
        let valid = state
            .tasks
            .get(&self.task.id)
            .filter(|record| record.task.key() == self.task)
            .is_some_and(|record| record.task.owns_file_table(&self.files));
        if valid {
            Ok(())
        } else {
            Err(HostPrepareError::StaleTask)
        }
    }
}

/// Fields drop in this order: private table and selected references before the
/// source thaws. None of the staged descriptor authority is publicly exposed.
pub struct HostCloseOnExecStage {
    successor: HostTableCustody,
    closed: Vec<FileDescriptionFdLease>,
    entries: std::vec::IntoIter<ExecDescriptor>,
    batch: Box<FileCloseBatch>,
    source: HostTableCustody,
    freeze: FileTableExecFreeze,
}

impl HostCloseOnExecStage {
    pub(super) fn files(&self) -> Arc<FileTable> {
        Arc::clone(&self.successor.files)
    }
}

/// Physical cleanup retained across graph publication. Drop settles once,
/// respecting live CLONE_FILES peers; the freeze is released last.
#[must_use]
pub struct HostExecReleases {
    source: HostTableCustody,
    batch: Option<Box<FileCloseBatch>>,
    _closed: Vec<FileDescriptionFdLease>,
    _freeze: FileTableExecFreeze,
}

impl Drop for HostExecReleases {
    fn drop(&mut self) {
        if !self
            .source
            .kernel
            .file_table_is_live_excluding(&self.source.files, None)
            && self.source.files.retire_functional_refs()
            && let Some(batch) = self.batch.take()
        {
            self.source.kernel.enqueue_file_close_batch(batch);
        }
    }
}

impl TableCustody for HostTableCustody {
    type Error = HostPrepareError;
    type Stage = HostCloseOnExecStage;

    fn exact_task(&self) -> TaskKey {
        self.task
    }

    fn stage(self) -> Result<Self::Stage, PrepareError<Self, Self::Error>> {
        // Borrow source until every fallible allocation/admission has finished;
        // on refusal these locals unwind before returning original custody.
        let staged = (|| {
            self.validate()?;
            let freeze = self
                .files
                .freeze_for_exec()
                .ok_or(HostPrepareError::Draining)?;
            self.validate()?;
            let id = self
                .kernel
                .object_ids()
                .file_table_id()
                .map_err(|_| HostPrepareError::NoMemory)?;
            let mut successor = FileTable::stage_exec_copy(id, &self.files);
            let (capacity, descriptors) = successor.exec_descriptors();
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(capacity)
                .map_err(|_| HostPrepareError::NoMemory)?;
            let mut closed = Vec::new();
            closed
                .try_reserve_exact(capacity)
                .map_err(|_| HostPrepareError::NoMemory)?;
            let mut events = Vec::new();
            events
                .try_reserve_exact(capacity)
                .map_err(|_| HostPrepareError::NoMemory)?;
            for (descriptor, slot) in descriptors {
                if let Some(slot) = slot {
                    events.push(FileCloseEvent {
                        fd: descriptor.fd.0,
                        slot,
                        disposition: FileCloseDisposition::Transferred,
                    });
                }
                entries.push(descriptor);
            }
            let successor = Arc::new(successor);
            let batch = Box::new(FileCloseBatch {
                table: self.files.id(),
                events,
                next: None,
            });
            Ok((successor, closed, entries.into_iter(), batch, freeze))
        })();
        match staged {
            Err(error) => Err(PrepareError::venue(error, self)),
            Ok((files, closed, entries, batch, freeze)) => {
                let successor = HostTableCustody {
                    kernel: Arc::clone(&self.kernel),
                    task: self.task,
                    files,
                };
                Ok(HostCloseOnExecStage {
                    successor,
                    closed,
                    entries,
                    batch,
                    source: self,
                    freeze,
                })
            }
        }
    }
}

impl CloseOnExecStage for HostCloseOnExecStage {
    type Custody = HostTableCustody;
    type Error = HostPrepareError;
    type Releases = HostExecReleases;

    fn next_descriptor(&mut self) -> Option<ExecDescriptor> {
        self.entries.next()
    }
    fn retain_closed(&mut self, fd: Fd) -> Result<(), Self::Error> {
        let files = Arc::get_mut(&mut self.successor.files).ok_or(HostPrepareError::Draining)?;
        if let Some(hold) = files.stage_exec_close(fd) {
            self.closed.push(hold);
        }
        Ok(())
    }
    fn finish_preparation(&mut self) -> Result<(), Self::Error> {
        let files = Arc::get_mut(&mut self.successor.files).ok_or(HostPrepareError::Draining)?;
        files.finish_exec_stage(&mut self.batch.events);
        Ok(())
    }
    fn rollback(self) -> Self::Custody {
        let Self {
            successor,
            closed,
            entries,
            batch,
            source,
            freeze,
        } = self;
        drop((successor, closed, entries, batch));
        drop(freeze);
        source
    }
    fn commit(self) -> (Self::Custody, Self::Releases) {
        let Self {
            successor,
            closed,
            entries: _,
            batch,
            source,
            freeze,
        } = self;
        (
            successor,
            HostExecReleases {
                source,
                batch: Some(batch),
                _closed: closed,
                _freeze: freeze,
            },
        )
    }
}
