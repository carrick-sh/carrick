//! Native adapter for the shared prepared close-on-exec transaction.

extern crate alloc;

use super::{GUEST_FD_CLOEXEC, ReleasedDescription, release_reference};
use alloc::vec::Vec;
use carrick_el1_abi::{DelegatedOpenFile, FD_MAP_CAPACITY, FdMapSlot, lock_fd_map};
use core::sync::atomic::Ordering;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeExecFdError {
    InvalidTable,
    NoMemory,
    StaleDescriptor,
}

/// Exact ring-owned descriptor table custody captured under process admission.
pub struct NativeTableCustody<'a> {
    task: carrick_sched_core::process::TaskKey,
    file_table: u64,
    fd_map: &'a [FdMapSlot],
    open_table: &'a [DelegatedOpenFile],
}

impl<'a> NativeTableCustody<'a> {
    pub(crate) fn capture(
        task: carrick_sched_core::process::TaskKey,
        file_table: u64,
        fd_map: &'a [FdMapSlot],
        open_table: &'a [DelegatedOpenFile],
    ) -> Result<Self, NativeExecFdError> {
        if file_table == 0 || fd_map.is_empty() {
            return Err(NativeExecFdError::InvalidTable);
        }
        Ok(Self {
            task,
            file_table,
            fd_map,
            open_table,
        })
    }

    pub fn file_table(&self) -> u64 {
        self.file_table
    }
}

struct NativeExecFdEntry {
    descriptor: carrick_fd_core::exec::ExecDescriptor,
    slot: usize,
    release: Option<ReleasedDescription>,
}

pub struct NativeCloseOnExecStage<'a> {
    custody: NativeTableCustody<'a>,
    entries: Vec<NativeExecFdEntry>,
    cursor: usize,
    closed: Vec<usize>,
    releases: Vec<ReleasedDescription>,
    guard: carrick_el1_abi::FdMapMutationGuard<'a>,
}

/// Physical open-reference obligations retained beyond descriptor publication.
#[must_use]
pub struct NativeExecReleases<'a> {
    open_table: &'a [DelegatedOpenFile],
    file_table: u64,
    releases: Vec<ReleasedDescription>,
    _guard: carrick_el1_abi::FdMapMutationGuard<'a>,
}

impl Drop for NativeExecReleases<'_> {
    fn drop(&mut self) {
        for release in self.releases.drain(..) {
            release_reference(self.open_table, release, self.file_table);
        }
    }
}

impl<'a> carrick_fd_core::exec::TableCustody for NativeTableCustody<'a> {
    type Error = NativeExecFdError;
    type Stage = NativeCloseOnExecStage<'a>;

    fn exact_task(&self) -> carrick_sched_core::process::TaskKey {
        self.task
    }

    fn stage(self) -> Result<Self::Stage, carrick_fd_core::exec::PrepareError<Self, Self::Error>> {
        let staged = (|| {
            let guard = lock_fd_map(self.fd_map).ok_or(NativeExecFdError::InvalidTable)?;
            let capacity = self
                .fd_map
                .iter()
                .take(FD_MAP_CAPACITY)
                .filter(|slot| {
                    let incarnation = slot.incarnation.load(Ordering::Acquire);
                    incarnation != 0
                        && incarnation != FdMapSlot::CLAIMED
                        && slot.file_table.load(Ordering::Relaxed) == self.file_table
                        && slot.handle.load(Ordering::Relaxed) != 0
                })
                .count();
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(capacity)
                .map_err(|_| NativeExecFdError::NoMemory)?;
            let mut closed = Vec::new();
            closed
                .try_reserve_exact(capacity)
                .map_err(|_| NativeExecFdError::NoMemory)?;
            let mut releases = Vec::new();
            releases
                .try_reserve_exact(capacity)
                .map_err(|_| NativeExecFdError::NoMemory)?;
            for (index, slot) in self.fd_map.iter().take(FD_MAP_CAPACITY).enumerate() {
                let incarnation = slot.incarnation.load(Ordering::Acquire);
                let handle = slot.handle.load(Ordering::Relaxed);
                if incarnation == 0
                    || incarnation == FdMapSlot::CLAIMED
                    || slot.file_table.load(Ordering::Relaxed) != self.file_table
                    || handle == 0
                {
                    continue;
                }
                let flags = slot.fd_flags.load(Ordering::Relaxed);
                let fd = i32::try_from(slot.fd.load(Ordering::Relaxed))
                    .map_err(|_| NativeExecFdError::StaleDescriptor)?;
                entries.push(NativeExecFdEntry {
                    descriptor: carrick_fd_core::exec::ExecDescriptor {
                        fd: carrick_fd_core::Fd(fd),
                        close_on_exec: flags & GUEST_FD_CLOEXEC != 0,
                    },
                    slot: index,
                    release: (flags & FdMapSlot::HOST_VIEW == 0
                        && handle & carrick_el1_abi::FD_HANDLE_INOTIFY_TAG == 0)
                        .then_some(ReleasedDescription {
                            handle,
                            incarnation,
                        }),
                });
            }
            Ok((guard, entries, closed, releases))
        })();
        match staged {
            Ok((guard, entries, closed, releases)) => Ok(NativeCloseOnExecStage {
                custody: self,
                entries,
                cursor: 0,
                closed,
                releases,
                guard,
            }),
            Err(error) => Err(carrick_fd_core::exec::PrepareError::venue(error, self)),
        }
    }
}

impl<'a> carrick_fd_core::exec::CloseOnExecStage for NativeCloseOnExecStage<'a> {
    type Custody = NativeTableCustody<'a>;
    type Error = NativeExecFdError;
    type Releases = NativeExecReleases<'a>;

    fn next_descriptor(&mut self) -> Option<carrick_fd_core::exec::ExecDescriptor> {
        let entry = self.entries.get(self.cursor)?;
        self.cursor += 1;
        Some(entry.descriptor)
    }

    fn retain_closed(&mut self, fd: carrick_fd_core::Fd) -> Result<(), Self::Error> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.descriptor.fd == fd)
            .ok_or(NativeExecFdError::StaleDescriptor)?;
        self.closed.push(index);
        if let Some(release) = self.entries[index].release {
            self.releases.push(release);
        }
        Ok(())
    }

    fn finish_preparation(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn rollback(self) -> Self::Custody {
        self.custody
    }

    fn commit(self) -> (Self::Custody, Self::Releases) {
        let Self {
            custody,
            entries,
            cursor: _,
            closed,
            releases,
            guard,
        } = self;
        for index in closed {
            let entry = &entries[index];
            custody.fd_map[entry.slot].clear();
        }
        let obligations = NativeExecReleases {
            open_table: custody.open_table,
            file_table: custody.file_table,
            releases,
            _guard: guard,
        };
        (custody, obligations)
    }
}
