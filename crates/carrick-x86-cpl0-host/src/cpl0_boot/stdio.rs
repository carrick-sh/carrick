//! The carrier's custody of the zone's standard descriptions (#2820).
//!
//! Linux gives a process stdin, stdout and stderr only by inheritance: the
//! launcher's descriptors, then fork's copy. The stopped carrier is the
//! launcher here. It admits the three descriptions once, into the first
//! table it binds to an initial task and before that task runs, and keeps
//! the [`StdioDescriptions`] it gets back; a later bound table shares them. No guest path admits stdio, so every
//! other table holds them only by fork, and a number a process closed stays
//! closed. The guest's release of a description's last reference must
//! present exactly the identity this custody holds, once.

use carrick_el1_abi::{DelegatedFile, DelegatedOpenFile, FdMapSlot, HostObjectBinding};
use carrick_el1_linux::file_table::{
    ReleasedDescription, StdioAdmissionError, StdioDescriptions, rename_unstarted_table,
};

/// The zone's stdio descriptions once the carrier has bound a table, the
/// boot tables that reference them, and which ones the guest has released.
#[derive(Debug, Default)]
pub(crate) struct StdioCustody {
    descriptions: Option<StdioDescriptions>,
    tables: Vec<u64>,
    released: [bool; 3],
}

/// Why the carrier refuses a guest's stdio release: each is a broken
/// invariant, never contention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioReleaseRefusal {
    /// The binding names no stdio route.
    NotStdio { binding: u64 },
    /// The carrier has bound no table, so it admitted no stdio.
    NotAdmitted { binding: HostObjectBinding },
    /// The presented description is not the one the carrier admitted for
    /// this binding.
    Foreign {
        binding: HostObjectBinding,
        presented: ReleasedDescription,
        admitted: ReleasedDescription,
    },
    /// The admitted description was already released.
    Duplicate {
        binding: HostObjectBinding,
        admitted: ReleasedDescription,
    },
}

impl core::fmt::Display for StdioReleaseRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotStdio { binding } => {
                write!(f, "host object release names no stdio binding ({binding})")
            }
            Self::NotAdmitted { binding } => write!(
                f,
                "host object release of binding {} before the carrier admitted stdio",
                binding.encoded()
            ),
            Self::Foreign {
                binding,
                presented,
                admitted,
            } => write!(
                f,
                "host object release identity mismatch: binding {}, handle {} incarnation {} \
                 (admitted handle {} incarnation {})",
                binding.encoded(),
                presented.handle,
                presented.incarnation,
                admitted.handle,
                admitted.incarnation
            ),
            Self::Duplicate { binding, admitted } => write!(
                f,
                "duplicate host object release: binding {}, handle {} incarnation {}",
                binding.encoded(),
                admitted.handle,
                admitted.incarnation
            ),
        }
    }
}

impl StdioCustody {
    /// Give `table`, which the stopped carrier binds to an initial task, the
    /// zone's stdio once: the first bound table admits the descriptions, a
    /// later one shares them, and a table already bound keeps what it has.
    pub(crate) fn bind_table(
        &mut self,
        fd_map: &[FdMapSlot],
        opens: &[DelegatedOpenFile],
        objects: &[DelegatedFile],
        table: u64,
    ) -> Result<(), StdioAdmissionError> {
        if self.tables.contains(&table) {
            return Ok(());
        }
        match &self.descriptions {
            Some(descriptions) => descriptions.share_into(fd_map, opens, table)?,
            None => {
                self.descriptions = Some(StdioDescriptions::admit(fd_map, opens, objects, table)?);
            }
        }
        self.tables.push(table);
        Ok(())
    }

    /// The stopped boot task, which has not run, takes the table its issued
    /// identity names in place of its provisional one; a provisional table
    /// the carrier never bound is simply replaced by a bound `to`.
    pub(crate) fn rename_unstarted(
        &mut self,
        fd_map: &[FdMapSlot],
        opens: &[DelegatedOpenFile],
        objects: &[DelegatedFile],
        from: u64,
        to: u64,
    ) -> Result<(), StdioAdmissionError> {
        if from == to {
            return self.bind_table(fd_map, opens, objects, to);
        }
        let Some(position) = self.tables.iter().position(|table| *table == from) else {
            return self.bind_table(fd_map, opens, objects, to);
        };
        if self.tables.contains(&to) || !rename_unstarted_table(fd_map, from, to) {
            return Err(StdioAdmissionError::TableHasStdio);
        }
        self.tables[position] = to;
        Ok(())
    }

    /// The guest released the last reference to a stdio description. It must
    /// present the exact description admitted for `binding`, once. Returns
    /// the stdio descriptor number the description was admitted as.
    pub(crate) fn release(
        &mut self,
        binding: u64,
        presented: ReleasedDescription,
    ) -> Result<i32, StdioReleaseRefusal> {
        let object = u32::try_from(binding)
            .ok()
            .and_then(HostObjectBinding::from_encoded)
            .filter(|object| object.stdio_fd().is_some())
            .ok_or(StdioReleaseRefusal::NotStdio { binding })?;
        let fd = object
            .stdio_fd()
            .ok_or(StdioReleaseRefusal::NotStdio { binding })?;
        let admitted = self
            .descriptions
            .as_ref()
            .ok_or(StdioReleaseRefusal::NotAdmitted { binding: object })?
            .key(object)
            .ok_or(StdioReleaseRefusal::NotStdio { binding })?;
        if presented != admitted {
            return Err(StdioReleaseRefusal::Foreign {
                binding: object,
                presented,
                admitted,
            });
        }
        let released = &mut self.released[fd as usize];
        if *released {
            return Err(StdioReleaseRefusal::Duplicate {
                binding: object,
                admitted,
            });
        }
        *released = true;
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_el1_abi::{FD_MAP_CAPACITY, MAX_ZONE_OPEN_FILES, fd_map_lookup};

    struct Tables {
        fd_map: Vec<FdMapSlot>,
        opens: Vec<DelegatedOpenFile>,
        objects: Vec<DelegatedFile>,
    }

    impl Tables {
        fn new() -> Self {
            Self {
                fd_map: (0..FD_MAP_CAPACITY).map(|_| FdMapSlot::new()).collect(),
                opens: (0..MAX_ZONE_OPEN_FILES)
                    .map(|_| DelegatedOpenFile::new())
                    .collect(),
                objects: (0..64).map(|_| DelegatedFile::new()).collect(),
            }
        }
        fn bind(&self, stdio: &mut StdioCustody, table: u64) {
            stdio
                .bind_table(&self.fd_map, &self.opens, &self.objects, table)
                .unwrap();
        }
    }

    /// #2820's refused record: a release naming stdout with any description
    /// but the admitted one is foreign; the admitted one releases once.
    #[test]
    fn release_presents_the_admitted_description_once() {
        let storage = Tables::new();
        let mut stdio = StdioCustody::default();
        let unbound = ReleasedDescription {
            handle: 2,
            incarnation: 1,
        };
        assert_eq!(
            stdio.release(2, unbound),
            Err(StdioReleaseRefusal::NotAdmitted {
                binding: HostObjectBinding::STDOUT
            })
        );
        storage.bind(&mut stdio, 5);
        let stdout = stdio
            .descriptions
            .as_ref()
            .unwrap()
            .key(HostObjectBinding::STDOUT)
            .unwrap();
        let foreign = ReleasedDescription {
            handle: 5,
            incarnation: 1,
        };
        assert_eq!(
            stdio.release(2, foreign),
            Err(StdioReleaseRefusal::Foreign {
                binding: HostObjectBinding::STDOUT,
                presented: foreign,
                admitted: stdout,
            })
        );
        assert_eq!(
            stdio.release(9, stdout),
            Err(StdioReleaseRefusal::NotStdio { binding: 9 })
        );
        assert_eq!(stdio.release(2, stdout), Ok(1));
        assert_eq!(
            stdio.release(2, stdout),
            Err(StdioReleaseRefusal::Duplicate {
                binding: HostObjectBinding::STDOUT,
                admitted: stdout,
            })
        );
    }

    #[test]
    fn boot_tables_share_one_admission_and_rename_before_running() {
        let storage = Tables::new();
        let (fd_map, opens, objects) = (&storage.fd_map, &storage.opens, &storage.objects);
        let mut stdio = StdioCustody::default();
        // A provisional table the carrier never bound: the issued one admits.
        stdio
            .rename_unstarted(fd_map, opens, objects, 0, 5)
            .unwrap();
        storage.bind(&mut stdio, 5);
        stdio
            .rename_unstarted(fd_map, opens, objects, 5, 77)
            .unwrap();
        assert!(fd_map_lookup(fd_map, 5, 1).is_none());
        storage.bind(&mut stdio, 77);
        storage.bind(&mut stdio, 6);
        let stdout = stdio
            .descriptions
            .as_ref()
            .unwrap()
            .key(HostObjectBinding::STDOUT)
            .unwrap();
        for table in [6, 77] {
            assert_eq!(fd_map_lookup(fd_map, table, 1).unwrap().0, stdout.handle);
        }
        assert_eq!(
            opens[stdout.handle as usize - 1]
                .lifetime
                .ring_references(stdout.incarnation),
            Some(2),
            "one admission, shared by reference"
        );
        assert_eq!(
            stdio.rename_unstarted(fd_map, opens, objects, 77, 6),
            Err(StdioAdmissionError::TableHasStdio)
        );
    }
}
