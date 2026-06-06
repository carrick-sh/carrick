//! Host facts the runtime needs (cpu count, memory, own exe path). macOS impl
//! lives in `carrick-host`; FreeBSD/Linux arms are new code in their backends.

use crate::error::OsError;
use std::path::PathBuf;

pub trait HostFacts {
    fn logical_cpus(&self) -> usize;
    fn total_memory(&self) -> u64;
    fn current_exe_path(&self) -> Result<PathBuf, OsError>;
}
