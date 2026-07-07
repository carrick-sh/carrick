//! carrick-kernel: the per-run KERNEL ARENA -- one file-backed `MAP_SHARED`
//! region holding the Linux-visible cross-process delta (identity, leases,
//! shared kernel objects) that the host kernel cannot express. There is NO
//! authority daemon: processes operate on the arena with atomics and robust
//! bucket locks; the run supervisor only sweeps after hard death.
//! Spec: docs/superpowers/specs/2026-07-06-carrick-kernel-authority-design.md.

pub mod domains;
