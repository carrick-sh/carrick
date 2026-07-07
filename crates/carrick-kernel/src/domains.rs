//! Typed identity domains for arena state. Raw integers cross only at the
//! `#[repr(C)]` slot layouts and host libc calls; constructors name the
//! crossing (`HostPid::new(libc::getpid() as u32)`).

/// A host (Darwin/Linux/BSD) process id as stored in arena slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HostPid(u32);

/// Monotonic per-process-record generation defeating pid reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ProcessGeneration(u32);

/// Monotonic per-lease generation defeating stale release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct LeaseGeneration(u32);

/// Bumped on successful `execve`; late releases stamped with the old image
/// generation must not apply to the new image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ExecGeneration(u32);

/// Hash-bucket key for multi-record critical sections (futex requeue, SysV).
/// Lock ordering is by ascending `BucketKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BucketKey(u64);

/// Run-scope token mixed into the arena header (hash of `CARRICK_RUN_ID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct RunToken(u64);

macro_rules! domain_impl {
    ($name:ident, $raw:ty) => {
        impl $name {
            pub const fn new(raw: $raw) -> Self {
                Self(raw)
            }

            pub const fn raw(self) -> $raw {
                self.0
            }
        }
    };
}

domain_impl!(HostPid, u32);
domain_impl!(ProcessGeneration, u32);
domain_impl!(LeaseGeneration, u32);
domain_impl!(ExecGeneration, u32);
domain_impl!(BucketKey, u64);
domain_impl!(RunToken, u64);

impl ProcessGeneration {
    /// Reserved: "no owner". Arena generation counters start at 1.
    pub const NONE: ProcessGeneration = ProcessGeneration(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_round_trip_and_do_not_mix() {
        let pid = HostPid::new(1234);
        assert_eq!(pid.raw(), 1234);
        let generation = ProcessGeneration::new(7);
        assert_eq!(generation.raw(), 7);
        // Generation 0 is reserved for "no owner" everywhere in the arena.
        assert!(ProcessGeneration::NONE.raw() == 0);
        let key = BucketKey::new(0xdead_beef);
        assert_eq!(key.raw(), 0xdead_beef);
    }
}
