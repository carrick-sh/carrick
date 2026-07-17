//! Identifier newtypes shared by the translation cache and its consumers.
//!
//! Moved verbatim from `carrick-runtime/src/native_darwin/dsr/types.rs` as
//! part of the staged native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! the runtime re-exports them under the old paths.

use carrick_guest_mem::HostVa;

/// Monotonic per-page guest-code generation. A published block is only
/// executable while every page it depends on still carries the generation it
/// was translated against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeGeneration(u64);

impl CodeGeneration {
    pub const INITIAL: Self = Self(0);

    pub const fn claimed(value: u64) -> Self {
        Self(value)
    }

    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Dense identifier for a translated block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(u64);

impl BlockId {
    pub const fn claimed(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Byte offset into a published block's code (e.g. a direct-link slot).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CacheOffset(u32);

impl CacheOffset {
    pub const fn published(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// EXEC-side host virtual address of published translation-cache code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheVa(HostVa);

impl CacheVa {
    pub const fn published(value: HostVa) -> Self {
        Self(value)
    }

    pub const fn host(self) -> HostVa {
        self.0
    }
}
