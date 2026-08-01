//! `carrick-dsr-aarch64` — the AArch64 guest-ISA half of the native (DSR)
//! execution backend: bad64 decode/classification, block planning (including
//! exclusive-region fusion analysis), dynasmrt emission, the gateway context
//! and its `gateway_aarch64.S` entry/exit surface, the CNTVCT/Apple-timebase
//! counter plan, and the per-block artifact-spike store.
//!
//! The whole crate compiles on every host (bad64/dynasmrt are pure Rust);
//! only the gateway's assembled half is target-gated — one
//! `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]` boundary in
//! `gateway`, mirrored by this crate's `build.rs`. Off that lane the gateway
//! entry points fail closed with `DsrError::Gateway`.
//!
//! Extracted verbatim from `carrick-runtime/src/native_darwin/dsr` (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! while the extraction is staged the runtime re-exports these modules under
//! their old paths so call sites are unchanged. The live-execution oracle
//! (`dsr/oracle.rs`) stays in the runtime: every one of its tests drives the
//! Darwin JIT, the assembled gateway, or the C trap shim, none of which link
//! from this crate before the host-seam slice (M0.6) lands.

pub mod artifact_spike;
pub mod block;
pub mod counter;
pub mod decode;
pub mod direct_binding;
pub mod emit;
pub mod emulate;
pub mod esr;
pub mod gateway;
pub mod mapped_memory;
pub mod mapped_metadata;
// The prepared-image schema moved to `carrick-dsr` (the platform-neutral
// crate) as part of the staged native-backend extraction: it is ISA-free
// (Task 6, docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md).
// Re-exported under its old path so every `carrick_dsr_aarch64::prepared_image::…`
// call site (notably `carrick-runtime`'s `native_prepared_image.rs` shim) is
// unchanged.
pub use carrick_dsr::prepared_image;
pub mod shared_cache;
pub mod snapshot;
pub mod translator;
pub mod types;

/// AArch64 guest ISA implementation for the DSR lane seam.
pub struct Aarch64Isa;

impl carrick_dsr::lane::GuestIsa for Aarch64Isa {
    const NAME: &'static str = "aarch64";
    const USER_VA_END_EXCLUSIVE: u64 = 1u64 << 48;
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::GuestIsa;

    #[test]
    fn aarch64_isa_constants() {
        assert_eq!(Aarch64Isa::NAME, "aarch64");
        assert_eq!(Aarch64Isa::USER_VA_END_EXCLUSIVE, 1u64 << 48);
    }
}

#[cfg(test)]
mod direct_binding_tests {
    use super::direct_binding::{
        DirectBindingCellRef, DirectBindingCellVa, DirectBindingTarget, DirectBindingTargetPrefix,
        PrivateJitEpoch,
    };
    use crate::types::CodeGeneration;
    use carrick_guest_mem::GuestVa;
    use std::sync::atomic::AtomicPtr;
    use std::sync::{Arc, Barrier};

    fn prefix_bytes(prefix: &DirectBindingTargetPrefix) -> [u8; 32] {
        let mut bytes = [0; 32];
        // SAFETY: `DirectBindingTargetPrefix` has an asserted 32-byte layout,
        // and both source and destination are valid for exactly that size.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(prefix).cast::<u8>(),
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        bytes
    }

    fn private_target(
        prefix: DirectBindingTargetPrefix,
        epoch: &Arc<PrivateJitEpoch>,
    ) -> Box<DirectBindingTarget> {
        Box::new(DirectBindingTarget::private(
            prefix,
            GuestVa(0x40_000),
            CodeGeneration::claimed(7),
            epoch,
        ))
    }

    #[test]
    fn one_word_publication_never_mixes_target_and_authority() {
        const ROUNDS: usize = 10_000;

        let epoch = PrivateJitEpoch::process_owner();
        let target_a = private_target(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x1000,
                cache_start: 0x1000,
                cache_end: 0x2000,
                generation_bindings: 0x3000,
            },
            &epoch,
        );
        let target_b = private_target(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x8000,
                cache_start: 0x8000,
                cache_end: 0x9000,
                generation_bindings: 0xa000,
            },
            &epoch,
        );
        let expected_a = prefix_bytes(&target_a.prefix);
        let expected_b = prefix_bytes(&target_b.prefix);
        let target_a_address = std::ptr::from_ref(target_a.as_ref()) as usize;
        let target_b_address = std::ptr::from_ref(target_b.as_ref()) as usize;

        let storage = Arc::new(AtomicPtr::<DirectBindingTarget>::new(std::ptr::null_mut()));
        let address = DirectBindingCellVa::mapped(std::ptr::from_ref(storage.as_ref()) as usize)
            .expect("AtomicPtr storage is mapped and naturally aligned");
        // SAFETY: `storage` remains allocated and mapped until both publisher
        // threads have joined and the final acquired load has completed.
        let cell = unsafe {
            DirectBindingCellRef::from_mapped_address(address)
                .expect("mapped AtomicPtr storage is a valid direct-binding cell")
        };

        let publish_barrier = Arc::new(Barrier::new(3));
        let published_barrier = Arc::new(Barrier::new(3));
        let publisher = |target_address: usize| {
            let publish_barrier = Arc::clone(&publish_barrier);
            let published_barrier = Arc::clone(&published_barrier);
            std::thread::spawn(move || {
                let target = target_address as *mut DirectBindingTarget;
                for _ in 0..ROUNDS {
                    publish_barrier.wait();
                    let _ = cell.publish_null(target);
                    published_barrier.wait();
                }
            })
        };
        let publisher_a = publisher(target_a_address);
        let publisher_b = publisher(target_b_address);

        for _ in 0..ROUNDS {
            cell.clear_release();
            publish_barrier.wait();
            published_barrier.wait();

            let winner = cell.load_acquire();
            assert!(!winner.is_null(), "one racing publisher must win");
            // SAFETY: the acquire load observed one of the two retained,
            // immutable descriptors, both of which outlive the publisher
            // threads and this read.
            let observed = unsafe { prefix_bytes(&(*winner).prefix) };
            assert!(
                observed == expected_a || observed == expected_b,
                "acquired prefix must be one complete published descriptor"
            );
        }

        publisher_a.join().expect("publisher A must finish");
        publisher_b.join().expect("publisher B must finish");
    }

    #[test]
    fn exact_pointer_clear_cannot_erase_a_newer_publication() {
        let epoch = PrivateJitEpoch::process_owner();
        let old_target = private_target(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x1000,
                cache_start: 0x1000,
                cache_end: 0x2000,
                generation_bindings: 0x3000,
            },
            &epoch,
        );
        let new_target = private_target(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x8000,
                cache_start: 0x8000,
                cache_end: 0x9000,
                generation_bindings: 0xa000,
            },
            &epoch,
        );
        let old_pointer = std::ptr::from_ref(old_target.as_ref()).cast_mut();
        let new_pointer = std::ptr::from_ref(new_target.as_ref()).cast_mut();

        let storage = AtomicPtr::<DirectBindingTarget>::new(std::ptr::null_mut());
        let address = DirectBindingCellVa::mapped(std::ptr::from_ref(&storage) as usize)
            .expect("AtomicPtr storage is mapped and naturally aligned");
        // SAFETY: `storage` remains live for every access through `cell`.
        let cell = unsafe {
            DirectBindingCellRef::from_mapped_address(address)
                .expect("mapped AtomicPtr storage is a valid direct-binding cell")
        };

        assert_eq!(cell.publish_null(old_pointer), Ok(()));
        assert!(cell.clear_if(old_pointer));
        assert_eq!(cell.publish_null(new_pointer), Ok(()));

        assert!(!cell.clear_if(old_pointer));
        assert_eq!(cell.load_acquire(), new_pointer);
    }

    #[test]
    fn mapped_cell_rejects_zero_and_unaligned_addresses() {
        let alignment = std::mem::align_of::<AtomicPtr<DirectBindingTarget>>();

        assert_eq!(DirectBindingCellVa::mapped(0), None);
        assert_eq!(DirectBindingCellVa::mapped(alignment + 1), None);
        assert_eq!(
            DirectBindingCellVa::mapped(alignment * 2).map(DirectBindingCellVa::get),
            Some(alignment * 2)
        );
    }

    #[test]
    fn private_epoch_reports_live_descriptor_leases() {
        let epoch = PrivateJitEpoch::process_owner();
        assert_eq!(Arc::strong_count(&epoch), 1);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 0);

        let first = private_target(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x1000,
                cache_start: 0x1000,
                cache_end: 0x2000,
                generation_bindings: 0x3000,
            },
            &epoch,
        );
        assert_eq!(Arc::strong_count(&epoch), 2);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 1);

        let second = private_target(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x8000,
                cache_start: 0x8000,
                cache_end: 0x9000,
                generation_bindings: 0xa000,
            },
            &epoch,
        );
        assert_eq!(Arc::strong_count(&epoch), 3);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 2);

        drop(first);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 1);
        drop(second);
        assert_eq!(Arc::strong_count(&epoch), 1);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 0);
    }
}
