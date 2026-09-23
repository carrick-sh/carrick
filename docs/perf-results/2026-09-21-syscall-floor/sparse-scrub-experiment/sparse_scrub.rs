use carrick_guest_mem::{DeferredAnonymousState, MemoryError};

pub(super) fn scrub_materialized_ranges(
    enabled: bool,
    deferred: Option<&DeferredAnonymousState>,
    address: u64,
    len: usize,
    mut scrub: impl FnMut(u64, usize) -> Result<(), MemoryError>,
) -> Result<(), MemoryError> {
    // Invalid ranges must reach the original validator, never become an empty
    // successful enumeration. Missing pristine authority also keeps the old path.
    let valid = len != 0
        && u64::try_from(len)
            .ok()
            .and_then(|n| address.checked_add(n))
            .is_some();
    let Some(deferred) = deferred.filter(|_| enabled && valid) else {
        return scrub(address, len);
    };
    // Exact-MM pristine provenance is authoritative; absent translations are not.
    // Release its lock before invoking COW preparation or backend maintenance.
    for range in deferred.materialized_subranges(carrick_guest_mem::GuestVa(address), len) {
        scrub(
            range.start.raw(),
            (range.end.raw() - range.start.raw()) as usize,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use carrick_guest_mem::GuestVa;
    use std::hash::{Hash, Hasher};

    #[test]
    fn sparse_scrub_contract() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry = ContractRegistry::load(root).unwrap();
        let mut source = std::collections::hash_map::DefaultHasher::new();
        include_str!("sparse_scrub.rs").hash(&mut source);
        include_str!("engine.rs").hash(&mut source);
        let mut observations = Vec::new();
        for scale in [1_u64, 8, 32, 128] {
            let state = DeferredAnonymousState::new();
            let len = scale as usize * 4096;
            let base = 0x1000;
            state.reserve_fresh(GuestVa(base), len).unwrap();
            let mut bytes = vec![0; len];
            let mut zeroed = 0;
            scrub_materialized_ranges(true, Some(&state), base, len, |start, length| {
                zeroed += length as u64;
                let offset = (start - base) as usize;
                bytes[offset..offset + length].fill(0);
                Ok(())
            })
            .unwrap();
            state
                .begin_materialization(GuestVa(base), 4096)
                .unwrap()
                .commit();
            bytes[..4096].fill(91);
            let provenance = state.snapshot();
            scrub_materialized_ranges(true, Some(&state), base, len, |start, length| {
                zeroed += length as u64;
                let offset = (start - base) as usize;
                bytes[offset..offset + length].fill(0);
                Ok(())
            })
            .unwrap();
            assert!(bytes.iter().all(|b| *b == 0));
            assert_eq!(provenance, state.snapshot());
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::GuestMemoryZeroBytes, zeroed)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.sparse-scrub").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: format!("source-default-hasher:{:016x}", source.finish()),
                fixture_identity: "unit:sparse-scrub".into(),
                scale,
                semantic_assertions: vec![SemanticAssertion::pass(
                    "all_bytes_zero_and_provenance_preserved",
                )],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
        println!("{observations:#?}");
        evaluate(
            registry.require("kernel.mm.sparse-scrub").unwrap(),
            &observations,
        )
        .unwrap();
    }
    #[test]
    fn fallback_and_invalid_ranges_preserve_backend_errors() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(4096), 4096).unwrap();
        for (enabled, authority, address, len) in [
            (false, Some(&state), 4096, 4096),
            (true, None, 4096, 4096),
            (true, Some(&state), u64::MAX, 4096),
            (true, Some(&state), 4096, 0),
        ] {
            let mut calls = Vec::new();
            let result = scrub_materialized_ranges(enabled, authority, address, len, |a, n| {
                calls.push((a, n));
                Err(MemoryError::Unsupported)
            });
            assert!(matches!(result, Err(MemoryError::Unsupported)));
            assert_eq!(calls, [(address, len)]);
        }
    }

    #[test]
    fn unknown_gaps_are_scrubbed_and_errors_stop_processing() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(8192), 4096).unwrap();
        let mut calls = Vec::new();
        scrub_materialized_ranges(true, Some(&state), 4096, 12288, |a, n| {
            calls.push((a, n));
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, [(4096, 4096), (12288, 4096)]);
        calls.clear();
        let result = scrub_materialized_ranges(true, Some(&state), 4096, 12288, |a, n| {
            calls.push((a, n));
            Err(MemoryError::Unsupported)
        });
        assert!(matches!(result, Err(MemoryError::Unsupported)));
        assert_eq!(calls, [(4096, 4096)]);
    }
}
