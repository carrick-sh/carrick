//! Bounded edge handling around a backend's aligned anonymous retirement.
use carrick_guest_mem::{GuestMemory, RepointPrivateError};

pub(crate) fn with_edges(
    memory: &mut impl GuestMemory,
    address: u64,
    len: usize,
    granule: u64,
) -> Result<bool, RepointPrivateError> {
    use carrick_guest_mem::MemoryError;
    let invalid = || {
        RepointPrivateError::clean(MemoryError::OutOfBounds {
            address,
            length: len,
        })
    };
    if !granule.is_power_of_two() || granule < 4096 || address % 4096 != 0 || len % 4096 != 0 {
        return Ok(false);
    }
    let end = address.checked_add(len as u64).ok_or_else(invalid)?;
    let start = address.checked_add(granule - 1).ok_or_else(invalid)? & !(granule - 1);
    let stop = end & !(granule - 1);
    if start >= stop {
        return Ok(false);
    }
    // The aligned path authenticates, removes translations, flushes, retires
    // aliases and publishes fresh-zero provenance before any edge COW work.
    // No retirement ticket survives an edge mutation of inventory generations.
    if !memory.discard_private_anonymous(start, (stop - start) as usize)? {
        return Ok(false);
    }
    for (edge, length) in [(address, start - address), (stop, end - stop)] {
        if length != 0 {
            memory
                .zero_backing(edge, length as usize)
                .map_err(RepointPrivateError::indeterminate)?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_mem::MemoryError;

    struct Memory {
        bytes: Vec<u8>,
        peer: Vec<u8>,
        scrubbed: usize,
        events: Vec<&'static str>,
        refuse: bool,
        fail_edge: usize,
        fail_retire: Option<RepointPrivateError>,
    }
    impl Memory {
        fn new(len: usize) -> Self {
            Self {
                bytes: vec![0x5a; len],
                peer: vec![0x5a; len],
                scrubbed: 0,
                events: Vec::new(),
                refuse: false,
                fail_edge: 0,
                fail_retire: None,
            }
        }
    }
    impl GuestMemory for Memory {
        fn read_bytes_raw(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
            Ok(self.bytes[address as usize..address as usize + len].to_vec())
        }
        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.bytes[address as usize..address as usize + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        fn discard_private_anonymous(
            &mut self,
            address: u64,
            len: usize,
        ) -> Result<bool, RepointPrivateError> {
            if let Some(error) = self.fail_retire.clone() {
                self.events.push("retire_failed");
                return Err(error);
            }
            if self.refuse || address % 16384 != 0 || len % 16384 != 0 {
                return Ok(false);
            }
            self.events.push("retire");
            self.bytes[address as usize..address as usize + len].fill(0);
            Ok(true)
        }
        fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
            self.events.push("edge");
            if self.fail_edge != 0
                && self.events.iter().filter(|&&e| e == "edge").count() == self.fail_edge
            {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: len,
                });
            }
            self.scrubbed += len;
            self.bytes[address as usize..address as usize + len].fill(0);
            Ok(())
        }
    }

    #[test]
    fn unaligned_discard_bounds_scrub_and_preserves_neighbors() {
        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        use sha2::{Digest, Sha256};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry = ContractRegistry::load(root).unwrap();
        let mut observations = Vec::new();
        for scale in [1, 8, 32, 128] {
            let mut max_scrubbed = 0;
            for head in [0, 4096, 8192, 12288] {
                for tail in [0, 4096, 8192, 12288] {
                    let start = 16384 + head;
                    let end = (scale + 3) * 16384 + tail;
                    let mut memory = Memory::new(end + 16384);
                    assert!(with_edges(&mut memory, start as u64, end - start, 16384).unwrap());
                    assert!(memory.bytes[..start].iter().all(|&b| b == 0x5a));
                    assert!(memory.bytes[start..end].iter().all(|&b| b == 0));
                    assert!(memory.bytes[end..].iter().all(|&b| b == 0x5a));
                    assert!(memory.peer.iter().all(|&b| b == 0x5a));
                    assert!(
                        memory.scrubbed <= 24576,
                        "scale={scale} head={head} tail={tail}"
                    );
                    max_scrubbed = max_scrubbed.max(memory.scrubbed);
                    assert_eq!(memory.events[0], "retire");
                }
            }
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::GuestMemoryZeroBytes, max_scrubbed as u64)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.anonymous-discard-edges").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: format!(
                    "sha256:{:x}",
                    Sha256::digest(include_bytes!("anonymous_discard.rs"))
                ),
                fixture_identity: "unit:anonymous-discard-edges".into(),
                scale: scale as u64,
                semantic_assertions: vec![SemanticAssertion {
                    name: "zeroed_range_neighbors_and_scripted_peer_preserved".into(),
                    passed: true,
                    detail: None,
                }],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
        evaluate(
            registry
                .require("kernel.mm.anonymous-discard-edges")
                .unwrap(),
            &observations,
        )
        .unwrap();
    }

    #[test]
    fn edge_failure_after_retirement_is_indeterminate() {
        for edge in [1, 2] {
            let mut memory = Memory::new(65536);
            memory.fail_edge = edge;
            assert!(matches!(
                with_edges(&mut memory, 4096, 49152, 16384),
                Err(RepointPrivateError::Indeterminate(_))
            ));
            assert_eq!(memory.events[0], "retire");
        }
    }

    #[test]
    fn refusal_and_empty_interior_do_not_mutate() {
        for (address, len, refuse) in [(4096, 4096, false), (4096, 49152, true)] {
            let mut memory = Memory::new(65536);
            memory.refuse = refuse;
            assert!(!with_edges(&mut memory, address, len, 16384).unwrap());
            assert!(memory.events.is_empty());
            assert!(memory.bytes.iter().all(|&b| b == 0x5a));
        }
    }
    #[test]
    fn interior_failure_preserves_classification_without_edge_work() {
        let cause = MemoryError::OutOfBounds {
            address: 16384,
            length: 32768,
        };
        for error in [
            RepointPrivateError::clean(cause.clone()),
            RepointPrivateError::indeterminate(cause),
        ] {
            let mut memory = Memory::new(65536);
            memory.fail_retire = Some(error.clone());
            assert_eq!(with_edges(&mut memory, 4096, 49152, 16384), Err(error));
            assert_eq!(memory.events, ["retire_failed"]);
            assert_eq!(memory.scrubbed, 0);
        }
    }

    #[test]
    fn invalid_ranges_do_not_reach_backend() {
        for (address, len, granule) in [
            (0, 4096, 0),
            (0, 4096, 12288),
            (1, 16384, 16384),
            (4096, 1, 16384),
            (0, 0, 16384),
        ] {
            let mut memory = Memory::new(65536);
            assert!(!with_edges(&mut memory, address, len, granule).unwrap());
            assert!(memory.events.is_empty());
        }
        let mut memory = Memory::new(65536);
        assert!(matches!(
            with_edges(&mut memory, u64::MAX - 4095, 8192, 16384),
            Err(RepointPrivateError::Clean(_))
        ));
        assert!(memory.events.is_empty());
    }
}
