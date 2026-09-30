//! Read-only projection boundary for the shared anonymous authority. The host
//! half cannot carry anonymous-private reservations; output rows are ephemeral
//! observations, never a mutable authority that can be imported back.

use super::*;
use carrick_el1_abi::ReservationGeneration;

/// File/shared/synthetic VMAs remaining under host ownership. Construction
/// rejects an anonymous-private row instead of silently retaining two owners.
pub struct NonAnonymousVmas {
    mm: ReservationMm,
    vmas: VmaMap,
}

impl TryFrom<(ReservationMm, VmaMap)> for NonAnonymousVmas {
    type Error = Refusal;

    fn try_from((mm, vmas): (ReservationMm, VmaMap)) -> Result<Self, Refusal> {
        if vmas.iter().any(|vma| vma.provenance.is_private_anonymous()) {
            return Err(Refusal::ForeignMapping);
        }
        Ok(Self { mm, vmas })
    }
}

/// One exact-MM, exact-generation /proc observation. Fields remain private so
/// only a guarded shared-root walk can mint the anonymous part of the result.
pub struct ReservationProcMaps {
    mm: ReservationMm,
    generation: ReservationGeneration,
    brk: u64,
    maps: Vec<ProcMapsEntry>,
}

impl ReservationProcMaps {
    pub fn mm(&self) -> ReservationMm {
        self.mm
    }
    pub fn generation(&self) -> ReservationGeneration {
        self.generation
    }
    pub fn brk_current(&self) -> u64 {
        self.brk
    }
    pub fn maps(&self) -> &[ProcMapsEntry] {
        &self.maps
    }

    /// Both inputs must be held under the same exact-MM snapshot admission.
    /// The anonymous walk and sorted merge each do linear work; no per-row
    /// point lookup, range trimming, or whole-population rewrite occurs.
    pub fn capture(model: &mut Reservations<'_>, host: &NonAnonymousVmas) -> Result<Self, Refusal> {
        if host.mm != model.mm() {
            return Err(Refusal::Stale);
        }
        let layout = model.layout();
        let mut anonymous = Vec::new();
        model.observe_mappings(&mut |mapping| {
            if mapping.anonymous {
                let prot = mapping.protection.bits();
                let in_heap =
                    mapping.range.start() < layout.brk && mapping.range.end() > layout.heap.start();
                anonymous.push(ProcMapsEntry {
                    start: mapping.range.start(),
                    end: mapping.range.end(),
                    read: prot & 1 != 0,
                    write: prot & 2 != 0,
                    execute: prot & 4 != 0,
                    sharing: ProcMapSharing::Private,
                    path: if in_heap {
                        "[heap]".to_owned()
                    } else {
                        String::new()
                    },
                });
            }
        })?;
        let mut anonymous = anonymous.into_iter().peekable();
        let mut host = host.vmas.iter().peekable();
        let mut maps: Vec<ProcMapsEntry> = Vec::new();
        while anonymous.peek().is_some() || host.peek().is_some() {
            let use_anonymous = match (anonymous.peek(), host.peek()) {
                (Some(a), Some(h)) => a.start < h.start,
                (Some(_), None) => true,
                _ => false,
            };
            let row = if use_anonymous {
                anonymous.next().ok_or(Refusal::Stale)?
            } else {
                let vma = host.next().ok_or(Refusal::Stale)?;
                ProcMapsEntry {
                    start: vma.start,
                    end: vma.end,
                    read: vma.read,
                    write: vma.write,
                    execute: vma.execute,
                    sharing: match vma.provenance {
                        VmaBackingProvenance::SharedAnonymous
                        | VmaBackingProvenance::SharedFile => ProcMapSharing::Shared,
                        _ => ProcMapSharing::Private,
                    },
                    path: vma.path.clone(),
                }
            };
            if maps.last().is_some_and(|last| last.end > row.start) {
                return Err(Refusal::ForeignMapping);
            }
            maps.push(row);
        }
        Ok(Self {
            mm: model.mm(),
            generation: model.generation(),
            brk: layout.brk,
            maps,
        })
    }
}
