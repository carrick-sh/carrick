//! Authenticated instruction reads retain physical content dependencies.
//! The dependencies cover participating host writers, not executable admission.
use super::super::code_content::ContentObservation;
use super::*;
use carrick_hal::foreign_mm::ForeignInstructionContentStatus;
use carrick_hal::{ForeignMmReadLease, ForeignMmReadReceipt, ForeignMmSnapshot};

type Error = carrick_hal::ForeignMmTransportError;

#[derive(Debug)]
struct InstructionReceipt {
    read: Box<dyn ForeignMmReadReceipt>,
    content: Vec<ContentObservation>,
}
impl ForeignMmReadReceipt for InstructionReceipt {
    fn bytes_read(&self) -> usize {
        self.read.bytes_read()
    }
    fn owner_generations(&self) -> &[carrick_hal::ForeignOwnerGeneration] {
        self.read.owner_generations()
    }
    fn authenticates(&self, snapshot: &dyn carrick_hal::ForeignMmSnapshot) -> bool {
        self.read.authenticates(snapshot)
    }
    fn begin_instruction_content(&mut self) -> Result<(), Error> {
        for index in 0..self.content.len() {
            if self.content[index].begin_execution().is_err() {
                self.finish_instruction_content();
                return Err(Error::Retry);
            }
        }
        Ok(())
    }
    fn finish_instruction_content(&mut self) {
        for observation in &mut self.content {
            observation.finish_execution();
        }
    }
    fn instruction_content_status(&self) -> ForeignInstructionContentStatus {
        if self.content.iter().all(ContentObservation::is_current) {
            ForeignInstructionContentStatus::UnchangedTrackedWrites
        } else {
            ForeignInstructionContentStatus::Changed
        }
    }
}

pub(super) fn read(
    lease: &CarrierForeignMmReadLease,
    invocation: &carrick_hal::ForeignMmInvocation,
    authority: &dyn carrick_hal::ForeignMmLiveAuthority,
    snapshot: &dyn carrick_hal::ForeignMmSnapshot,
    va: carrick_guest_mem::GuestVa,
    dst: &mut [u8],
    deadline: std::time::Instant,
) -> Result<Box<dyn ForeignMmReadReceipt>, Error> {
    if dst.is_empty() {
        return Err(Error::Translation(va));
    }
    let content = match observe_resident(lease, authority, snapshot, va, dst.len(), deadline) {
        Ok(content) => content,
        // The normal reader also authenticates deferred pristine recipes.
        // Preserve those bytes, but never describe an unresident recipe as a
        // tracked physical dependency. Native admission must reject Untracked.
        Err(Error::Translation(_)) => {
            return lease.read(invocation, authority, snapshot, va, dst, deadline);
        }
        Err(error) => return Err(error),
    };
    let read = lease.read(invocation, authority, snapshot, va, dst, deadline)?;
    let receipt = InstructionReceipt { read, content };
    if receipt.instruction_content_status()
        != ForeignInstructionContentStatus::UnchangedTrackedWrites
    {
        return Err(Error::Retry);
    }
    Ok(Box::new(receipt))
}

fn observe_resident(
    lease: &CarrierForeignMmReadLease,
    authority: &dyn carrick_hal::ForeignMmLiveAuthority,
    snapshot: &dyn carrick_hal::ForeignMmSnapshot,
    va: carrick_guest_mem::GuestVa,
    len: usize,
    deadline: std::time::Instant,
) -> Result<Vec<ContentObservation>, Error> {
    let inner = lease
        .inner
        .try_lock_until(deadline)
        .ok_or(Error::TimedOut)?;
    if !inner.retained.has_same_contents(snapshot) {
        return Err(Error::LeaseStale);
    }
    let _coordinator = lease
        .state
        .mutation_coordinator
        .try_lock_until(deadline)
        .ok_or(Error::TimedOut)?;
    if !live_snapshot_matches(authority, &inner.retained, deadline)? {
        return Err(Error::Retry);
    }
    let mut content = Vec::new();
    let mut offset = 0;
    let mut owners = Vec::new();
    while offset < len {
        let address = va
            .raw()
            .checked_add(offset as u64)
            .ok_or(Error::Translation(va))?;
        let chunk = (0x1000 - (address as usize & 0xfff)).min(len - offset);
        let physical = foreign_stage1_translate(
            &inner.backing,
            snapshot.binding().stage1_root(),
            carrick_guest_mem::GuestVa(address),
            &mut owners,
        )?;
        let extent = inner.backing.extent_for(physical, chunk)?;
        let within = usize::try_from(physical - extent.key.0).map_err(|_| Error::OwnerStale)?;
        let tracker = match &extent.owner {
            RetainedPhysicalOwner::Global(pin) => &pin.owner().mapping.code_content,
            RetainedPhysicalOwner::Structural(owner) => &owner.retained.mapping.code_content,
        };
        content.push(tracker.observe(within, chunk).map_err(|_| Error::Retry)?);
        offset += chunk;
    }
    Ok(content)
}
