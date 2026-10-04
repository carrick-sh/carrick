//! Physical custody for N1's prepared-copy protocol. The borrow prevents
//! memslot revoke/reuse until settlement; it carries no VA permission policy.
use super::*;
use carrick_aarch64::user_transfer::TransferPin;
use carrick_el1_abi::{PortalCopyRequest, PortalRetainedData, PortalTransferIntent};

pub struct RetainedX86Data<'a> {
    slot: &'a Slot,
    vm_generation: NonZeroU64,
    output: FrameGpa,
    len: usize,
}
impl CarrierMemory {
    /// Retain exact physical output after owner selection, before PREPARE.
    /// Semantic authorization is issued only by the production MmPortal.
    pub fn retain_output(
        &self,
        output: FrameGpa,
        len: usize,
    ) -> Result<RetainedX86Data<'_>, MemoryError> {
        self.admit()?;
        if len == 0 || len > carrick_el1_abi::MM_PORTAL_MAX_BYTES as usize {
            return Err(error("invalid owner transfer chunk"));
        }
        let slot = self
            .locate(output, len)
            .ok_or_else(|| error("unbacked owner transfer output"))?;
        Ok(RetainedX86Data {
            slot,
            vm_generation: self.vm_generation,
            output,
            len,
        })
    }
}
impl RetainedX86Data<'_> {
    fn authenticates(&self, request: &PortalCopyRequest<'_>, bytes: usize) -> bool {
        let request = request.request();
        request.retained == self.identity()
            && request.selected.ipa == self.output.raw()
            && request.range.len() <= self.len as u64
            && bytes as u64 <= request.range.len()
    }
}
impl TransferPin for RetainedX86Data<'_> {
    fn identity(&self) -> PortalRetainedData {
        PortalRetainedData {
            record: self.slot.handle.generation.0,
            vm_generation: self.vm_generation,
            owner: Some((
                self.slot.backing.identity.frame_id,
                self.slot.backing.identity.owner_generation,
            )),
        }
    }
    fn copy(&mut self, request: PortalCopyRequest<'_>, bytes: &mut [u8]) -> bool {
        if request.request().intent == PortalTransferIntent::UserWrite
            || !self.authenticates(&request, bytes.len())
        {
            return false;
        }
        let Some(ptr) = self.slot.backing.extent.ptr(self.output.raw(), bytes.len()) else {
            return false;
        };
        // SAFETY: the borrowed slot retains the exact registered extent. The
        // owner-issued copy capability authenticates this bounded pin identity;
        // the caller's separately owned host buffer does not alias its backing.
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), bytes.len());
        }
        true
    }
    fn copy_out(&mut self, request: PortalCopyRequest<'_>, bytes: &[u8]) -> bool {
        if request.request().intent != PortalTransferIntent::UserWrite
            || !self.authenticates(&request, bytes.len())
        {
            return false;
        }
        let Some(ptr) = self.slot.backing.extent.ptr(self.output.raw(), bytes.len()) else {
            return false;
        };
        // SAFETY: exact retained slot and owner-issued write capability as
        // above. Memslot deletion/reuse requires exclusive carrier access.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        }
        true
    }
}
