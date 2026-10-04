//! Physical half of UserTransfer. EL1 selects and authorizes the user VA;
//! this adapter resolves only its IPA through existing carrier directories.
use super::*;
use carrick_aarch64::user_transfer::{TransferCustody, TransferPin};
use carrick_el1_abi::{PortalRetainedData, PortalSelectedData, PortalTransferIntent};
use core::num::NonZeroU64;
use std::sync::Arc;

#[derive(Clone)]
pub struct UserTransferCustody {
    custody: Arc<CarrierVmCustody>,
    transport: Option<Arc<CarrierForeignMmTransport>>,
    metadata: Option<crate::metadata_grant::CarrierMetadataAccess>,
}
impl UserTransferCustody {
    /// Retain an exact external physical source for pre-admission copying.
    /// This never transfers its source frame or directory into the target.
    pub fn retain_import_source(
        &self,
        physical: carrick_guest_mem::Gpa,
        len: usize,
        expected: PortalRetainedData,
    ) -> Result<sparse_materialization::RetainedImportSource, TrapError> {
        let invalid = || TrapError::Hypervisor("stale import source identity".into());
        let owner = self
            .custody
            .global_frame_host_owners
            .lock()
            .range(..=(physical.0, u64::MAX))
            .next_back()
            .filter(|((base, size), _)| {
                physical
                    .0
                    .checked_add(len as u64)
                    .is_some_and(|end| end <= base.saturating_add(*size))
            })
            .and_then(|(_, entry)| entry.live_owner().cloned())
            .ok_or_else(invalid)?;
        let identity = owner.record_identity;
        let logical = identity.logical_owner.and_then(|owner| {
            Some((
                NonZeroU64::new(owner.id)?,
                NonZeroU64::new(owner.generation)?,
            ))
        });
        if expected.record.get() != identity.record_id.0
            || expected.vm_generation.get() != identity.vm_generation.0
            || expected.owner != logical
        {
            return Err(invalid());
        }
        let base = owner.snapshot().ok_or_else(invalid)?.ipa;
        let offset = usize::try_from(physical.0.checked_sub(base).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let pin = owner.pin().map_err(|_| invalid())?;
        sparse_materialization::RetainedImportSource::from_pin(pin, identity, offset, len)
    }
    /// Prepare copied physical bytes before the exact target's root admission.
    /// The kernel permit retains publication exclusion through commit/refusal.
    pub fn prepare_import<'a>(
        &self,
        target: carrick_hal::ForeignMmBinding,
        permit: carrick_hal::PreAdmissionPermit<'a>,
        source: sparse_materialization::RetainedImportSource,
        range: carrick_el1_abi::ReservationRange,
        protection: carrick_el1_abi::ReservationProtection,
    ) -> Result<sparse_materialization::PendingImport<'a>, TrapError> {
        let invalid = || TrapError::Hypervisor("import target is not bound".into());
        let transport = self.transport.as_ref().ok_or_else(invalid)?;
        let binding = CarrierForeignMmBinding {
            asid: target.asid(),
            stage1_root: target.stage1_root(),
        };
        let state = transport
            .states
            .read()
            .get(&binding)
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(invalid)?;
        sparse_materialization::PublicationContext::for_import(
            state,
            self.custody.clone(),
            &permit,
        )?
        .prepare_import(permit, source, range, protection)
    }
    pub(crate) fn from_transport(
        transport: Arc<CarrierForeignMmTransport>,
        carrier: Option<Arc<PersistentCarrierMappings>>,
    ) -> Self {
        Self {
            custody: Arc::clone(&transport.custody),
            transport: Some(transport),
            metadata: carrier.and_then(crate::metadata_grant::CarrierMetadataAccess::new),
        }
    }
    #[cfg(test)]
    pub(crate) fn new(custody: Arc<CarrierVmCustody>) -> Self {
        Self {
            custody,
            transport: None,
            metadata: None,
        }
    }
}

pub struct RetainedUserData {
    _pin: CarrierStage2Pin,
    custody: Arc<CarrierVmCustody>,
    _mapping: Option<Arc<GlobalFrameSharedMapping>>,
    _metadata: Option<crate::metadata_grant::CarrierMetadataAccess>,
    _write: Option<Arc<code_content::PendingContentWrite<OwnedCodeContent>>>,
    carrier: NonZeroU64,
    identity: PortalRetainedData,
    selected: PortalSelectedData,
    intent: PortalTransferIntent,
    pointer: *mut u8,
    len: usize,
}
enum TransferBytes<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}
impl TransferPin for RetainedUserData {
    fn pending(&self) -> Option<carrick_guest_mem::OwnedMemoryWait> {
        self._write
            .as_ref()
            .filter(|write| !write.is_ready())
            .map(|write| carrick_guest_mem::OwnedMemoryWait(write.clone()))
    }
    fn identity(&self) -> PortalRetainedData {
        self.identity
    }
    fn copy(
        &mut self,
        authorization: carrick_el1_abi::PortalCopyRequest<'_>,
        bytes: &mut [u8],
    ) -> bool {
        if self.intent == PortalTransferIntent::UserWrite {
            self.copy_out(authorization, bytes)
        } else {
            self.copy_bytes(authorization, TransferBytes::Read(bytes))
        }
    }
    fn copy_out(
        &mut self,
        authorization: carrick_el1_abi::PortalCopyRequest<'_>,
        bytes: &[u8],
    ) -> bool {
        if self.intent != PortalTransferIntent::UserWrite {
            return false;
        }
        self.copy_bytes(authorization, TransferBytes::Write(bytes))
    }
}
impl RetainedUserData {
    fn copy_bytes(
        &mut self,
        authorization: carrick_el1_abi::PortalCopyRequest<'_>,
        bytes: TransferBytes<'_>,
    ) -> bool {
        if self._write.as_ref().is_some_and(|write| !write.is_ready()) {
            return false;
        }
        let len = match &bytes {
            TransferBytes::Read(bytes) => bytes.len(),
            TransferBytes::Write(bytes) => bytes.len(),
        };
        let request = authorization.request();
        if request.operation.carrier != self.carrier
            || request.retained != self.identity
            || request.selected != self.selected
            || request.intent != self.intent
            || request.range.len() > self.len as u64
            || request.range.len() != len as u64
        {
            return false;
        }
        // SAFETY: exact authorization, retained backing and pin cover this
        // bounded interval. The typed buffer chooses the copy direction.
        unsafe {
            match bytes {
                TransferBytes::Read(bytes) => {
                    core::ptr::copy_nonoverlapping(self.pointer, bytes.as_mut_ptr(), len)
                }
                TransferBytes::Write(bytes) => {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.pointer, len)
                }
            }
        }
        if self.intent == PortalTransferIntent::UserWrite {
            // A peer MM may have consumed admission dirtiness before this
            // memcpy. Publish the completed write, then await I2 completion.
            let mapping = self._mapping.as_ref().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "write lost retained content owner"
                )
            });
            let offset = self.pointer as usize - mapping.host_base() as usize;
            mapping.code_content.mark_icache_dirty(offset, len);
        }
        if self.intent == PortalTransferIntent::UserWrite && self.selected.executable {
            self.custody
                .publish_user_executable(self.selected.ipa, len as u64, |_, _| None, |_, _| None)
                .unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::user_transfer",
                        "executable write publication failed: {error:?}"
                    )
                });
        }
        true
    }
}
impl TransferCustody for UserTransferCustody {
    type Pin = RetainedUserData;
    fn carrier(&self) -> NonZeroU64 {
        self.custody.transfer_carrier
    }
    fn prepare(
        &self,
        target: carrick_aarch64::user_transfer::TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<Option<Box<dyn carrick_aarch64::user_transfer::TransferGrant>>, TrapError> {
        let Some(transport) = &self.transport else {
            return Ok(None);
        };
        let Some(asid) = core::num::NonZeroU16::new((target.ttbr0() >> 48) as u16) else {
            return Ok(None);
        };
        let binding = CarrierForeignMmBinding {
            asid: carrick_hal::ForeignAsid::from_kernel_allocation(asid),
            stage1_root: carrick_guest_mem::Gpa(target.ttbr0() & 0x0000_ffff_ffff_f000),
        };
        let state = transport
            .states
            .read()
            .get(&binding)
            .and_then(std::sync::Weak::upgrade);
        let Some(state) = state else {
            return Ok(None);
        };
        sparse_materialization::PublicationContext::for_transfer(
            state,
            Arc::clone(&self.custody),
            target,
            window,
        )?
        .prepare_transfer(window)
    }
    fn publish_executable(
        &self,
        target: carrick_aarch64::user_transfer::TransferTarget,
        request: carrick_el1_abi::PortalExecutablePublication,
    ) -> bool {
        let Some(pool) = carrick_el1_abi::cow_grant_pool_host() else {
            return false;
        };
        self.publish_claimed_executable(
            target.handle().carrier(),
            target.handle().mm().raw(),
            pool,
            request,
        )
    }
    fn refill_cow(
        &self,
        target: carrick_aarch64::user_transfer::TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<bool, TrapError> {
        let Some(state) = self
            .custody
            .guest_cow_state(target.handle().mm().raw())
            .ok()
            .flatten()
        else {
            return Ok(false);
        };
        let context = sparse_materialization::PublicationContext::for_transfer(
            state,
            self.custody.clone(),
            target,
            window,
        )?;
        context.refill_transfer_cow()
    }
    fn retain(
        &self,
        selected: PortalSelectedData,
        len: usize,
        intent: PortalTransferIntent,
    ) -> Result<Option<Self::Pin>, TrapError> {
        self.retain_exact(selected, len, intent)
    }
}
impl UserTransferCustody {
    fn publish_claimed_executable(
        &self,
        carrier: NonZeroU64,
        mm: u64,
        pool: &carrick_el1_abi::CowGrantPool,
        request: carrick_el1_abi::PortalExecutablePublication,
    ) -> bool {
        if carrier != self.carrier()
            || mm != request.grant.mm_key
            || !request.valid()
            || !pool.authenticates_claimed(&request.grant)
        {
            return false;
        }
        let Some(owner) = self
            .custody
            .global_frame_host_owners
            .lock()
            .get(&(request.grant.physical_ipa, carrick_el1_abi::COW_GRANT_SIZE))
            .and_then(|entry| entry.live_owner().cloned())
        else {
            return false;
        };
        if owner.generation() != request.grant.backing.owner_generation.get() {
            return false;
        }
        let Ok(_pin) = self.custody.pin_stage2_record(owner.record_identity) else {
            return false;
        };
        // The grant record authenticates the existing physical inventory
        // receipt. No MM policy or host snapshot participates in publication.
        let offset = (request.ipa - request.grant.physical_ipa) as usize;
        owner
            .mapping
            .code_content
            .mark_icache_dirty(offset, request.len as usize);
        self.custody
            .publish_user_executable(request.ipa, request.len, |_, _| None, |_, _| None)
            .is_ok()
    }
    fn retain_exact(
        &self,
        selected: PortalSelectedData,
        len: usize,
        intent: PortalTransferIntent,
    ) -> Result<Option<RetainedUserData>, TrapError> {
        let error =
            || TrapError::Hypervisor("UserTransfer physical custody invariant refused".to_owned());
        if len == 0 || len > 4096 || selected.ipa.checked_add(len as u64).is_none() {
            return Err(error());
        }
        let Some(identity) = self.custody.stage2_record_covering(selected.ipa, len) else {
            carrick_observability::probes::hvpatch_el1_host_read_retention(selected.ipa, 1);
            return Ok(None);
        };
        let global = {
            let owners = self.custody.global_frame_host_owners.lock();
            if let Some((&(base, length), entry)) =
                owners.range(..=(selected.ipa, u64::MAX)).next_back()
            {
                let end = base.saturating_add(length);
                if selected.ipa < end {
                    if selected.ipa + len as u64 > end {
                        return Err(error());
                    }
                    entry
                        .live_owner()
                        .filter(|owner| owner.record_identity == identity)
                        .cloned()
                } else {
                    None
                }
            } else {
                None
            }
        };
        let mapping = if let Some(owner) = global {
            Some(Arc::clone(&owner.mapping))
        } else {
            self.custody
                .structural_backings
                .lock()
                .get(&identity.record_id)
                .map(|entry| Arc::clone(&entry.mapping))
        };
        let pin = match self.custody.pin_stage2_record(identity) {
            Ok(pin) => pin,
            Err(
                reason @ (CarrierStage2PinError::NotFound
                | CarrierStage2PinError::NotMapped
                | CarrierStage2PinError::RetirementRequested),
            ) => {
                carrick_observability::probes::hvpatch_el1_host_read_retention(
                    selected.ipa,
                    match reason {
                        CarrierStage2PinError::NotFound => 3,
                        CarrierStage2PinError::NotMapped => 4,
                        _ => 5,
                    },
                );
                return Ok(None);
            }
            Err(reason) => {
                return Err(TrapError::Hypervisor(format!(
                    "UserTransfer physical pin refused: {reason:?}"
                )));
            }
        };
        // A bare stage-2 alias does not own its source allocation. Require
        // the retained physical backing before exposing even a read pin.
        let metadata = if mapping.is_none()
            && intent == PortalTransferIntent::CarrickInternalRead
            && selected.ipa >= carrick_el1_abi::EL1_REGION_BASE
            && selected.ipa + len as u64 <= carrick_el1_abi::EL1_REGION_BASE + 4096
        {
            self.metadata.clone()
        } else {
            None
        };
        if mapping.is_none() && metadata.is_none() {
            return Err(error());
        }
        let record = self
            .custody
            .stage2_record_snapshot(identity.record_id)
            .ok_or_else(error)?;
        if let Some(mapping) = &mapping {
            if record.host_addr != mapping.host_base() as usize {
                return Err(error());
            }
        }
        if let Some(metadata) = &metadata {
            let base = metadata.region().map_err(|_| error())?.as_ptr() as usize;
            if record
                .host_addr
                .checked_add((selected.ipa - record.ipa) as usize)
                != base.checked_add((selected.ipa - carrick_el1_abi::EL1_REGION_BASE) as usize)
            {
                return Err(error());
            }
        }
        let offset = selected
            .ipa
            .checked_sub(record.ipa)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(error)?;
        if offset.checked_add(len).is_none_or(|end| end > record.len) {
            return Err(error());
        }
        let pointer = record.host_addr.checked_add(offset).ok_or_else(error)? as *mut u8;
        let retained = PortalRetainedData {
            record: NonZeroU64::new(identity.record_id.0).ok_or_else(error)?,
            vm_generation: NonZeroU64::new(identity.vm_generation.0).ok_or_else(error)?,
            owner: match identity.logical_owner {
                Some(owner) => Some((
                    NonZeroU64::new(owner.id).ok_or_else(error)?,
                    NonZeroU64::new(owner.generation).ok_or_else(error)?,
                )),
                None => None,
            },
        };
        // Revocation returns owned readiness without waiting for native-code
        // users. Its writer exclusion survives suspension through pending().
        let write = if intent == PortalTransferIntent::UserWrite {
            Some(Arc::new(
                mapping
                    .as_ref()
                    .ok_or_else(error)?
                    .prepare_content_write(offset, len)
                    .map_err(|_| error())?,
            ))
        } else {
            None
        };
        Ok(Some(RetainedUserData {
            _pin: pin,
            custody: self.custody.clone(),
            _mapping: mapping,
            _metadata: metadata,
            _write: write,
            carrier: self.carrier(),
            identity: retained,
            selected,
            intent,
            pointer,
            len,
        }))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use carrick_el1_abi::{PortalByteRange, PortalOperation, PortalTransferSlot, ReservationMm};
    use std::sync::atomic::Ordering;
    pub(crate) fn backing(custody: &Arc<CarrierVmCustody>, ipa: u64) -> Arc<GlobalFrameHostOwner> {
        backing_len(custody, ipa, 16384)
    }
    fn backing_len(
        custody: &Arc<CarrierVmCustody>,
        ipa: u64,
        len: usize,
    ) -> Arc<GlobalFrameHostOwner> {
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .unwrap();
        let mut lease = GlobalFrameStage2Lease::fixed(ipa, len as u64);
        lease.mark_test_mapped_without_backend();
        register_global_frame_host_owner_in(
            custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .unwrap();
        Arc::clone(
            custody
                .global_frame_host_owners
                .lock()
                .get(&(ipa, len as u64))
                .unwrap()
                .owner(),
        )
    }
    fn selection(ipa: u64) -> PortalSelectedData {
        PortalSelectedData {
            ipa,
            executable: false,
            root_generation: NonZeroU64::new(1).unwrap(),
            offset: 0,
        }
    }
    #[test]
    fn user_write_retention_releases_executor_while_code_reader_is_active() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let owner = backing(&custody, 0x4800_0000);
        let mut observation = owner.mapping.code_content.observe(0, 4).unwrap();
        observation.begin_execution().unwrap();
        let physical = UserTransferCustody::new(custody.clone());
        let (sent, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let pin = physical
                .retain(selection(0x4800_0000), 4, PortalTransferIntent::UserWrite)
                .unwrap()
                .unwrap();
            sent.send(()).unwrap();
            drop(pin);
        });
        let returned = received
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_ok();
        observation.finish_execution();
        if !returned {
            received
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
        }
        worker.join().unwrap();
        assert!(
            returned,
            "physical retention parked its executor behind a live code reader"
        );
    }

    #[test]
    fn native_owner_matrix_moves_bytes_with_balanced_physical_pins() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        struct Physical {
            custody: UserTransferCustody,
            pin: Option<RetainedUserData>,
            owners: Vec<Arc<GlobalFrameHostOwner>>,
        }
        impl carrick_el1::personality::mm_portal::test_support::PhysicalTransferFixture for Physical {
            fn carrier(&self) -> NonZeroU64 {
                self.custody.carrier()
            }
            fn provision(&mut self, ipa: u64, len: usize) {
                self.owners
                    .push(backing_len(&self.custody.custody, ipa, len));
            }
            fn retain(
                &mut self,
                selected: PortalSelectedData,
                len: usize,
                intent: PortalTransferIntent,
            ) -> PortalRetainedData {
                assert!(self.pin.is_none());
                let pin = self.custody.retain(selected, len, intent).unwrap().unwrap();
                let identity = pin.identity();
                self.pin = Some(pin);
                assert_eq!(
                    self.owners
                        .iter()
                        .map(|owner| self
                            .custody
                            .custody
                            .stage2_record_snapshot(owner.record_identity.record_id)
                            .unwrap()
                            .pin_count)
                        .sum::<u64>(),
                    1
                );
                identity
            }
            fn copy(
                &mut self,
                authorization: carrick_el1_abi::PortalCopyRequest<'_>,
                bytes: &mut [u8],
            ) -> bool {
                self.pin.as_mut().unwrap().copy(authorization, bytes)
            }
            fn release(&mut self) {
                drop(self.pin.take().unwrap());
                assert!(self.owners.iter().all(|owner| {
                    self.custody
                        .custody
                        .stage2_record_snapshot(owner.record_identity.record_id)
                        .unwrap()
                        .pin_count
                        == 0
                }));
            }
        }
        carrick_el1::personality::mm_portal::test_support::native_owner_matrix(|| {
            Box::new(Physical {
                custody: UserTransferCustody::new(Arc::new(CarrierVmCustody::new_live_fixture())),
                pin: None,
                owners: Vec::new(),
            })
        });
    }

    #[test]
    fn invalid_physical_request_is_not_an_owner_recheck_wait() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let _owner = backing(&custody, 0xa085_3100_0000);
        let physical = UserTransferCustody::new(custody);
        assert!(
            physical
                .retain(
                    selection(0xa085_3100_0000),
                    0,
                    PortalTransferIntent::UserRead
                )
                .is_err(),
            "permanent physical refusal was erased into immediate owner reselect"
        );
        assert!(
            physical
                .retain(
                    selection(0xa085_3100_0000 + 16382),
                    4,
                    PortalTransferIntent::UserRead
                )
                .is_err(),
            "known backing range overflow must not become a recheck wait"
        );
        assert!(
            physical
                .retain(
                    selection(0xa085_3100_0000 + 32768),
                    4,
                    PortalTransferIntent::UserRead
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn drained_copy_stays_ready_during_rejected_stale_execution_entry() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let ipa = 0xa085_3000_0000;
        let owner = backing(&custody, ipa);
        let mut stale = owner.mapping.code_content.observe(0, 4).unwrap();
        let physical = UserTransferCustody::new(custody);
        let selected = selection(ipa);
        let mut pin = physical
            .retain(selected, 4, PortalTransferIntent::UserWrite)
            .unwrap()
            .unwrap();
        assert!(pin.pending().is_none());
        let request = carrick_el1_abi::PortalTransferRequest::new(
            PortalOperation {
                carrier: physical.carrier(),
                mm: ReservationMm::new(77).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            PortalByteRange::new(0x4000_0000, 4).unwrap(),
            PortalTransferIntent::UserWrite,
            selected,
            pin.identity(),
        )
        .unwrap();
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        let mut copied = false;
        let rejected = stale.begin_execution_with_hook(|| {
            copied = service.copy_with(|| {
                assert!(
                    ticket.copy_requested(|authorization| pin.copy_out(authorization, b"data")),
                    "drained destination became unready after source consumption"
                )
            });
        });
        assert_eq!(rejected, Err(code_content::ContentError::Changed));
        assert!(copied);
        assert!(service.complete(4, 0));
        assert_eq!(ticket.take_completion().unwrap().completed, 4);
    }

    #[test]
    fn executable_transfer_republishes_after_peer_cleans_admitted_write() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let ipa = 0xa085_2000_0000;
        let owner = backing(&custody, ipa);
        let physical = UserTransferCustody::new(custody.clone());
        let selected = PortalSelectedData {
            executable: true,
            ..selection(ipa)
        };
        let mut pin = physical
            .retain(selected, 4, PortalTransferIntent::UserWrite)
            .unwrap()
            .unwrap();
        // A different MM publishes the same physical source after write
        // admission, before the exact transfer copy fence has been entered.
        assert_eq!(
            custody
                .publish_user_executable(ipa, 4, |_, _| None, |_, _| None)
                .unwrap(),
            1
        );
        let before = owner
            .mapping
            .code_content
            .icache_publications
            .load(Ordering::Relaxed);
        let request = carrick_el1_abi::PortalTransferRequest::new(
            PortalOperation {
                carrier: physical.carrier(),
                mm: ReservationMm::new(77).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            PortalByteRange::new(0x4000_0000, 4).unwrap(),
            PortalTransferIntent::UserWrite,
            selected,
            pin.identity(),
        )
        .unwrap();
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        let mut bytes = *b"code";
        assert!(service.copy_with(|| assert!(
            ticket.copy_requested(|authorization| pin.copy(authorization, &mut bytes))
        )));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(owner.mapping.host_base(), 4) },
            b"code"
        );
        assert_eq!(
            owner
                .mapping
                .code_content
                .icache_publications
                .load(Ordering::Relaxed),
            before + 1,
            "copy must complete I2 even when another MM consumed admission dirtiness"
        );
        assert!(service.complete(4, 0));
        assert_eq!(ticket.take_completion().unwrap().errno, 0);
    }

    #[test]
    fn nonexecutable_transfer_redirties_for_executable_peer() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let ipa = 0xa085_2000_0000;
        let owner = backing(&custody, ipa);
        let physical = UserTransferCustody::new(custody.clone());
        let selected = PortalSelectedData {
            executable: false,
            ..selection(ipa)
        };
        let mut pin = physical
            .retain(selected, 4, PortalTransferIntent::UserWrite)
            .unwrap()
            .unwrap();
        // A different MM publishes the same physical source after write
        // admission, before the exact transfer copy fence has been entered.
        assert_eq!(
            custody
                .publish_user_executable(ipa, 4, |_, _| None, |_, _| None)
                .unwrap(),
            1
        );
        let before = owner
            .mapping
            .code_content
            .icache_publications
            .load(Ordering::Relaxed);
        let request = carrick_el1_abi::PortalTransferRequest::new(
            PortalOperation {
                carrier: physical.carrier(),
                mm: ReservationMm::new(77).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            PortalByteRange::new(0x4000_0000, 4).unwrap(),
            PortalTransferIntent::UserWrite,
            selected,
            pin.identity(),
        )
        .unwrap();
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        let mut bytes = *b"code";
        assert!(service.copy_with(|| assert!(
            ticket.copy_requested(|authorization| pin.copy(authorization, &mut bytes))
        )));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(owner.mapping.host_base(), 4) },
            b"code"
        );
        assert_eq!(
            custody
                .publish_user_executable(ipa, 4, |_, _| None, |_, _| None)
                .unwrap(),
            1,
            "nonexecuting writer must dirty bytes after copy"
        );
        assert_eq!(
            owner
                .mapping
                .code_content
                .icache_publications
                .load(Ordering::Relaxed),
            before + 1,
            "copy must complete I2 even when another MM consumed admission dirtiness"
        );
        assert!(service.complete(4, 0));
        assert_eq!(ticket.take_completion().unwrap().errno, 0);
    }

    #[test]
    fn retained_data_uses_exact_physical_pin_and_moves_actual_bytes() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let owner = backing(&custody, 0xa085_0000_0000);
        let physical = UserTransferCustody::new(Arc::clone(&custody));
        let selected = selection(0xa085_0000_0000 + 4096);
        let mut pin = physical
            .retain(selected, 4096, PortalTransferIntent::UserWrite)
            .unwrap()
            .unwrap();
        assert_eq!(
            custody
                .stage2_record_snapshot(owner.record_identity.record_id)
                .unwrap()
                .pin_count,
            1
        );
        let operation = PortalOperation {
            carrier: physical.carrier(),
            mm: ReservationMm::new(77).unwrap(),
            incarnation: NonZeroU64::new(1).unwrap(),
            sequence: NonZeroU64::new(1).unwrap(),
        };
        let request = carrick_el1_abi::PortalTransferRequest::new(
            operation,
            PortalByteRange::new(0x4000_1000, 4096).unwrap(),
            PortalTransferIntent::UserWrite,
            selected,
            pin.identity(),
        )
        .unwrap();
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        let mut bytes = vec![0x5a; 4096];
        assert!(service.copy_with(|| assert!(
            ticket.copy_requested(|authorization| pin.copy(authorization, &mut bytes))
        )));
        assert!(service.complete(4096, 0));
        assert_eq!(ticket.take_completion().unwrap().retained, pin.identity());
        // Retirement reaches the existing custodian before any backend unmap.
        let mut unmaps = 0;
        assert_eq!(
            custody.retire_stage2_record_using(owner.record_identity, |_, _| {
                unmaps += 1;
                Ok(())
            }),
            CarrierStage2RetireOutcome::DeferredActivePins
        );
        assert_eq!(unmaps, 0);
        assert!(
            physical
                .retain(selected, 4096, PortalTransferIntent::UserRead)
                .unwrap()
                .is_none()
        );
        // SAFETY: the owned mapping and pin still retain the checked interval.
        let actual =
            unsafe { core::slice::from_raw_parts(owner.mapping.host_base().add(4096), 4096) };
        assert_eq!(actual, &bytes);
        drop(pin);
        assert_eq!(
            custody
                .stage2_record_snapshot(owner.record_identity.record_id)
                .unwrap()
                .pin_count,
            0
        );
        assert_eq!(
            custody.retire_stage2_record_using(owner.record_identity, |_, _| {
                unmaps += 1;
                Ok(())
            }),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
    }
    #[test]
    fn prepared_short_commit_copies_only_actual_prefix_with_exact_physical_pin() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let owner = backing(&custody, 0xa085_0000_0000);
        let physical = UserTransferCustody::new(Arc::clone(&custody));
        let selected = selection(0xa085_0000_0000 + 4096);
        let mut pin = physical
            .retain(selected, 4096, PortalTransferIntent::UserWrite)
            .unwrap()
            .unwrap();
        let request = carrick_el1_abi::PortalTransferRequest::new(
            PortalOperation {
                carrier: physical.carrier(),
                mm: ReservationMm::new(77).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            PortalByteRange::new(0x4000_1000, 4096).unwrap(),
            PortalTransferIntent::UserWrite,
            selected,
            pin.identity(),
        )
        .unwrap();
        let permit = carrick_el1_abi::PortalPreparedPermit {
            index: 11,
            generation: NonZeroU64::new(21).unwrap(),
            operation: request.operation,
        };
        let slot = PortalTransferSlot::new();
        let mut prepare = slot.submit_prepare(request).unwrap();
        assert!(slot.claim().unwrap().complete_prepared(permit));
        assert_eq!(prepare.take_prepared(), Some(permit));
        let mut bytes = [0x5a; 23];
        let mut ticket = slot
            .submit_commit(request, permit, bytes.len() as u64)
            .unwrap();
        let service = slot.claim().unwrap();
        assert!(
            service.copy_with(|| assert!(
                ticket.copy_requested(|authorization| pin.copy(authorization, &mut bytes))
            )),
            "a short committed prefix must retain the full prepared identity"
        );
        assert!(service.complete(bytes.len() as u64, 0));
        assert_eq!(ticket.take_completion().unwrap().completed, 23);
        // SAFETY: owner and exact pin retain this entire physical interval.
        let actual =
            unsafe { core::slice::from_raw_parts(owner.mapping.host_base().add(4096), 4096) };
        assert_eq!(&actual[..23], &bytes);
        assert!(actual[23..].iter().all(|byte| *byte == 0));
        assert_eq!(
            custody
                .stage2_record_snapshot(owner.record_identity.record_id)
                .unwrap()
                .pin_count,
            1
        );
        drop(pin);
        assert_eq!(
            custody
                .stage2_record_snapshot(owner.record_identity.record_id)
                .unwrap()
                .pin_count,
            0
        );
    }

    #[test]
    fn independent_carriers_cannot_cross_feed_identical_mm_and_vm_generations() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let a = Arc::new(CarrierVmCustody::new_live_fixture());
        let b = Arc::new(CarrierVmCustody::new_live_fixture());
        let _owner_a = backing(&a, 0xa086_0000_0000);
        let _owner_b = backing(&b, 0xa086_0000_0000);
        let pa = UserTransferCustody::new(a);
        let pb = UserTransferCustody::new(b);
        assert_ne!(pa.carrier(), pb.carrier());
        let selected = selection(0xa086_0000_0000);
        let pin_a = pa
            .retain(selected, 1, PortalTransferIntent::UserRead)
            .unwrap()
            .unwrap();
        let mut pin_b = pb
            .retain(selected, 1, PortalTransferIntent::UserRead)
            .unwrap()
            .unwrap();
        assert_eq!(pin_a.identity(), pin_b.identity()); // Identical local generation namespaces.
        let request = carrick_el1_abi::PortalTransferRequest::new(
            PortalOperation {
                carrier: pa.carrier(),
                mm: ReservationMm::new(77).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            PortalByteRange::new(0x40000000, 1).unwrap(),
            PortalTransferIntent::UserRead,
            selected,
            pin_a.identity(),
        )
        .unwrap();
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        let mut bytes = [0x37];
        assert!(!service.copy_with(|| assert!(
            ticket.copy_requested(|authorization| pin_b.copy(authorization, &mut bytes))
        )));
        assert!(service.complete(0, 125));
        assert_eq!(bytes, [0x37]);
    }
    pub(crate) fn copy_bytes(
        physical: &UserTransferCustody,
        ipa: u64,
        intent: PortalTransferIntent,
        bytes: &mut [u8],
    ) {
        copy_selected_bytes(physical, ipa, intent, bytes, false)
    }
    fn copy_selected_bytes(
        physical: &UserTransferCustody,
        ipa: u64,
        intent: PortalTransferIntent,
        bytes: &mut [u8],
        executable: bool,
    ) {
        let mut selected = selection(ipa);
        selected.executable = executable;
        let mut pin = physical
            .retain(selected, bytes.len(), intent)
            .unwrap()
            .unwrap();
        let request = carrick_el1_abi::PortalTransferRequest::new(
            PortalOperation {
                carrier: physical.carrier(),
                mm: ReservationMm::new(77).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            PortalByteRange::new(0x4000_0000, bytes.len() as u64).unwrap(),
            intent,
            selected,
            pin.identity(),
        )
        .unwrap();
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        assert!(service.copy_with(|| assert!(
            ticket.copy_requested(|authorization| pin.copy(authorization, bytes))
        )));
        assert!(service.complete(bytes.len() as u64, 0));
        assert_eq!(
            ticket.take_completion().unwrap().completed,
            bytes.len() as u64
        );
    }

    #[test]
    fn imported_source_modes_keep_bytes_and_guest_cow_preserves_private_source() {
        imported_transfer_fixture(false);
    }
    #[test]
    fn red_until_n1_executable_cow_copies_and_publishes_coherent_bytes() {
        imported_transfer_fixture(true);
    }
    fn imported_transfer_fixture(executable: bool) {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            BackingIdentity, CallerInvalidatesAsid, DescriptorOp, DescriptorOutcome, DescriptorTxn,
            DescriptorTxnId, InlineJournal, PageSpan, PrimaryTableWords, TableGrants, TerminalEdit,
            execute_descriptor_txn,
        };
        use carrick_mmu_core::aarch64::{PtOp, SubstrateGpa, TerminalRule, indices};
        use core::sync::atomic::{AtomicU64, Ordering};
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsRawFd;
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        for mode in ["Owned", "HostBackingPrivate", "HostBackingShared"] {
            let before = [0xe0, 0x00, 0x80, 0x52]; // mov w0,#7
            let after = [0x20, 0x01, 0x80, 0x52]; // mov w0,#9

            let custody = Arc::new(CarrierVmCustody::new_live_fixture());
            let physical = UserTransferCustody::new(custody.clone());
            let source_ipa = 0xa088_0000_0000;
            let mut file = std::fs::File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(std::env::temp_dir().join(format!(
                    "carrick-transfer-import-{}-{mode}",
                    std::process::id()
                )))
                .unwrap();
            let path = std::env::temp_dir().join(format!(
                "carrick-transfer-import-{}-{mode}",
                std::process::id()
            ));
            // Unlink immediately; the test owns only its open vnode/mappings.
            std::fs::remove_file(path).unwrap();
            file.set_len(16384).unwrap();
            file.write_all(&before).unwrap();
            file.write_all(&[0xc0, 0x03, 0x5f, 0xd6]).unwrap(); // ret
            let mapping = if mode == "HostBackingPrivate" {
                crate::host_mapping::OwnedHostMapping::map_private_file(file.as_raw_fd(), 0, 16384)
                    .unwrap()
            } else if mode == "HostBackingShared" {
                crate::host_mapping::OwnedHostMapping::map_shared_file(
                    file.as_raw_fd(),
                    0,
                    16384,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
                .unwrap()
            } else {
                let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    16384,
                    crate::host_mapping::HostMappingKind::FrameCow,
                )
                .unwrap();
                unsafe {
                    std::ptr::copy_nonoverlapping(before.as_ptr(), mapping.as_ptr(), 4);
                    std::ptr::copy_nonoverlapping(
                        [0xc0, 0x03, 0x5f, 0xd6].as_ptr(),
                        mapping.as_ptr().add(4),
                        4,
                    );
                };
                mapping
            };
            let mut lease = GlobalFrameStage2Lease::fixed(source_ipa, 16384);
            lease.mark_test_mapped_without_backend();
            register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
            .unwrap();
            let source = custody
                .global_frame_host_owners
                .lock()
                .get(&(source_ipa, 16384))
                .unwrap()
                .owner()
                .clone();
            let mut seen = [0; 4];
            copy_bytes(
                &physical,
                source_ipa,
                PortalTransferIntent::UserRead,
                &mut seen,
            );
            assert_eq!(&seen, &before);
            let private = mode == "HostBackingPrivate";
            let destination = if private {
                Some(backing(&custody, source_ipa + 0x4000))
            } else {
                None
            };
            let crossings = std::cell::Cell::new(0usize);
            let selected_ipa = if let Some(destination) = &destination {
                const ROOT: u64 = 0x8800_0000;
                const VA: u64 = 0x4000_0000;
                const PA: u64 = 0x0000_ffff_ffff_f000;
                let arena = (0..6 * 512).map(|_| AtomicU64::new(0)).collect::<Vec<_>>();
                let set = |offset: usize, value| arena[offset / 8].store(value, Ordering::Relaxed);
                let va = indices(VA);
                let win = indices(carrick_el1_abi::EL1_COW_COPY_BASE);
                set(va[0] * 8, (ROOT + 0x1000) | 3);
                set(0x1000 + va[1] * 8, (ROOT + 0x2000) | 3);
                set(0x2000 + va[2] * 8, (ROOT + 0x3000) | 3);
                set(0x1000 + win[1] * 8, (ROOT + 0x4000) | 3);
                set(0x4000 + win[2] * 8, (ROOT + 0x5000) | 3);
                for lane in 0..4 {
                    set(
                        0x3000 + (va[3] + lane) * 8,
                        (source_ipa + lane as u64 * 4096)
                            | 3
                            | (3 << 6)
                            | (1 << 10)
                            | (3 << 8)
                            | (1 << 54),
                    );
                }
                for lane in 0..2 {
                    set(
                        0x5000 + (win[3] + lane) * 8,
                        carrick_el1_abi::EL1_COW_COPY_BASE + lane as u64 * 4096,
                    );
                }
                let maintenance = CallerInvalidatesAsid;
                let words = unsafe {
                    PrimaryTableWords::new(
                        arena.as_ptr().cast_mut(),
                        ROOT,
                        arena.len() * 8,
                        &maintenance,
                    )
                }
                .unwrap();
                let nz = |n| NonZeroU64::new(n).unwrap();
                let txn = DescriptorTxn {
                    id: DescriptorTxnId {
                        mm_key: nz(77),
                        generation: nz(1),
                    },
                    root: SubstrateGpa(ROOT),
                    tables: TableGrants::new(&[]).unwrap(),
                    op: DescriptorOp::Terminal {
                        span: PageSpan::new(VA, 16384),
                        edit: TerminalEdit {
                            rule: TerminalRule::Pt {
                                op: Some(PtOp::ReadWrite { exec: executable }),
                                reset_retired: false,
                                deny_host_buffers: false,
                                fork_arm: true,
                                adopt_private: true,
                            },
                            asid_scoped: true,
                            excluded_ipa: 0,
                            excluded_len: 0,
                            reclaim_budget: 0,
                        },
                    },
                };
                assert!(matches!(
                    execute_descriptor_txn(
                        &words,
                        SubstrateGpa(ROOT),
                        &txn,
                        &mut InlineJournal::new()
                    )
                    .outcome,
                    DescriptorOutcome::Applied(_)
                ));
                let pool = carrick_el1_abi::CowGrantPool::new();
                pool.publish(
                    77,
                    source_ipa + 0x4000,
                    BackingIdentity {
                        frame_id: nz(7),
                        mapping_id: nz(8),
                        owner_generation: nz(destination.generation()),
                        inventory_revision: nz(9),
                    },
                )
                .unwrap();
                let layout = std::alloc::Layout::new::<carrick_el1_abi::FrameGrantResidencyTable>();
                let raw = unsafe { std::alloc::alloc_zeroed(layout) };
                assert!(!raw.is_null());
                let residency = unsafe {
                    Box::from_raw(raw.cast::<carrick_el1_abi::FrameGrantResidencyTable>())
                };
                let publication_slot = carrick_el1_abi::PortalExecutableSlot::new();
                let publish = |grant, ipa, len| {
                    publication_slot.publish_with(
                        carrick_el1_abi::PortalExecutablePublication { grant, ipa, len },
                        || {
                            crossings.set(crossings.get() + 1);
                            assert!(publication_slot.handle(|request| {
                                physical.publish_claimed_executable(
                                    physical.carrier(),
                                    77,
                                    &pool,
                                    request,
                                )
                            }));
                        },
                    )
                };
                let result = carrick_el1::cow::resolve_guest_cow(
                    &carrick_el1::cow::GuestCowVenue {
                        publish_executable: Some(&publish),
                        words: &words,
                        root: SubstrateGpa(ROOT),
                        pool: &pool,
                        residency: &residency,
                        copy_window: carrick_el1::cow::CowCopyWindow::target(
                            &words,
                            SubstrateGpa(ROOT),
                        ),
                    },
                    77,
                    VA,
                    |from, to| {
                        let from =
                            arena[(0x5000 / 8) + indices(from)[3]].load(Ordering::Acquire) & PA;
                        let to = arena[(0x5000 / 8) + indices(to)[3]].load(Ordering::Acquire) & PA;
                        assert!((source_ipa..source_ipa + 16384).contains(&from));
                        assert!((source_ipa + 0x4000..source_ipa + 0x8000).contains(&to));
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                source.mapping.host_base().add((from - source_ipa) as usize),
                                destination
                                    .mapping
                                    .host_base()
                                    .add((to - source_ipa - 0x4000) as usize),
                                4096,
                            )
                        };
                    },
                    || {},
                );
                assert!(matches!(
                    result,
                    carrick_el1::cow::GuestCowOutcome::Resolved(_)
                ));
                arena[(0x3000 / 8) + va[3]].load(Ordering::Acquire) & PA
            } else {
                source_ipa
            };
            assert_eq!(crossings.get(), usize::from(executable && private));
            let executable_owner = destination.as_ref().unwrap_or(&source);
            if executable {
                // VM-free host RX execution (W^X), after independently proving
                // I2 completed. Guest execution remains a signed gate.
                if !private {
                    custody
                        .publish_user_executable(selected_ipa, 8, |_, _| None, |_, _| None)
                        .unwrap();
                }
                assert_eq!(
                    custody.publish_user_executable(selected_ipa, 8, |_, _| None, |_, _| None),
                    Ok(0)
                );
                assert_eq!(
                    unsafe {
                        executable_owner
                            .mapping
                            .host_base()
                            .cast::<u32>()
                            .read_unaligned()
                    },
                    u32::from_le_bytes(before)
                );
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            executable_owner.mapping.host_base().cast(),
                            16384,
                            libc::PROT_READ | libc::PROT_EXEC,
                        )
                    },
                    0,
                    "RX host view {mode}: {}",
                    std::io::Error::last_os_error()
                );
                let code: unsafe extern "C" fn() -> u32 =
                    unsafe { std::mem::transmute(executable_owner.mapping.host_base()) };
                assert_eq!(unsafe { code() }, 7);
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            executable_owner.mapping.host_base().cast(),
                            16384,
                            libc::PROT_READ | libc::PROT_WRITE,
                        )
                    },
                    0
                );
            }
            let mut edit = after;
            copy_selected_bytes(
                &physical,
                selected_ipa,
                PortalTransferIntent::UserWrite,
                &mut edit,
                executable,
            );
            if executable {
                assert_eq!(
                    custody.publish_user_executable(selected_ipa, 8, |_, _| None, |_, _| None),
                    Ok(0),
                    "write completed only after I2 publication"
                );
                assert_eq!(
                    unsafe {
                        executable_owner
                            .mapping
                            .host_base()
                            .cast::<u32>()
                            .read_unaligned()
                    },
                    u32::from_le_bytes(after)
                );
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            executable_owner.mapping.host_base().cast(),
                            16384,
                            libc::PROT_READ | libc::PROT_EXEC,
                        )
                    },
                    0,
                    "RX host view {mode}: {}",
                    std::io::Error::last_os_error()
                );
                let code: unsafe extern "C" fn() -> u32 =
                    unsafe { std::mem::transmute(executable_owner.mapping.host_base()) };
                assert_eq!(unsafe { code() }, 9);
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            executable_owner.mapping.host_base().cast(),
                            16384,
                            libc::PROT_READ | libc::PROT_WRITE,
                        )
                    },
                    0
                );
            }
            copy_bytes(
                &physical,
                selected_ipa,
                PortalTransferIntent::UserRead,
                &mut seen,
            );
            assert_eq!(&seen, &after);
            copy_bytes(
                &physical,
                source_ipa,
                PortalTransferIntent::UserRead,
                &mut seen,
            );
            assert_eq!(&seen, if private { &before } else { &after });
            file.rewind().unwrap();
            file.read_exact(&mut seen).unwrap();
            assert_eq!(
                &seen,
                if mode == "HostBackingShared" {
                    &after
                } else {
                    &before
                }
            );
            drop(destination);
            drop(source);
        }
    }
    #[test]
    fn dirty_compound_reuse_zeroes_fresh_partial_page_and_preserves_adjacent_owner() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let pool = Arc::new(crate::frame_pool::PreMappedFramePool::new_test_fixture(2));
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        custody.install_frame_pool(pool.clone());
        let adjacent = pool.allocate_compound().unwrap();
        let adjacent_ipa = adjacent.ipa();
        let dirty = pool.allocate_compound().unwrap();
        let reused_ipa = dirty.ipa();
        unsafe {
            std::ptr::write_bytes(adjacent.as_mut_ptr(), 0x31, adjacent.len());
            std::ptr::write_bytes(dirty.as_mut_ptr(), 0xe7, dirty.len());
        }
        register_pooled_global_frame_host_owner_in(
            &custody,
            adjacent,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .unwrap();
        drop(dirty);
        let physical = UserTransferCustody::new(custody.clone());
        let prepared = sparse_materialization::prepare(
            custody.clone(),
            0x4000_0000,
            0x4000_4000,
            SparseExtentBacking::Anon,
        )
        .unwrap();
        assert_eq!(prepared.physical_ipa, reused_ipa);
        assert_eq!(prepared.semantic_ipa, reused_ipa);
        let partial_page = prepared.semantic_ipa + 4096;
        let mut zero = [1; 4096];
        copy_bytes(
            &physical,
            partial_page,
            PortalTransferIntent::UserRead,
            &mut zero,
        );
        assert_eq!(zero, [0; 4096]);
        copy_bytes(
            &physical,
            partial_page,
            PortalTransferIntent::UserWrite,
            &mut [0x42],
        );
        let mut neighbor = [0; 4096];
        copy_bytes(
            &physical,
            adjacent_ipa + 4096,
            PortalTransferIntent::UserRead,
            &mut neighbor,
        );
        assert_eq!(neighbor, [0x31; 4096]);
        copy_bytes(
            &physical,
            partial_page,
            PortalTransferIntent::UserRead,
            &mut zero,
        );
        assert_eq!(zero[0], 0x42);
        assert!(zero[1..].iter().all(|byte| *byte == 0));
        drop(prepared);
    }
}
