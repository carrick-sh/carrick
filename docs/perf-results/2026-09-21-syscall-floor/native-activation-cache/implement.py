from pathlib import Path
# A wrapper invalidates on every mutable access, including take/replace/as_mut.
p=Path('crates/carrick-aarch64/src/stage1_authority.rs');s=p.read_text();pos=s.index('struct Stage1AuthorityInner')
s=s[:pos]+'''/// All mutable access to the software image advances this generation before
/// exposing the manager. Failed edits and rollbacks invalidate too. Exhaustion
/// permanently disables reuse; it never wraps to an older valid generation.
struct TrackedStage1Image {
    image: Option<PageTableManager>,
    generation: Option<std::num::NonZeroU64>,
}
impl std::ops::Deref for TrackedStage1Image {
    type Target = Option<PageTableManager>;
    fn deref(&self) -> &Self::Target { &self.image }
}
impl std::ops::DerefMut for TrackedStage1Image {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.generation = self.generation.and_then(|g| g.get().checked_add(1)).and_then(std::num::NonZeroU64::new);
        &mut self.image
    }
}

'''+s[pos:]
s=s.replace('struct Stage1AuthorityInner {\n    manager: Option<PageTableManager>,','struct Stage1AuthorityInner {\n    manager: TrackedStage1Image,',1)
s=s.replace('                manager,\n                arena_source: None,','                manager: TrackedStage1Image { image: manager, generation: std::num::NonZeroU64::new(1) },\n                arena_source: None,',1)
s=s.replace('std::mem::replace(&mut inner.manager, manager)','std::mem::replace(&mut *inner.manager, manager)')
s=s.replace('self.inner.lock().manager = Some(manager);','*self.inner.lock().manager = Some(manager);')
s=s.replace('self.inner.lock().manager.clone()','(*self.inner.lock().manager).clone()')
s=s.replace('inner.manager = Some(manager);','*inner.manager = Some(manager);').replace('inner.manager = new_manager;','*inner.manager = new_manager;')
s=s.replace('prev_guard.manager = Some(old);','*prev_guard.manager = Some(old);').replace('new_guard.manager = Some(old);','*new_guard.manager = Some(old);')
pos=s.index('    /// Discard the open undo journal')
s=s[:pos]+'''    /// Observe the exact image and its mutation generation under one lock.
    /// A generation has meaning only with this retained authority's identity.
    /// `None` disables reuse after generation exhaustion. The callback cannot
    /// mutate the image or retain a reference beyond this lock.
    pub fn try_with_manager_generation_until<F, R, E>(
        &self, deadline: std::time::Instant, on_timeout: E, on_absent: E, f: F,
    ) -> Result<R, E>
    where F: FnOnce(&PageTableManager, Option<std::num::NonZeroU64>) -> Result<R, E> {
        let guard = self.inner.try_lock_until(deadline).ok_or(on_timeout)?;
        let manager = guard.manager.as_ref().ok_or(on_absent)?;
        f(manager, guard.manager.generation)
    }

'''+s[pos:];p.write_text(s)
# Optional allocation-free stamp; an unimplemented backend keeps full snapshots.
p=Path('crates/carrick-kernel/src/kernel/address.rs');s=p.read_text();pos=s.index('pub trait MmBackend:')
s=s[:pos]+'''/// Revisions of all tables in an MM snapshot, observed through the same
/// backend protocol. Valid only for the exact retained backend instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmBackendStamp {
    pub revision: u64,
    pub binding: MmBinding,
    pub vma_revision: VmaRevision,
    pub frame_inventory_revision: u64,
}

'''+s[pos:];s=s.replace('pub trait MmBackend: Send + Sync {','''pub trait MmBackend: Send + Sync {
    /// Optional cheap validation of a previously authenticated snapshot.
    /// Implementations must advance the relevant revision for EVERY content or
    /// source change, including change/restoration, and never reuse a revision.
    /// A stamp cannot itself authenticate a caller-created snapshot's contents.
    fn snapshot_stamp(&self, _deadline: Instant) -> Result<Option<MmBackendStamp>, SnapshotError> {
        Ok(None)
    }''',1);p.write_text(s)
p=Path('crates/carrick-kernel/src/kernel/mod.rs');s=p.read_text().replace('Asid, MmBackend, MmBackendSnapshot,','Asid, MmBackend, MmBackendSnapshot, MmBackendStamp,',1);p.write_text(s)
p=Path('crates/carrick-kernel/src/kernel/frame_inventory.rs');s=p.read_text().replace('    pub(crate) fn revision_until(','''    /// Observe the inventory publication generation without copying its rows.
    /// Only validates an already authenticated snapshot of this exact inventory.
    pub fn revision_until(''',1);p.write_text(s)
p=Path('crates/carrick-runtime/src/hvpatch/stage1_mm.rs');s=p.read_text();s=s.replace('        *self.vma_source.write() = Some(source);\n        self.bump_revision();','        let mut slot = self.vma_source.write();\n        *slot = Some(source);\n        self.bump_revision();',1).replace('            drop(slot);\n            backend.bump_revision();','            backend.bump_revision();\n            drop(slot);',1)
pos=s.index('    fn snapshot(&self, deadline:',s.index('impl MmBackend for Stage1MmBackend'))
s=s[:pos]+'''    fn snapshot_stamp(&self, deadline: Instant) -> Result<Option<carrick_kernel::kernel::MmBackendStamp>, SnapshotError> {
        let before = self.revision.load(Ordering::Acquire);
        let binding = *self.binding.try_read_until(deadline).ok_or_else(|| deadline_error(deadline))?;
        let source = self.vma_source.try_read_until(deadline).ok_or_else(|| deadline_error(deadline))?
            .clone().ok_or(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))?;
        let kernel = {
            let slot = self.inventory.try_read_until(deadline).ok_or_else(|| deadline_error(deadline))?;
            slot.as_ref().and_then(|inventory| inventory.kernel.upgrade())
                .ok_or(SnapshotError::AuthorityUnavailable(SnapshotTable::Mappings))?
        };
        // Never hold a backend lock across an independent authority's read.
        let vma_revision = source.revision();
        let frame_inventory_revision = kernel.frame_inventory().revision_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?;
        if before != self.revision.load(Ordering::Acquire) || vma_revision != source.revision() {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        Ok(Some(carrick_kernel::kernel::MmBackendStamp { revision: before, binding, vma_revision, frame_inventory_revision }))
    }

'''+s[pos:];p.write_text(s)
# Comparison without allocating retained vectors; used only by native activation.
p=Path('crates/carrick-hal/src/foreign_mm.rs');s=p.read_text();s=s.replace('pub trait ForeignMmSnapshot: Debug + Send + Sync {','''pub trait ForeignMmSnapshot: Debug + Send + Sync {
    fn has_same_contents(&self, other: &dyn ForeignMmSnapshot) -> bool {
        self.mm() == other.mm() && self.binding() == other.binding()
            && self.backend_revision() == other.backend_revision()
            && self.vma_revision() == other.vma_revision()
            && self.frame_inventory_revision() == other.frame_inventory_revision()
            && self.mapping_ids() == other.mapping_ids()
            && self.executable_ranges() == other.executable_ranges()
            && self.readable_ranges() == other.readable_ranges()
    }''',1)
s=s.replace('pub trait ForeignMmLiveAuthority: Send + Sync {','''pub trait ForeignMmLiveAuthority: Send + Sync {
    /// Validate an already authenticated snapshot. Implementations may use
    /// non-reusing revisions of the exact authority; otherwise copy and compare.
    /// This does not authenticate arbitrary caller-supplied snapshot contents.
    fn matches_authenticated_snapshot(&self, expected: &dyn ForeignMmSnapshot, deadline: Instant) -> Result<bool, ForeignMmTransportError> {
        Ok(self.snapshot(deadline)?.has_same_contents(expected))
    }''',1)
start=s.index('    fn validate_native_activation(');end=s.index('    /// # Safety',start);chunk=s[start:end].replace('&self,','&mut self,',1).replace('        authority: &dyn ForeignMmLiveAuthority,\n','').replace('(authority, snapshot, deadline)','(snapshot, deadline)');s=s[:start]+chunk+s[end:]
s=s.replace('owner generation, protection tracker and every crossed user-RW leaf. A saved','owner generation, protection tracker and every crossed user-RW leaf (or an\n/// exact authority generation proving those leaf checks remain valid). A saved',1)
s=s.replace('    /// default refuses activation, even for an otherwise valid pinned span.','''    /// kernel validates its authenticated snapshot before and after this call.
    /// The default refuses activation, even for an otherwise valid pinned span.''',1);p.write_text(s)
# Kernel owns the before/after snapshot checks; transport checks live physical authority.
p=Path('crates/carrick-kernel/src/kernel/mm_access.rs');s=p.read_text();pos=s.index('    fn snapshot(',s.index('impl carrick_hal::ForeignMmLiveAuthority for RetainedMmLiveAuthority'))
s=s[:pos]+'''    fn matches_authenticated_snapshot(&self, expected: &dyn carrick_hal::ForeignMmSnapshot, deadline: Instant) -> Result<bool, carrick_hal::ForeignMmTransportError> {
        let backend = self.mm.backend().ok_or(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?;
        if let Some(stamp) = backend.snapshot_stamp(deadline).map_err(|e| snapshot_error_for_transport(MmAccessError::Snapshot(e)))? {
            return Ok(expected.mm().raw_for_probe() == self.mm.id().raw()
                && expected.binding().asid().raw_for_probe() == stamp.binding.asid.raw()
                && expected.binding().stage1_root() == stamp.binding.stage1_root.gpa()
                && expected.backend_revision() == carrick_hal::ForeignBackendRevision::from_authority_raw(stamp.revision)
                && expected.vma_revision() == carrick_hal::ForeignVmaRevision::from_authority_raw(stamp.vma_revision.raw())
                && expected.frame_inventory_revision() == carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(stamp.frame_inventory_revision));
        }
        Ok(self.snapshot(deadline)?.has_same_contents(expected))
    }

'''+s[pos:]
start=s.index('        let before = snapshot_backend(',s.index('impl PreparedNativeData'));end=s.index('        scope.data_context(mutation)?;',start)
s=s[:start]+'''        use carrick_hal::ForeignMmLiveAuthority;
        let live = RetainedMmLiveAuthority { mm: Arc::clone(&self.token.mm) };
        // The opaque preparation already authenticated permissions and contents.
        // These revisions belong to its immutable MM backend; they cannot grant
        // authority to a new or caller-created snapshot.
        if !live.matches_authenticated_snapshot(&self.snapshot, deadline).map_err(MmAccessError::ForeignTransport)? {
            return Err(MmAccessError::StaleNativeData);
        }
        self.transport.validate_native_activation(&self.snapshot, deadline)
            .map_err(MmAccessError::ForeignTransport)?;
        if !live.matches_authenticated_snapshot(&self.snapshot, deadline).map_err(MmAccessError::ForeignTransport)? {
            return Err(MmAccessError::StaleNativeData);
        }
'''+s[end:];p.write_text(s)
p=Path('crates/carrick-vmm-hvf/src/trap/foreign_mm.rs');s=p.read_text();start=s.index('struct CarrierNativeDataSpan');pos=s.index('\n}',start);s=s[:pos]+'''\n    validated_stage1: Option<(carrick_aarch64::Stage1Authority, std::num::NonZeroU64)>,'''+s[pos:]
start=s.index('    fn validate_native_activation(');end=s.index('    unsafe fn as_mut_ptr',start);chunk=s[start:end]
chunk=chunk.replace('&self,','&mut self,',1).replace('        authority: &dyn carrick_hal::ForeignMmLiveAuthority,\n','')
chunk=chunk.replace('if !self.range.snapshot.matches(snapshot)\n            || !live_snapshot_matches(authority, &self.range.snapshot, deadline)?','if !carrick_hal::ForeignMmSnapshot::has_same_contents(&self.range.snapshot, snapshot)')
chunk=chunk.replace('        self.state.page_tables_authority().try_with_manager_until(','''        let page_tables = self.state.page_tables.try_read_until(deadline).ok_or(Error::TimedOut)?;
        let validated_generation = page_tables.try_with_manager_generation_until(''')
chunk=chunk.replace('            |tables| {','''            |tables, generation| {
                if generation.is_some_and(|current| self.validated_stage1.as_ref().is_some_and(|(authority, saved)| authority.shares_exact_authority(&page_tables) && *saved == current)) {
                    return Ok(generation);
                }''',1)
chunk=chunk.replace('                Ok(())\n            },','                Ok(generation)\n            },',1)
chunk=chunk.replace('''        if !live_snapshot_matches(authority, &self.range.snapshot, deadline)? {
            return Err(Error::LeaseStale);
        }
        Ok(())''','''        if let Some(generation) = validated_generation {
            if !self.validated_stage1.as_ref().is_some_and(|(saved, old)| saved.shares_exact_authority(&page_tables) && *old == generation) {
                self.validated_stage1 = Some((page_tables.clone(), generation));
            }
        } else { self.validated_stage1 = None; }
        Ok(())''',1)
s=s[:start]+chunk+s[end:];s=s.replace('Box::new(CarrierNativeDataSpan {','Box::new(CarrierNativeDataSpan {\n                    validated_stage1: None,',1);p.write_text(s)
