use std::collections::BTreeMap;

pub(super) mod block;
pub(super) mod cache;
pub(super) mod decode;
pub(super) mod emit;
pub(super) mod gateway;
#[cfg(test)]
mod oracle;
pub(super) mod types;

#[derive(Debug)]
pub(super) enum ThreadExit {
    Syscall { resume: carrick_guest_mem::GuestVa },
    Continue,
    Unsupported(String),
}

pub(super) struct ThreadTranslator {
    cache: cache::TranslationCache,
    blocks: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), types::CacheVa>,
    pending: BTreeMap<(carrick_guest_mem::GuestVa, types::CodeGeneration), Vec<cache::LinkSite>>,
    resume_entry: Option<(
        carrick_guest_mem::GuestVa,
        types::CodeGeneration,
        types::CacheVa,
    )>,
    stats: ResolverStats,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ResolverStats {
    pub(super) resolver_exits: u64,
    pub(super) one_entry_hits: u64,
    pub(super) translations: u64,
    pub(super) duplicate_publications: u64,
}

impl ThreadTranslator {
    pub(super) fn new(capacity: usize) -> Result<Self, types::DsrError> {
        Ok(Self {
            cache: cache::TranslationCache::new(capacity)?,
            blocks: BTreeMap::new(),
            pending: BTreeMap::new(),
            resume_entry: None,
            stats: ResolverStats::default(),
        })
    }

    fn translate(
        &mut self,
        memory: &super::NativeMappedMemory,
        guest: carrick_guest_mem::GuestVa,
    ) -> Result<types::CacheVa, types::DsrError> {
        let key = (guest, types::CodeGeneration::INITIAL);
        if let Some(entry) = self.blocks.get(&key) {
            return Ok(*entry);
        }
        let block = block::plan_block(memory, guest, types::CodeGeneration::INITIAL, 256)?;
        let emitted = emit::emit_block(&mut self.cache, &block)?;
        self.stats.translations = self.stats.translations.saturating_add(1);
        let entry = emitted.entry();
        let links = emitted.direct_links().to_vec();
        self.blocks.insert(key, entry);

        for link in links {
            let target_key = (link.target, types::CodeGeneration::INITIAL);
            let site = cache::LinkSite {
                source: entry,
                slot: link.slot,
            };
            if let Some(target) = self.blocks.get(&target_key) {
                self.cache.patch_direct_branch(site, *target)?;
            } else {
                self.pending.entry(target_key).or_default().push(site);
            }
        }
        if let Some(sites) = self.pending.remove(&key) {
            for site in sites {
                self.cache.patch_direct_branch(site, entry)?;
            }
        }
        Ok(entry)
    }

    fn resolve_indirect(
        &mut self,
        memory: &super::NativeMappedMemory,
        source: carrick_guest_mem::GuestVa,
        target: carrick_guest_mem::GuestVa,
    ) -> Result<types::CacheVa, types::DsrError> {
        self.stats.resolver_exits = self.stats.resolver_exits.saturating_add(1);
        if !target.raw().is_multiple_of(4) {
            return Err(types::DsrError::InvalidIndirectTarget {
                source_pc: source.raw(),
                target: target.raw(),
                reason: "target is not instruction aligned",
            });
        }
        if !memory.guest_address_is_executable(target.raw()) {
            return Err(types::DsrError::InvalidIndirectTarget {
                source_pc: source.raw(),
                target: target.raw(),
                reason: "target is outside an executable guest mapping",
            });
        }
        self.translate(memory, target)
    }

    #[cfg(test)]
    pub(super) const fn resolver_stats(&self) -> ResolverStats {
        self.stats
    }

    pub(super) fn enter_once(
        &mut self,
        memory: &super::NativeMappedMemory,
        snapshot: &mut super::NativeUcontextSnapshot,
    ) -> Result<ThreadExit, types::DsrError> {
        let guest = carrick_guest_mem::GuestVa(snapshot.pc);
        let entry = match self.resume_entry.take() {
            Some((cached_guest, generation, entry))
                if cached_guest == guest && generation == types::CodeGeneration::INITIAL =>
            {
                self.stats.one_entry_hits = self.stats.one_entry_hits.saturating_add(1);
                entry
            }
            _ => self.translate(memory, guest)?,
        };
        let mut exit = types::NativeDsrExit::Syscall {
            resume: carrick_guest_mem::GuestVa(snapshot.pc),
        };
        gateway::enter_translated(entry, snapshot, &mut exit)?;
        Ok(match exit {
            types::NativeDsrExit::Syscall { resume } => ThreadExit::Syscall { resume },
            types::NativeDsrExit::ResolveDirect { target, .. } => {
                self.translate(memory, target)?;
                snapshot.pc = target.raw();
                ThreadExit::Continue
            }
            types::NativeDsrExit::ResolveIndirect { source, target, .. } => {
                let entry = self.resolve_indirect(memory, source, target)?;
                self.resume_entry = Some((target, types::CodeGeneration::INITIAL, entry));
                snapshot.pc = target.raw();
                ThreadExit::Continue
            }
            other => ThreadExit::Unsupported(format!("{other:?}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::decode::classify;
    use super::types::{DirectKind, IndirectKind, InstAction, PcRelativeKind, SensitiveKind};
    use carrick_guest_mem::GuestVa;
    use proptest::prelude::*;

    const PC: GuestVa = GuestVa(0x1000);

    #[test]
    fn dsr_indirect_resolver_stats_start_at_zero() {
        let translator = super::ThreadTranslator::new(16 * 1024).expect("create translator");
        assert_eq!(translator.resolver_stats(), super::ResolverStats::default());
    }

    #[test]
    fn classifies_copy_syscall_and_control_flow() {
        assert!(matches!(
            classify(0x9100_0400, PC),
            Ok(InstAction::Copy(0x9100_0400))
        ));
        assert!(matches!(
            classify(0xd400_0001, PC),
            Ok(InstAction::Syscall { resume }) if resume == GuestVa(0x1004)
        ));
        assert!(matches!(
            classify(0x1400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Branch && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0x9400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Call && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd61f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Branch
        ));
        assert!(matches!(
            classify(0xd65f_03c0, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Return
        ));
    }

    #[test]
    fn copy_subset_rejects_virtualized_x18_operands() {
        for word in [
            0xd280_0032, // mov x18, #1
            0xf940_0240, // ldr x0, [x18]
        ] {
            assert!(super::decode::decoded_operands_mention_x18(word, PC));
            assert!(matches!(
                classify(word, PC),
                Ok(InstAction::VirtualizedX18 { word: observed, .. }) if observed == word
            ));
        }
    }

    proptest! {
        #[test]
        fn copy_subset_never_contains_virtualized_x18(word in any::<u32>()) {
            if matches!(classify(word, PC), Ok(InstAction::Copy(_))) {
                prop_assert!(!super::decode::decoded_operands_mention_x18(word, PC));
            }
        }
    }

    #[test]
    fn classifies_pc_relative_and_sensitive_operations() {
        assert!(matches!(
            classify(0x1000_0040, PC),
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::Adr && inst.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd53b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadTpidr
        ));
        assert!(matches!(
            classify(0xd51b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::WriteTpidr
        ));
        assert!(matches!(
            classify(0xd50b_7420, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcZva
        ));
        assert!(matches!(
            classify(0x9000_0000, PC),
            Ok(InstAction::PcRelative(inst)) if inst.kind == PcRelativeKind::Adrp
        ));
        assert!(matches!(
            classify(0x5800_0040, PC),
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::LiteralLoad && inst.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd53b_0020, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadCtr
        ));
        assert!(matches!(
            classify(0xd53b_00e0, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadDczid
        ));
        assert!(matches!(
            classify(0xd50b_7b20, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcCvau
        ));
        assert!(matches!(
            classify(0xd50b_7520, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::IcIvau
        ));
    }

    #[test]
    fn classifies_conditional_compare_test_and_indirect_calls() {
        assert!(matches!(
            classify(0x5400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Conditional && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: false }
                    && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb500_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: true }
        ));
        assert!(matches!(
            classify(0x3600_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: false }
        ));
        assert!(matches!(
            classify(0x3700_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: true }
        ));
        assert!(matches!(
            classify(0xd63f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Call
        ));
    }

    proptest! {
        #[test]
        fn direct_branch_targets_follow_signed_imm26(word_offset in -0x1ff_ffff_i32..=0x1ff_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (word_offset as u32) & 0x03ff_ffff;
            let word = 0x1400_0000 | immediate;
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(word_offset) * 4));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::Direct(exit))
                    if exit.kind == DirectKind::Branch && exit.target == expected
            ));
        }

        #[test]
        fn adr_targets_follow_signed_imm21(byte_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (byte_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x1000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(byte_offset)));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adr && inst.target == expected
            ));
        }

        #[test]
        fn adrp_targets_follow_signed_page_imm21(page_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0abc);
            let immediate = (page_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x9000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa((pc.raw() & !0xfff).wrapping_add_signed(i64::from(page_offset) * 4096));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adrp && inst.target == expected
            ));
        }
    }

    #[test]
    fn dsr_cache_publishes_executable_aarch64_code() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let result = super::cache::TranslationCache::new(16 * 1024).and_then(|mut cache| {
                let mut writer = cache.begin_write(8)?;
                writer.write_words(&[0xd280_0540, 0xd65f_03c0])?; // mov x0,#42; ret
                let published = writer.publish()?;
                if published.len() != 8
                    || !cache.contains_host_pc(published.entry().host())
                    || cache.contains_host_pc(carrick_guest_mem::HostVa(1))
                {
                    return Err(super::types::DsrError::CachePolicy(
                        "published code metadata was inconsistent".to_string(),
                    ));
                }
                let function: extern "C" fn() -> u64 =
                    unsafe { std::mem::transmute(published.entry().host().raw()) };
                if function() != 42 {
                    return Err(super::types::DsrError::CachePolicy(
                        "published code returned the wrong value".to_string(),
                    ));
                }
                Ok(())
            });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_cache_second_publication_executes_new_instructions() {
        let mut cache =
            super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let mut first_writer = cache.begin_write(8).expect("begin first cache write");
        first_writer
            .write_words(&[0xd280_0540, 0xd65f_03c0])
            .expect("write first code");
        let first = first_writer.publish().expect("publish first code");
        let first_function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(first.entry().host().raw()) };
        assert_eq!(first_function(), 42);

        let mut second_writer = cache.begin_write(8).expect("begin second cache write");
        second_writer
            .write_words(&[0xd280_00e0, 0xd65f_03c0])
            .expect("write second code"); // mov x0,#7; ret
        let second = second_writer.publish().expect("publish second code");
        let second_function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(second.entry().host().raw()) };
        assert_eq!(second_function(), 7);
        assert_ne!(first.entry(), second.entry());
    }

    fn assert_child_faults(action: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            action();
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let fatal_handler_exit = libc::WIFEXITED(status)
            && matches!(
                libc::WEXITSTATUS(status),
                value if value == 128 + libc::SIGBUS || value == 128 + libc::SIGSEGV
            );
        assert!(
            fatal_handler_exit
                || (libc::WIFSIGNALED(status)
                    && matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV)),
            "child unexpectedly survived W/X violation: status=0x{status:x}"
        );
    }

    #[test]
    fn dsr_cache_write_and_execute_phases_are_disjoint() {
        assert_child_faults(|| {
            let mut cache =
                super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
            let mut writer = cache.begin_write(8).expect("begin cache write");
            writer
                .write_words(&[0xd280_0540, 0xd65f_03c0])
                .expect("write code");
            let function: extern "C" fn() -> u64 =
                unsafe { std::mem::transmute(writer.entry_for_test().host().raw()) };
            let _ = function();
        });

        assert_child_faults(|| {
            let mut cache =
                super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
            let mut writer = cache.begin_write(8).expect("begin cache write");
            writer
                .write_words(&[0xd280_0540, 0xd65f_03c0])
                .expect("write code");
            let published = writer.publish().expect("publish code");
            let ptr = published.entry().host().raw() as *mut u32;
            unsafe { std::ptr::write_volatile(ptr, 0xd280_00e0) };
        });
    }

    #[test]
    fn dsr_cache_published_code_is_fork_inherited() {
        let mut cache =
            super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let mut writer = cache.begin_write(8).expect("begin cache write");
        writer
            .write_words(&[0xd280_0540, 0xd65f_03c0])
            .expect("write code");
        let published = writer.publish().expect("publish code");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let function: extern "C" fn() -> u64 =
                unsafe { std::mem::transmute(published.entry().host().raw()) };
            unsafe { libc::_exit(i32::from(function() != 42)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_cache_child_discards_inherited_unpublished_write() {
        let mut cache =
            super::cache::TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let writer = cache.begin_write(8).expect("begin inherited cache write");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            drop(writer);
            let result = cache.begin_write(8).and_then(|mut clean_writer| {
                clean_writer.write_words(&[0xd280_00e0, 0xd65f_03c0])?;
                let published = clean_writer.publish()?;
                let function: extern "C" fn() -> u64 =
                    unsafe { std::mem::transmute(published.entry().host().raw()) };
                if function() != 7 {
                    return Err(super::types::DsrError::CachePolicy(
                        "child clean transaction returned the wrong value".to_string(),
                    ));
                }
                Ok(())
            });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);

        drop(writer);
    }

    #[test]
    fn dsr_cache_exhaustion_is_a_typed_error() {
        let mut cache =
            super::cache::TranslationCache::new(1).expect("allocate one-page translation cache");
        let error = match cache.begin_write(16 * 1024 + 4) {
            Ok(_) => panic!("oversized write should exhaust cache"),
            Err(error) => error,
        };
        assert!(matches!(error, super::types::DsrError::CachePolicy(_)));
    }
}
