from pathlib import Path
p=Path('crates/carrick-aarch64/src/stage1_authority.rs');s=p.read_text();pos=s.index('    #[test]',s.index('mod tests {'))
s=s[:pos]+'''    fn observed_generation(authority: &Stage1Authority) -> Option<std::num::NonZeroU64> {
        authority.try_with_manager_generation_until(std::time::Instant::now() + std::time::Duration::from_secs(1), (), (), |_, generation| Ok(generation)).unwrap()
    }

    #[test]
    fn image_generation_invalidates_edits_errors_restore_and_replacement() {
        let manager = || PageTableManager::new(stage1_hvpatch_page_tables(), LINUX_PAGE_TABLES_BASE);
        let mut authority = Stage1Authority::new_with_manager(Some(manager()));
        let original = observed_generation(&authority);
        authority.with_manager(|m| m.debug_walk(0x40_0000));
        let image = authority.snapshot_image().unwrap();
        assert_eq!(observed_generation(&authority), original, "reads preserve generation");
        let failed = authority.edit(|| Err(()), |editor| {
            editor.set_readonly(0x40_0000, 0x1000, false).unwrap();
            Err::<(), _>(())
        });
        assert!(failed.is_err());
        let after_error = observed_generation(&authority);
        assert_ne!(after_error, original);
        authority.restore_image(image, 0);
        let after_restore = observed_generation(&authority);
        assert_ne!(after_restore, original);
        assert_ne!(after_restore, after_error);
        authority.try_edit_until(std::time::Instant::now() + std::time::Duration::from_secs(1), (), (), || Err(()), |_| Ok(())).unwrap();
        let after_try_edit = observed_generation(&authority);
        assert_ne!(after_try_edit, after_restore);
        authority.set_manager(manager());
        let after_set = observed_generation(&authority);
        assert_ne!(after_set, after_try_edit);
        let saved = authority.replace_manager(None).unwrap();
        authority.replace_manager(Some(saved));
        let after_replace = observed_generation(&authority);
        assert_ne!(after_replace, after_set);
        let previous = Stage1Authority::new_with_manager(Some(manager()));
        let previous_generation = observed_generation(&previous);
        authority.adopt_unshared_predecessor(&previous);
        assert_ne!(observed_generation(&previous), previous_generation);
        assert_ne!(observed_generation(&authority), after_replace);
        let before_exec = observed_generation(&authority);
        let exact = authority.clone();
        authority.replace_for_exec(|| Ok::<_, ()>(Some(manager())), |_| Ok(())).unwrap();
        assert!(authority.shares_exact_authority(&exact));
        assert_ne!(observed_generation(&authority), before_exec);
        // Taking an image invalidates even if exec preparation subsequently fails.
        assert!(authority.replace_for_exec(|| Err::<Option<PageTableManager>, _>(()), |_| Ok(())).is_err());
        assert!(authority.is_none());
        authority.set_manager(manager());
        assert_ne!(observed_generation(&authority), before_exec);
    }

    #[test]
    fn image_generation_exhaustion_never_reenables_reuse() {
        let authority = Stage1Authority::new_with_manager(Some(PageTableManager::new(stage1_hvpatch_page_tables(), LINUX_PAGE_TABLES_BASE)));
        authority.inner.lock().manager.generation = std::num::NonZeroU64::new(u64::MAX);
        for _ in 0..2 {
            authority.edit(|| Err::<PageTableManager, ()>(()), |_| Ok(())).unwrap();
            assert_eq!(observed_generation(&authority), None);
        }
    }

'''+s[pos:]
s=s.replace('        // Rollback via Stage1Authority::rollback_undo\n        unsafe {','        // Rollback via Stage1Authority::rollback_undo\n        let before_rollback = observed_generation(&authority);\n        unsafe {',1).replace('            authority.rollback_undo(resolver);\n        }','            authority.rollback_undo(resolver);\n        }\n        assert_ne!(observed_generation(&authority), before_rollback);',1);p.write_text(s)
p=Path('crates/carrick-vmm-hvf/src/trap/foreign_mm.rs');s=p.read_text();s=s.replace('''        /// Mutate only fixture state, after COW has minted a witness, to test
        /// refusal independently of the kernel VMA revision check.
        /// Counts actual terminal-leaf validations performed during activation.''','''        /// Counts actual terminal-leaf validations performed during activation.''',1).replace('        pub fn deny_native_data_for_test','''        /// Change the live carrier authority independently of kernel VMA revisions.
        pub fn deny_native_data_for_test''',1)
start=s.index('        pub fn deny_native_data_for_test');pos=s.index('                _ => Err("unknown fixture denial"',start)
s=s[:pos]+'''                4 => {
                    let old = self.state.page_tables_authority();
                    let generation = old.try_with_manager_generation_until(std::time::Instant::now() + std::time::Duration::from_secs(1), "busy", "absent", |_, g| Ok(g)).map_err(str::to_owned)?.ok_or("exhausted")?;
                    let mut image = old.snapshot_image().ok_or("absent")?;
                    image.set_readonly(start, 0x1000, false, None).map_err(|e| format!("readonly: {e:?}"))?;
                    let replacement = carrick_aarch64::Stage1Authority::new_with_manager(Some(image));
                    // Deliberately collide numeric generations of DIFFERENT authorities.
                    for _ in 1..generation.get() {
                        replacement.edit(|| Err("absent"), |_| Ok(())).map_err(str::to_owned)?;
                    }
                    *self.state.page_tables.write() = replacement;
                    Ok(())
                }
                5 => self.state.page_tables_authority().edit(
                    || Err("absent".to_owned()),
                    |editor| {
                        let old = editor.translate_retained_output(start).ok_or("absent")?;
                        editor.unmap_aliased(start, 0x1000).map_err(|e| format!("unmap: {e:?}"))?;
                        editor.map_aliased(start, old + 0x1000, 0x1000, true).map_err(|e| format!("remap: {e:?}"))?;
                        Ok(())
                    },
                ),
'''+s[pos:];p.write_text(s)
p=Path('crates/carrick-runtime/src/vcpu_loop/memory.rs');s=p.read_text();start=s.index('    fn native_data_activation_rejects_changes_after_preparation');end=s.index('    #[test]',start);chunk=s[start:end].replace('for mode in 0..7','for mode in 0..10',1)
chunk=chunk.replace('                            _ => unreachable!(),','''                            7 | 8 => fixture.carrier.deny_native_data_for_test(TEST_VA + 4096, (mode - 3) as u8).unwrap(),
                            // Equal binding values cannot revive an older backend revision.
                            9 => { let backend = fixture.stage1.backend(); backend.publish_binding(backend.binding()); },
                            _ => unreachable!(),''',1)
s=s[:start]+chunk+s[end:];p.write_text(s)
