//! Compiled-frame contracts for the ARM entry chains that retain native owners.
//!
//! These are conservative, reviewed chain envelopes, not a whole-program Rust
//! call-graph analysis. In particular, indirect copy/descriptor calls must be
//! charged explicitly; following only `bl` misses precisely those callees.
//! See docs/el1-stack-budget.md for the scope and nesting arguments.
use std::collections::BTreeMap;

#[derive(Debug)]
pub(crate) struct Frames(BTreeMap<String, usize>);

fn immediate(operands: &str) -> Result<usize, String> {
    let number = operands
        .split('#')
        .nth(1)
        .and_then(|value| value.split([',', ' ', ']']).next())
        .ok_or_else(|| format!("missing stack immediate: {operands}"))?;
    let amount = if let Some(hex) = number.strip_prefix("0x") {
        usize::from_str_radix(hex, 16)
    } else {
        number.parse()
    }
    .map_err(|_| format!("invalid stack immediate: {operands}"))?;
    Ok(if operands.contains("lsl #12") {
        amount << 12
    } else {
        amount
    })
}

impl Frames {
    pub(crate) fn parse(disassembly: &str) -> Result<Self, String> {
        let mut frames = BTreeMap::new();
        let mut current: Option<(String, usize)> = None;
        let mut prologue = true;
        let mut aligned = false;
        for line in disassembly.lines() {
            let line = line.trim();
            if let Some((address, name)) = line.strip_suffix(">:").and_then(|s| s.split_once(" <"))
                && u64::from_str_radix(address, 16).is_ok()
            {
                if let Some((name, size)) = current.take() {
                    frames.insert(name, size);
                }
                current = Some((name.to_owned(), 0));
                prologue = true;
                aligned = false;
                continue;
            }
            let Some((_, size)) = current.as_mut() else {
                continue;
            };
            if !prologue {
                continue;
            }
            let Some((address, instruction)) = line.split_once(':') else {
                continue;
            };
            if u64::from_str_radix(address, 16).is_err() {
                continue;
            }
            let instruction = instruction.split("//").next().unwrap_or("").trim();
            let Some((mnemonic, operands)) = instruction.split_once(char::is_whitespace) else {
                continue;
            };
            let operands = operands.trim();
            // LLVM can shrink-wrap the allocation past an early fast-path
            // branch. Follow the allocation through its first call/return,
            // rather than stopping at a branch or an arbitrary N instructions.
            if *size > 0 && matches!(mnemonic, "bl" | "blr" | "ret") {
                prologue = false;
                continue;
            }
            if matches!(mnemonic, "stp" | "str")
                && operands.contains("[sp, #-")
                && operands.contains("]!")
            {
                *size += immediate(&operands.replace("#-", "#"))?;
            }
            if mnemonic == "sub" {
                if operands.starts_with("x9, sp,") {
                    aligned = true;
                    // LLVM rounds down to the 64-byte ThreadCtx alignment.
                    // Charge its maximum padding as well as the target SP.
                    *size += 63;
                }
                if operands.starts_with("sp, sp,") && !aligned
                    || aligned
                        && (operands.starts_with("x9, sp,") || operands.starts_with("x9, x9,"))
                {
                    *size += immediate(operands)?;
                }
            }
            if mnemonic == "and"
                && operands.starts_with("sp,")
                && (!aligned || !operands.ends_with("#0xffffffffffffffc0"))
            {
                return Err(format!("unrecognized stack realignment: {instruction}"));
            }
        }
        if let Some((name, size)) = current {
            frames.insert(name, size);
        }
        if frames.is_empty() {
            return Err("no ARM function frames measured".to_owned());
        }
        Ok(Self(frames))
    }

    /// Max across all emitted monomorphizations. Inlined callees are charged
    /// by their caller's measured frame, so an absent optional leaf costs zero.
    pub(crate) fn maximum(&self, fragment: &str) -> usize {
        self.0
            .iter()
            .filter(|(name, _)| {
                name.contains(fragment)
                    && (!fragment.ends_with("::")
                        || name.rsplit_once("::").is_some_and(|(head, _)| {
                            head.ends_with(fragment.trim_end_matches("::"))
                        }))
                    && (fragment.contains("closure") || !name.contains("closure"))
            })
            .map(|(_, size)| *size)
            .max()
            .unwrap_or(0)
    }

    fn qualified(&self, owner: &str, method: &str) -> usize {
        self.0
            .iter()
            .filter(|(name, _)| name.contains(owner) && name.contains(method))
            .map(|(_, size)| *size)
            .max()
            .unwrap_or(0)
    }

    fn required(&self, fragment: &str) -> Result<usize, String> {
        let size = self.maximum(fragment);
        if size == 0 {
            return Err(format!("missing retained EL1 frame {fragment}"));
        }
        Ok(size)
    }

    fn sum(&self, fragments: &[&str]) -> usize {
        fragments
            .iter()
            .map(|fragment| self.maximum(fragment))
            .sum()
    }

    pub(crate) fn check(
        &self,
        stack_size: usize,
        vector_size: usize,
    ) -> Result<Vec<String>, String> {
        let limit = stack_size * 3 / 4;
        let entry = vector_size
            + self.required("carrick_el1_syscall")?
            + self.required("::dispatch::dispatch_entry::")?;
        let native = entry
            + self
                .required("::dispatch::dispatch_syscall::")?
                .max(self.required("::dispatch::arm_signal_user_return::")?)
            + self.required("::aarch64_process::with_process_entry::")?;
        let resume = entry
            + self.sum(&[
                "::interrupt::",
                "::preempt_record::",
                "::idle::",
                "::load::",
                "::aarch64_process::resume_production::",
                "::aarch64_process::resume_selected::",
                "::resume_checkpoint::",
                "::resume_pending_lifecycle::",
            ]);
        // Notification retirement and allocation can wake a guest while every
        // outer owner/editor frame is live. Include panic tails as well.
        let schedule = self.sum(&[
            "ObjectWaitGuard$LT$C$GT$$u20$as$u20$core..ops..drop..Drop$GT$::drop::",
            "::place_in_guest::",
            "::find_idle_except::",
            "::accepts::",
            "::running_raw::",
            "::panic_bounds_check",
            "::panic_fmt",
            "__rustc::rust_begin_unwind",
        ]);
        let allocation = self
            .maximum("MetadataStorage::allocate::")
            .max(self.maximum("MetadataStorage::deallocate::"))
            + self.sum(&[
                "MetadataStorage::service_mailbox::",
                "MetadataStorage::publish_pending_return::",
            ])
            + schedule;
        let root = self.sum(&[
            "::root_any::",
            "::lock_using::",
            "core::ptr::drop_in_place$LT$carrick_core..mm..reservation..root..Reservations",
            "::release_retiring_resource::",
            "::release_resource::",
        ]) + schedule;
        // Four architectural table levels. Charge descend at every level too,
        // although the level-3 leaf cannot descend. Trait calls are included.
        let descriptors = self
            .maximum("::execute_descriptor_txn::")
            .max(self.maximum("::execute_descriptor_op::"))
            + 4 * self.sum(&["::visit_live_table::", "::visit_entry::", "::descend::"])
            + self.sum(&["::store::", "::unlink::"])
            + self.qualified("descriptor_txn::InlineJournal", "::reserve::")
            + allocation;
        let write = self.required("::copy_signal_bytes::")?
            + self.required("::write_user_bytes::")?
            + self.sum(&["::authorize::", "::root_for::"])
            + root;
        // A failed caught signal can force SIGSEGV once; a failed SIGSEGV
        // delivery terminates, so two delivery frames is the maximum nesting.
        let delivery = self.required("::arm_signal::deliver_on_user_return::")?
            + 2 * self.required("::signal_delivery::deliver_signal_on_syscall_return::")?
            + self.maximum("::signal_delivery::force_delivery_fault::");
        let chains = [
            (
                "native admission",
                native
                    + self.required("::admit_entry_runtime::")?
                    + self.sum(&[
                        "::admit_fresh_root::",
                        "::process_owner::GuestTask$LT$C$C$U$C$N$GT$::new::",
                        "::process_owner::GuestThreads::new::",
                    ])
                    + allocation,
            ),
            (
                "native fork publication",
                native
                    + self.required("::fork_owned::")?
                    + self.required("::prepare_mm::")?
                    + self.maximum("::publish_fork::")
                    + self.maximum("::root::")
                    + root,
            ),
            (
                "native fork descriptors",
                native
                    + self.required("::fork_owned::")?
                    + self.required("::prepare_mm::")?
                    + self.maximum("::prepare_fork::")
                    + descriptors,
            ),
            (
                "native fork context",
                native
                    + self.required("::fork_owned::")?
                    + self.maximum("::fork_child_context_boxed::")
                    + allocation,
            ),
            // Commit copies the 128-byte settlement onto the stopped CPU's
            // stack. The release of the child's space gate may also schedule
            // another lane, so retain the owner and allocation frames here.
            (
                "native fork settlement",
                native
                    + self.required("::fork_owned::")?
                    + self.required("::settle_mm::")?
                    + allocation,
            ),
            (
                "native wait copy",
                native.max(resume)
                    + self.required("::wait_query::")?
                    + self.maximum("::copy_with::")
                    + write,
            ),
            (
                "signal delivery copy",
                native
                    + delivery
                    + self.required("::setup_arm_signal_frame::")?
                    + self.maximum(
                        "::signal_delivery::deliver_signal_on_syscall_return::_$u7b$$u7b$closure",
                    )
                    + write,
            ),
            // Resume checkpoints service pending exit directly. Delivery runs
            // after scheduler return, with that resume entry already dropped.
            (
                "signal terminal exit",
                (native + delivery).max(resume)
                    + self.sum(&[
                        "::exit_with_signal::",
                        "::exit_with_status::",
                        "::native_process_entry::publish_exit::",
                        "::finish_exit::",
                        "::publish_exit_receipt::",
                        "::insert_recursing::",
                    ])
                    + allocation,
            ),
            (
                "signal return",
                native
                    + self.required("::restore_live_arm_signal_frame::")?
                    + self.sum(&[
                        "::restore_signal_frame::",
                        "::arm_signal::restore::",
                        "::arm::decode::",
                    ])
                    + allocation,
            ),
            (
                "anonymous munmap",
                entry
                    + self.required("::dispatch::dispatch_syscall::")?
                    + self.required("::serve_delegated_anonymous::")?
                    + self.maximum("::protect_existing_el1_private_pages::")
                    + descriptors,
            ),
            (
                "metadata grant",
                entry
                    + self.required("::serve_grant_hw::")?
                    + self.sum(&["::apply_grant::", "::execute_grant::"])
                    + descriptors,
            ),
            (
                "backing retirement",
                entry
                    + self.required("::serve_backing_maintenance_hw::")?
                    + self.maximum("::begin_backing_maintenance::")
                    + root
                    + descriptors,
            ),
            (
                "descriptor drain",
                entry
                    + self.maximum("::drain_before_el0_hw::")
                    + self.maximum("::dispatch_fault::")
                    + self.maximum("HardwareDescriptorTxnApplier")
                    + descriptors,
            ),
        ];
        let mut report = Vec::new();
        let mut failures = Vec::new();
        for (name, bytes) in chains {
            let line = format!(
                "EL1 stack {name}: {bytes} / {limit} bytes (stack {stack_size}, vector included)"
            );
            if bytes > limit {
                failures.push(line.clone());
            }
            report.push(line);
        }
        // No new giant frame may hide outside the registered chain families.
        for (name, size) in &self.0 {
            if *size > stack_size * 3 / 16 {
                failures.push(format!(
                    "EL1 individual frame {name}: {size} > {} bytes",
                    stack_size * 3 / 16
                ));
            }
        }
        if failures.is_empty() {
            Ok(report)
        } else {
            Err(failures.join("\n"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_long_probe_prologue_and_does_not_borrow_next_frame() {
        let mut input = "1000 <large>:\n1000: stp x29, x30, [sp, #-0x60]!\n".to_owned();
        for _ in 0..8 {
            input.push_str("1004: sub sp, sp, #0x1, lsl #12\n1008: str xzr, [sp]\n100c: nop\n");
        }
        input.push_str("1010: sub sp, sp, #0x20\n1014: bl 0x2000 <tail>\n2000 <tail>:\n2000: b 0x3000 <leaf>\n3000 <leaf>:\n3000: stp x29, x30, [sp, #-0x10]!\n3004: ret\n");
        let frames = Frames::parse(&input).unwrap();
        assert_eq!(frames.maximum("large"), 8 * 4096 + 128);
        assert_eq!(frames.maximum("tail"), 0);
        assert_eq!(frames.maximum("leaf"), 16);
    }

    #[test]
    fn cumulative_frames_and_an_oversized_new_function_are_rejected() {
        let mut values = BTreeMap::new();
        for name in [
            "carrick_el1_syscall",
            "x::dispatch::dispatch_entry::h0",
            "x::dispatch::dispatch_syscall::h0",
            "x::dispatch::arm_signal_user_return::h0",
            "x::aarch64_process::with_process_entry::h0",
            "x::copy_signal_bytes::h0",
            "x::write_user_bytes::h0",
            "x::arm_signal::deliver_on_user_return::h0",
            "x::signal_delivery::deliver_signal_on_syscall_return::h0",
            "x::admit_entry_runtime::h0",
            "x::fork_owned::h0",
            "x::settle_mm::h0",
            "x::prepare_mm::h0",
            "x::fork_child_context_boxed::h0",
            "x::wait_query::h0",
            "x::setup_arm_signal_frame::h0",
            "x::restore_live_arm_signal_frame::h0",
            "x::serve_delegated_anonymous::h0",
            "x::serve_grant_hw::h0",
            "x::serve_backing_maintenance_hw::h0",
        ] {
            values.insert(name.to_owned(), 128);
        }
        let mut frames = Frames(values);
        assert!(frames.check(16384, 288).is_ok());
        frames.0.insert("x::settle_mm::h0".to_owned(), 12000);
        assert!(
            frames
                .check(16384, 288)
                .unwrap_err()
                .contains("native fork settlement")
        );
        frames.0.insert("x::settle_mm::h0".to_owned(), 128);
        for method in ["fork_owned", "prepare_mm", "publish_fork", "root_any"] {
            frames.0.insert(format!("x::{method}::h0"), 3000);
        }
        // Every individual frame is below 3 KiB; their retained sum fails.
        let error = frames.check(16384, 288).unwrap_err();
        assert!(error.contains("native fork publication"));
        assert!(!error.contains("individual frame"));
        frames
            .0
            .insert("new_fixture_personality::entry::h0".to_owned(), 16384);
        assert!(
            frames
                .check(16384, 288)
                .unwrap_err()
                .contains("individual frame")
        );
    }

    #[test]
    fn aligned_frames_include_padding_and_malformed_allocations_fail() {
        let frames = Frames::parse("1000 <aligned>:\n1000: stp x29, x30, [sp, #-0x60]!\n1004: sub x9, sp, #0x2, lsl #12\n1008: sub x9, x9, #0x20\n100c: and sp, x9, #0xffffffffffffffc0\n1010: ret\n").unwrap();
        assert_eq!(frames.maximum("aligned"), 96 + 8192 + 32 + 63);
        assert!(Frames::parse("1000 <bad>:\n1000: sub sp, sp, x8\n").is_err());
        assert!(frames.required("missing").is_err());
        assert!(Frames::parse("").is_err());
    }
}
