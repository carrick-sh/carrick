//! #2441: a native fork refusal that breaks a kernel invariant ends the run
//! at the production fork entry, on both ISA contexts; it never reaches the
//! guest as an errno.
use super::*;

fn arm_words(address: AddressContext<RootGpa>) -> carrick_sched_core::Aarch64ParkedContext {
    carrick_sched_core::Aarch64ParkedContext::from_parts(carrick_el1_abi::ThreadCtx::ZERO, address)
}

/// The fork's census meets an owner that contradicts its own state
/// (`ForkError::Core`). Formerly the clone answered EFAULT.
fn fork_invariant_refusal_ends_the_run<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
) {
    let fixture = native_exec_fixture_for::<C, B>(make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    let mut service = fixture.service();
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &make_words(fixture.address),
            &mut service,
        )
        .unwrap();
    fail_prepare_mm(&[crate::native_fork_refusal::refused(
        crate::native_fork_refusal::NativeForkStage::Census,
        carrick_core::mm::fork::ForkError::Core,
    )]);
    let outcome = entry.fork(ProcessForkChildTid::NONE);
    panic!(
        "a broken invariant reached the guest: {}",
        outcome_kind(&outcome)
    );
}

#[cfg(test)]
mod serial_host {
    use super::*;

    /// Run `test`'s body in a child test process whose fatal sink exits
    /// 86, bounded so that a regression fails instead of hanging.
    fn fatal_child(test: &str, run: impl FnOnce()) {
        use wait_timeout::ChildExt;
        const CHILD: &str = "CARRICK_NATIVE_FORK_FATAL_CHILD";
        if std::env::var(CHILD).ok().as_deref() == Some(test) {
            carrick_fatal::set_hook(|domain, _| {
                assert_eq!(domain, "el1::entry_completion");
                std::process::exit(86);
            });
            run();
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, test)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let timed_out = child
            .wait_timeout(std::time::Duration::from_secs(10))
            .unwrap()
            .is_none();
        if timed_out {
            child.kill().unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(!timed_out, "fork fatal child exceeded 10 seconds");
        assert_eq!(
            output.status.code(),
            Some(86),
            "the broken invariant must end the run: {}",
            std::string::String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn fork_invariant_refusal_ends_the_run_x86() {
        fatal_child(
            "native_process_runtime::host_test_support::fork_refusal_class::serial_host::fork_invariant_refusal_ends_the_run_x86",
            || {
                fork_invariant_refusal_ends_the_run::<
                    ParkedContextWords,
                    carrick_mmu_core::x86::owner_mmu::X86Mmu,
                >(words)
            },
        );
    }

    #[test]
    fn fork_invariant_refusal_ends_the_run_aarch64() {
        fatal_child(
            "native_process_runtime::host_test_support::fork_refusal_class::serial_host::fork_invariant_refusal_ends_the_run_aarch64",
            || {
                fork_invariant_refusal_ends_the_run::<
                    carrick_sched_core::Aarch64ParkedContext,
                    carrick_mmu_core::owner_mmu::Aarch64Mmu,
                >(arm_words)
            },
        );
    }
}
