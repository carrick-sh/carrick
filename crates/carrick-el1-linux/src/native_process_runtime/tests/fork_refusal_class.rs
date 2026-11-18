//! #2441: a native fork refusal that breaks a kernel invariant ends the run
//! at the production fork entry, on both ISA contexts; it never reaches the
//! guest as an errno, and the fork never reruns on it.
use super::*;

fn arm_words(address: AddressContext<RootGpa>) -> carrick_sched_core::Aarch64ParkedContext {
    carrick_sched_core::Aarch64ParkedContext::from_parts(carrick_el1_abi::ThreadCtx::ZERO, address)
}

/// The fork's preparation meets `refusal`, a broken invariant: the entry
/// must end the run on it. Formerly a census `ForkError::Core` answered
/// EFAULT, and a prepare or publish `MmError::Stale` reran the fork.
fn fork_invariant_refusal_ends_the_run<
    C: ProcessContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
    make_words: fn(AddressContext<RootGpa>) -> C,
    refusal: NativeProcessError,
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
    assert_eq!(prepare_mm_calls(), 0);
    fail_prepare_mm(&[refusal]);
    let outcome = entry.fork(ProcessForkChildTid::NONE);
    panic!(
        "a broken invariant reached the guest: {} after {} preparations",
        outcome_kind(&outcome),
        prepare_mm_calls()
    );
}

/// The invariant refusal each fatal case injects.
fn invariant_case(case: &str) -> NativeProcessError {
    use crate::native_fork_refusal::{NativeForkStage, refused};
    use carrick_core::mm::transaction::MmError;
    match case {
        "census-core" => refused(
            NativeForkStage::Census,
            carrick_core::mm::fork::ForkError::Core,
        ),
        // A Stale prepare or publish is a broken invariant: a parent
        // snapshot another thread moved is `MmError::Busy` at its source.
        "prepare-stale" => refused(NativeForkStage::Prepare, MmError::Stale),
        "publish-stale" => refused(NativeForkStage::Publish, MmError::Stale),
        _ => unreachable!("{case}"),
    }
}

#[cfg(test)]
mod serial_host {
    use super::*;

    /// Run `test`'s body once per case, each in a child test process whose
    /// fatal sink exits 86 when the fork ran exactly one preparation (no
    /// rerun) and 87 otherwise; bounded so that a regression fails instead
    /// of hanging.
    fn fatal_child(test: &str, cases: &[&str], run: impl Fn(&str)) {
        use wait_timeout::ChildExt;
        const CHILD: &str = "CARRICK_NATIVE_FORK_FATAL_CHILD";
        const CASE: &str = "CARRICK_NATIVE_FORK_FATAL_CASE";
        if std::env::var(CHILD).ok().as_deref() == Some(test) {
            carrick_fatal::set_hook(|domain, _| {
                assert_eq!(domain, "el1::entry_completion");
                std::process::exit(if prepare_mm_calls() == 1 { 86 } else { 87 });
            });
            run(&std::env::var(CASE).unwrap());
            return;
        }
        for case in cases {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env(CHILD, test)
                .env(CASE, case)
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
            assert!(!timed_out, "fork fatal child {case} exceeded 10 seconds");
            assert_ne!(
                output.status.code(),
                Some(87),
                "{case}: the fork reran before the broken invariant ended the run"
            );
            assert_eq!(
                output.status.code(),
                Some(86),
                "{case}: the broken invariant must end the run: {}",
                std::string::String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    const MODULE: &str =
        "native_process_runtime::host_test_support::fork_refusal_class::serial_host::";

    #[test]
    fn fork_invariant_refusal_ends_the_run_x86() {
        fatal_child(
            &std::format!("{MODULE}fork_invariant_refusal_ends_the_run_x86"),
            &["census-core"],
            |case| {
                fork_invariant_refusal_ends_the_run::<
                    ParkedContextWords,
                    carrick_mmu_core::x86::owner_mmu::X86Mmu,
                >(words, invariant_case(case))
            },
        );
    }

    #[test]
    fn fork_invariant_refusal_ends_the_run_aarch64() {
        fatal_child(
            &std::format!("{MODULE}fork_invariant_refusal_ends_the_run_aarch64"),
            &["census-core"],
            |case| {
                fork_invariant_refusal_ends_the_run::<
                    carrick_sched_core::Aarch64ParkedContext,
                    carrick_mmu_core::owner_mmu::Aarch64Mmu,
                >(arm_words, invariant_case(case))
            },
        );
    }

    /// The director's ruling on #2508: `MmError::Stale` at the fork's
    /// prepare and publish stages stays a broken invariant. It ends the
    /// run through the entry-completion fatal after exactly one
    /// preparation: zero reruns.
    #[test]
    fn fork_stale_prepare_or_publish_ends_the_run_without_rerun_x86() {
        fatal_child(
            &std::format!("{MODULE}fork_stale_prepare_or_publish_ends_the_run_without_rerun_x86"),
            &["prepare-stale", "publish-stale"],
            |case| {
                fork_invariant_refusal_ends_the_run::<
                    ParkedContextWords,
                    carrick_mmu_core::x86::owner_mmu::X86Mmu,
                >(words, invariant_case(case))
            },
        );
    }

    #[test]
    fn fork_stale_prepare_or_publish_ends_the_run_without_rerun_aarch64() {
        fatal_child(
            &std::format!(
                "{MODULE}fork_stale_prepare_or_publish_ends_the_run_without_rerun_aarch64"
            ),
            &["prepare-stale", "publish-stale"],
            |case| {
                fork_invariant_refusal_ends_the_run::<
                    carrick_sched_core::Aarch64ParkedContext,
                    carrick_mmu_core::owner_mmu::Aarch64Mmu,
                >(arm_words, invariant_case(case))
            },
        );
    }
}
