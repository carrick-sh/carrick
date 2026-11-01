//! Required KVM differential for the same two-vCPU CPL0 wake/IPI fixture.
#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/apic_fixture.rs"]
mod apic_fixture;
#[path = "support/apic_kvm.rs"]
mod apic_kvm;
#[test]
fn two_vcpu_wake_and_ipi_matches_kvm() {
    // KVM_RUN may block in the kernel. Bound the entire isolated child, including
    // its vCPU joins, so a lost IPI fails rather than stranding the host suite.
    const CHILD: &str = "CARRICK_APIC_PARITY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new("timeout")
            .args(["--signal=KILL", "10s"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "two_vcpu_wake_and_ipi_matches_kvm",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "bounded APIC parity child failed: {status}"
        );
        return;
    }
    let soft = apic_fixture::run_two_vcpu_fixture_on_softmachine();
    assert_eq!(soft, apic_fixture::expected_outcome());
    assert_eq!(soft, apic_kvm::run_two_vcpu_fixture_on_kvm());
}
