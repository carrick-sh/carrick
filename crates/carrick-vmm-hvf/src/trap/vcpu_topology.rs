//! Every vCPU lives for its VM's whole life (EL1 plan 1a, decision D2).
//!
//! Hypervisor.framework's in-kernel GIC treats a VM's topology as final once
//! its vCPUs run (`hv_gic.h`: "Once the virtual machine vcpus are running, its
//! topology is considered final. Destroy vcpus only when you are tearing down
//! the virtual machine."). libkrun (Apache-2.0) keeps one vCPU per thread for
//! the VM's life for the same reason.
//!
//! [`VcpuTopology`] is that rule as a state machine over one VM generation:
//! vCPUs are created while the generation assembles, the first `hv_vcpu_run`
//! seals it, and a vCPU is destroyed only once teardown has begun (or before
//! the first run, when a creation is rolled back). The carrier's instance is
//! consulted by the only `hv_vcpu_create` funnel (`vcpu_admission`), the only
//! `hv_vcpu_run` funnel (`HvfAarch64Vcpu::run`) and the only raw
//! `hv_vcpu_destroy` ([`destroy_raw_vcpu`]); a violation is a carrier fault.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use carrick_fatal::carrick_fatal;

/// Why a vCPU is being destroyed. Every site is a teardown-class destroy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VcpuDestroySite {
    /// A persistent executor leaving at pool shutdown (carrier teardown), or
    /// at a pool-start rollback before any vCPU ran.
    WorkerExit,
    /// The rollback of a VM creation that did not commit.
    CreationRollback,
    /// A vCPU whose own setup failed before it could run.
    CreationError,
    /// The mature lane's whole-VM execve rebuild.
    ExecveRebuild,
}

/// Where one VM generation is in its topology lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TopologyPhase {
    /// No VM.
    Vacant,
    /// A VM exists and no vCPU has run: vCPUs may be created or rolled back.
    Assembling,
    /// A vCPU has run: the topology is final.
    Running,
    /// Teardown began: vCPUs may be destroyed, none created or first run.
    TearingDown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VcpuTopologyViolation {
    CreateWithoutVm,
    CreateAfterFirstRun {
        generation: u64,
    },
    CreateDuringTeardown {
        generation: u64,
    },
    RunWithoutVm,
    FirstRunDuringTeardown {
        generation: u64,
    },
    DestroyWithoutVm {
        site: VcpuDestroySite,
    },
    DestroyBeforeTeardown {
        generation: u64,
        site: VcpuDestroySite,
    },
}

/// One VM generation's topology lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VcpuTopology {
    generation: u64,
    phase: TopologyPhase,
}

impl VcpuTopology {
    pub(crate) const VACANT: Self = Self {
        generation: 0,
        phase: TopologyPhase::Vacant,
    };

    #[cfg(test)]
    pub(crate) fn phase(&self) -> TopologyPhase {
        self.phase
    }

    /// A new VM exists (`hv_vm_create` succeeded).
    pub(crate) fn begin_generation(&mut self, generation: u64) {
        *self = Self {
            generation,
            phase: TopologyPhase::Assembling,
        };
    }

    /// The VM was destroyed.
    pub(crate) fn end_generation(&mut self) {
        *self = Self::VACANT;
    }

    pub(crate) fn admit_create(&self) -> Result<(), VcpuTopologyViolation> {
        let generation = self.generation;
        match self.phase {
            TopologyPhase::Assembling => Ok(()),
            TopologyPhase::Vacant => Err(VcpuTopologyViolation::CreateWithoutVm),
            TopologyPhase::Running => {
                Err(VcpuTopologyViolation::CreateAfterFirstRun { generation })
            }
            TopologyPhase::TearingDown => {
                Err(VcpuTopologyViolation::CreateDuringTeardown { generation })
            }
        }
    }

    /// A vCPU is about to run for the first time; the first one seals the
    /// generation's topology.
    pub(crate) fn admit_first_run(&mut self) -> Result<(), VcpuTopologyViolation> {
        let generation = self.generation;
        match self.phase {
            TopologyPhase::Assembling => {
                self.phase = TopologyPhase::Running;
                Ok(())
            }
            TopologyPhase::Running => Ok(()),
            TopologyPhase::Vacant => Err(VcpuTopologyViolation::RunWithoutVm),
            TopologyPhase::TearingDown => {
                Err(VcpuTopologyViolation::FirstRunDuringTeardown { generation })
            }
        }
    }

    /// The VM's vCPUs are about to be destroyed with it.
    pub(crate) fn begin_teardown(&mut self) {
        if self.phase != TopologyPhase::Vacant {
            self.phase = TopologyPhase::TearingDown;
        }
    }

    pub(crate) fn admit_destroy(&self, site: VcpuDestroySite) -> Result<(), VcpuTopologyViolation> {
        let generation = self.generation;
        match self.phase {
            TopologyPhase::Assembling | TopologyPhase::TearingDown => Ok(()),
            TopologyPhase::Vacant => Err(VcpuTopologyViolation::DestroyWithoutVm { site }),
            TopologyPhase::Running => {
                Err(VcpuTopologyViolation::DestroyBeforeTeardown { generation, site })
            }
        }
    }
}

/// The carrier VM's topology. Hypervisor.framework allows one VM per process,
/// so the carrier owns exactly one generation at a time.
fn carrier_vcpu_topology() -> &'static parking_lot::Mutex<VcpuTopology> {
    static TOPOLOGY: parking_lot::Mutex<VcpuTopology> =
        parking_lot::Mutex::new(VcpuTopology::VACANT);
    &TOPOLOGY
}

fn topology_fault(violation: VcpuTopologyViolation) -> ! {
    carrick_fatal!(
        "hvf::vcpu_lifetime",
        "vCPU topology violation (a vCPU lives for its VM's whole life): {violation:?}"
    )
}

pub(crate) fn begin_vcpu_topology_generation(generation: u64) {
    carrier_vcpu_topology().lock().begin_generation(generation);
}

pub(crate) fn end_vcpu_topology_generation() {
    carrier_vcpu_topology().lock().end_generation();
}

/// Carrier teardown begins: every vCPU is destroyed with the VM from here on.
pub fn begin_carrier_vcpu_teardown() {
    carrier_vcpu_topology().lock().begin_teardown();
}

/// Run `create` (one `hv_vcpu_create`) only while the generation assembles.
/// The topology lock is held across the create so a concurrent first run
/// cannot seal the generation underneath it.
pub(crate) fn create_admitted<T>(create: impl FnOnce() -> T) -> T {
    let topology = carrier_vcpu_topology().lock();
    if let Err(violation) = topology.admit_create() {
        topology_fault(violation);
    }
    create()
}

pub(crate) fn admit_vcpu_first_run() {
    if let Err(violation) = carrier_vcpu_topology().lock().admit_first_run() {
        topology_fault(violation);
    }
}

/// The only raw `hv_vcpu_destroy` in the crate. Owning thread only; the
/// caller forgets its handle so applevisor's `Drop` never runs on it. A
/// successful destroy is reported through `vcpu_destroyed`.
pub(crate) fn destroy_raw_vcpu(
    vcpu_id: applevisor_sys::hv_vcpu_t,
    site: VcpuDestroySite,
) -> applevisor_sys::hv_return_t {
    if let Err(violation) = carrier_vcpu_topology().lock().admit_destroy(site) {
        topology_fault(violation);
    }
    // SAFETY: the caller owns the vCPU on this thread and never uses or drops
    // its handle again.
    let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
    if rc == 0 {
        super::vcpu_destroyed(vcpu_id);
    }
    rc
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITES: [VcpuDestroySite; 4] = [
        VcpuDestroySite::WorkerExit,
        VcpuDestroySite::CreationRollback,
        VcpuDestroySite::CreationError,
        VcpuDestroySite::ExecveRebuild,
    ];

    #[test]
    fn a_generation_creates_before_its_first_run_and_destroys_at_teardown() {
        let mut topology = VcpuTopology::VACANT;
        topology.begin_generation(7);
        for _ in 0..18 {
            topology.admit_create().unwrap();
        }
        topology.admit_first_run().unwrap();
        topology.admit_first_run().unwrap();
        topology.begin_teardown();
        for site in SITES {
            topology.admit_destroy(site).unwrap();
        }
        topology.end_generation();
        assert_eq!(topology.phase(), TopologyPhase::Vacant);
    }

    #[test]
    fn a_create_after_the_first_run_is_a_violation() {
        let mut topology = VcpuTopology::VACANT;
        topology.begin_generation(3);
        topology.admit_first_run().unwrap();
        assert_eq!(
            topology.admit_create(),
            Err(VcpuTopologyViolation::CreateAfterFirstRun { generation: 3 })
        );
        topology.begin_teardown();
        assert_eq!(
            topology.admit_create(),
            Err(VcpuTopologyViolation::CreateDuringTeardown { generation: 3 })
        );
        assert_eq!(
            topology.admit_first_run(),
            Err(VcpuTopologyViolation::FirstRunDuringTeardown { generation: 3 })
        );
    }

    #[test]
    fn a_destroy_while_the_topology_runs_is_a_violation_at_every_site() {
        let mut topology = VcpuTopology::VACANT;
        topology.begin_generation(5);
        topology.admit_first_run().unwrap();
        for site in SITES {
            assert_eq!(
                topology.admit_destroy(site),
                Err(VcpuTopologyViolation::DestroyBeforeTeardown {
                    generation: 5,
                    site
                })
            );
        }
    }

    #[test]
    fn a_creation_rolled_back_before_any_run_may_destroy() {
        let mut topology = VcpuTopology::VACANT;
        topology.begin_generation(2);
        topology.admit_create().unwrap();
        topology
            .admit_destroy(VcpuDestroySite::CreationError)
            .unwrap();
        topology.admit_create().unwrap();
    }

    #[test]
    fn nothing_is_admitted_without_a_vm() {
        let mut topology = VcpuTopology::VACANT;
        assert_eq!(
            topology.admit_create(),
            Err(VcpuTopologyViolation::CreateWithoutVm)
        );
        assert_eq!(
            topology.admit_first_run(),
            Err(VcpuTopologyViolation::RunWithoutVm)
        );
        assert_eq!(
            topology.admit_destroy(VcpuDestroySite::WorkerExit),
            Err(VcpuTopologyViolation::DestroyWithoutVm {
                site: VcpuDestroySite::WorkerExit
            })
        );
    }

    /// The vCPU lifecycle Carrick ran before EL1 plan 1a D2, replayed against
    /// the rule: a first root staged its registers in a boot vCPU that ran the
    /// bring-up maintenance trampoline, the executor pool was created after
    /// that run, and a second root in the reused carrier created and destroyed
    /// its own boot vCPU while executor vCPUs ran. Each step now faults.
    #[test]
    fn the_retired_initial_runner_hand_off_violates_the_topology() {
        let mut topology = VcpuTopology::VACANT;
        topology.begin_generation(1);
        topology.admit_create().unwrap(); // first root's boot vCPU
        topology.admit_first_run().unwrap(); // its bring-up TLB maintenance
        assert!(
            topology.admit_create().is_err(),
            "executor pool created after a run"
        );
        assert!(
            topology.admit_destroy(VcpuDestroySite::WorkerExit).is_err(),
            "boot vCPU destroyed mid-life"
        );
        assert!(topology.admit_create().is_err(), "second root's boot vCPU");
    }
}
