# x86 CPL0 host coordinator

This crate owns the stopped-task CPU state machine, carrier memory custody,
bootstrap-to-worker transfer and physical service venues. Backends supply
required hardware operations through `CarrierCpuBackend`; `OwnedCpuIo` consumes
that implementation before it enters sealed `CarrierCpuIo` custody. No accessor
returns the backend or its vCPU handle. `BootstrapCustody` is consumed when the
stopped carrier becomes `ProductionWorkerParts`; worker custody and its fields
remain crate-private.

The crate has no direct `carrick-personality-linux` dependency. Linux wait-status
validation and process outcome conversion stay in the KVM adapter. The one
`carrick-el1-linux` edge is the existing physical-custody fail-stop
(`dispatch::invalid_completion`), named at its owner since the EL1 Linux client
moved out of `carrick-el1`. Work-boundary
consumption uses the existing `CurrentTask` ABI rather than importing a Linux
state type. That ABI and the retained reservation implementation still carry
transitive Linux coupling tracked by #366/#237; this extraction does not resolve
those shared-layer dependencies or introduce another direct dependency.

CPU/coordinator modules compile only for x86_64. The guest-RAM module also serves
the Linux aarch64 KVM lane. Memory scenarios are shared through an explicit
`test-support` feature: VM-free tests use a test-only slot map, while
`carrick-vmm-kvm` registers all 16 scenarios in its KVM lane with actual KVM
memory ioctls. The fake does not replace those hardware witnesses.

Fixtures retain KVM's five-second guest-interval watchdog through the backend's
required `Watchdog` associated type. Timeout errors preserve the pre-extraction
messages. Host service intervals do not consume the guest watchdog budget.
