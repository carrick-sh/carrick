# follow-up (seam): x86 CPL0 idle peer serves a host-custody raw exit against the idle peer's task

Refs #2109, PR #2182.

On x86, `production_boundary(Action::HostCustody)` maps to
`ProductionBoundary::HostCustody`, and the CPL0 idle lane
(`crates/carrick-runtime/src/vcpu_loop/executor/cpl0.rs`, `settle_lane`,
`CarrierRunExit::SyscallTrap`) services every syscall trap against
`physical.idle_peer_task()`. If a ring-born member's raw exit declines into host
custody while it runs on the idle peer, the trap is served for the wrong task, or for
none. #2182 removes the robust-list decline for both ISAs (it lives in shared
`serve_exit`), so glibc thread exits no longer take this path on x86. The remaining
declines in follow-up 1 still could. Seam #925 already covers exposing the peer's zone
slot to the host.
