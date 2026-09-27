# Private allocator control build gate

Pre-change source 8fc9c913a. The real shared EL1 syscall dispatcher served
SYS_CARRICK_EL1_CONTROL in ordinary builds. The production-control witness
reproduces this as Served versus required Forward (red.log, exit 101). An
initial witness through the host-only wrapper was non-diagnostic because that
wrapper always forwards; the recorded red uses dispatch_syscall_with_regions.

The private dispatch arm and allocator test routines now compile only with
allocator-test-control. The embedded image forwards that explicit feature to
the bare-metal nested build. Only carrick-embed's dev dependency enables it;
ordinary CLI/image defaults leave it disabled. The large private syscall
continues down normal unsupported syscall handling in production.

All 57 EL1 unit tests pass in each of default and enabled configurations,
including the actual dispatcher behavior. Both embedded-image builds and
header tests pass; embed test compile-check and scoped all-feature Clippy pass.
Signed verification of this build separation is next. The prior concurrent
signed green belongs to 8fc9c913a and is recorded separately. IRQ protocol and
remaining structural/retention requirements remain open.
