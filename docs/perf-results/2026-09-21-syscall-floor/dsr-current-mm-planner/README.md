# Current-MM reader connected to the DSR planner

The isolated research workspace now has current_mm::plan_current_mm. It fetches
one bounded remainder of a 4-KiB instruction page through the real kernel API,
passes only that copied window into the recovered block planner, and retains
the InstructionRead and its execution-lease borrow with a private BlockPlan.
There is no emitter entry point or cache publication method on UnpublishedPlan.
CodeGeneration::INITIAL is a decoder annotation only, not a live cache key.
The decoder-only draft is deliberately not evidence of executable authority.

cargo check passes; the focused integration test passes. The test uses the real
kernel task graph and execution lease with a mock byte transport, decodes mov
x0,#7 followed by svc #0, verifies the exit/resume PCs, rejects another task's
lease, and detects a changed mapping revision. It does not execute guest code.
The prior carrier tests separately cover real transport with fixture backing;
this test does not compose those layers. The old mapped_memory ignored-result
warning remains; that memory implementation is not used by this adapter.

## Publication audit

The donor NativeMappedMemory::note_dsr_code_mutation updates its generation table
and severs direct links. Donor translator direct links can skip entry generation
guards. Current kernel/backend writes do not invoke that donor lifecycle, so
simply using current mapping revisions as CodeGeneration would permit stale code
through in-place writes or surviving direct links. Do not restore the old cache
as a shortcut. Keep draft planning separate from execution until publication and
revocation cover guest stores, kernel copies into guest memory, foreign writes,
permission changes, unmap/replacement and exec, including shared executable aliases.

The existing production carrier composition seam is
carrick-runtime/src/vcpu_loop/memory.rs::real_production_cow_fixture,
using carrick-vmm-hvf::trap::foreign_cow_test_support. Reuse that exact kernel
mapping/frame fixture to compose the reader with real transport, rather than
creating an independent authority model.

No product workspace member was restored, no CLI was rebuilt, and no performance
gain or native execution acceptance is claimed. The next executable adapter still
requires publication/revocation, memory lowering, TLS/register and signal handling.
