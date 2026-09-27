# Review round 2 — dc2b83706 is not accepted

Same el1-elastic-metadata task/conversation; review round2 of maximum3.
The original eight prescribed commands independently pass. The original
alignment64 and overhead-inclusive grant sizing screens now pass. Preserve
those fixes. Review evidence is /tmp/el1-allocator-review2 (source identities,
raw logs, exact standalone screens). The real guest path remains incomplete.
Read AGENTS.md and the original brief. No guest/Docker/main/push; director owns
signed execution. No budget relaxation or narrower host-only substitute.

Required corrections, in execution order:

1. Build the actual standalone Linux fixture. `RUSTC_WRAPPER= cargo build
--manifest-path fixtures/embed-el1-sched/Cargo.toml --target
aarch64-unknown-linux-musl --release` exits101: carrick_el1_abi is referenced
but absent from that standalone manifest. Host embed --no-run never compiles
this fixture. The fixture Cargo.toml/Cargo.lock are necessary scope additions;
change only the dependency/lock needed, not unrelated fixture dependencies.
Add this exact build to your original verification list.

2. Initialize and map the production allocator before use. Repository-wide
search finds init_bootstrap_allocator only at its declaration. #[global_allocator]
with no bootstrap admission is not initialization. Dynamic stage1 mappings were
added only to stage1_carrier_maintenance_page_tables; prove actual process roots
on which EL1 handles the control request, fork/exec roots and idle roots can
access the kernel-only metadata range. The existing kernel-only classifier
is not itself a mapping. Prove EL0 cannot access it. Reuse existing authority
and carrier lifetime rather than create an unrelated address identity.

3. Preserve the complete grant receipt and register ABI. Host returns token in
x3; guest request asm doesn't declare x3 as output/clobber, drops it, and invents
token=granted_base. Return asm doesn't supply token in x3; host accepts token0
as a wildcard. This both breaks ownership authentication and risks compiler
register corruption. Carry exact host token/current owner generation through
admission and return, reject zero/stale/mismatched tokens, and declare every
modified asm register. No invented or wildcard authentication. GLOBAL_GENERATION
is stored but never validated; token/generation resets currently permit ABA.

4. Reserve full extent spans atomically, with rollback. Production host policy
uses a512KiB slot but maps requested size rounded to64KiB. Independent unchanged
HostApertureState screen requests1114112bytes atslot0, then proposes slot1 at
offset524288: overlapping extents. Reserve all covered space, not just first
bit. Allocation selection and occupancy publication are also separate critical
sections, so concurrent grants choose the same slot. Prove two simultaneous
requests and >quantum requests cannot overlap. A failed map must release the
reservation; publication failure must not leak successful mappings. Use carrier-
owned state and existing exact VM/owner lifecycle. The static counter/table is
still not coupled to VM destroy, and reset still ignores unmap failure then
frees backing. Failed return is ignored by guest after discarding its descriptor;
retain recoverable ownership until return succeeds, without unbounded retries.

5. Fix actual denial/recovery/concurrency witness. The embed test arms deny-next
before any fixture work, so the FIRST growth request is denied, not subcommand3.
The 10MiB growth loop treats that as immediate rc201; it never reaches recovery.
Arrange explicit scoped phases. Prove production grant denial preserves live
allocations, then clears for a successful request and exact return. Exercise
concurrent guest users and pending host work, with counters owned by that carrier.
Keep the real9MiB bootstrap; don't shrink it to fit a superficial test. Ensure
control entry is explicitly test-gated and Linux-visible unsupported calls retain
normal behavior. Demonstrate actual installed allocator use, not only a direct
helper bypass. Restore prior IRQ state, but do not mistake restoring masked DAIF
for enabling IRQs before a host wait; prove the permitted calling contexts.

6. Make structural evidence truthful. Current budget host_mapping_allocations=0
claims preallocated stage2 capacity, while handler allocates backing on each grant.
It does not encode search/split/merge/admission/reclamation bounds. Bind the real
work units and derived bounds, including fragmentation and repeated returned-slot
reuse. Rejecting a request merely because the first free-list head is undersized
is not sufficient proof of bounded allocation with usable capacity. Keep exact
raw red/green source identities. Do not claim all review areas resolved unless
production paths and their acceptance witnesses exist.

Re-run the original eight commands plus fixture cross-build. Report remaining
work honestly in the existing output contract. Do not run signed guests. This
round addresses the same guest allocator deliverable, not a new foundation task.
