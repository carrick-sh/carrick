#!/usr/sbin/dtrace -Zs
/*
 * hvpatch-global-frame-stage2-inventory.d
 *
 * WHAT IT MEASURES
 *   Every physical stage-2 edge of the HVPatch global-frame IPA arena, plus
 *   every dynamic alias-map attempt and its raw `hv_return_t`. Written to
 *   answer "why did `hv_vm_map alias ... failed: 0xfae94001` (HV_ERROR)
 *   happen, and is the IPA or the host backing at fault?"
 *
 *   carrick*:::hvpatch-global-frame-stage2  arg0 phase (0=Mapped, 1=Unmapped),
 *                                           arg1 IPA, arg2 length,
 *                                           arg3 host VA, arg4 permissions
 *                                           (host VA / perms are 0 on unmap;
 *                                            emitted ONLY on rc == 0)
 *   carrick*:::hv-vm-map-alias               arg0 guest VA, arg1 IPA, arg2 size,
 *                                           arg3 hv_return_t, arg4 forked_no_exec
 *
 * WHAT IT ESTABLISHED (2026-08-15, macOS 27.0 / Apple Silicon, HVPatch/HVF)
 *   HV_ERROR from `hv_vm_map` on an alias is NOT an IPA-reuse leak. Measured
 *   at the exact failing call with lldb (reproduced twice):
 *     - anonymous RW host memory at the SAME "failing" IPA          -> rc = 0
 *     - the REAL host mapping at a FRESH never-used IPA             -> HV_ERROR
 *   The host mapping is the fault: a `MAP_SHARED` mapping of an **O_RDONLY**
 *   host fd has `max_protection == VM_PROT_READ` on Darwin (verified:
 *   `mprotect(range, len, PROT_READ|PROT_WRITE)` returns EACCES), and HVF
 *   refuses to stage-2 map such a region — with perms=RWX *and* with
 *   perms=READ alike. An O_RDWR fd mapped `PROT_READ` maps fine, so the
 *   requested stage-2 permission bits are not the discriminator; the fd's
 *   access mode is. Beware the post-mortem artifact: probing the same IPA
 *   *after* the failure can show it occupied, because the failed lease
 *   already returned it to the free list and a sibling thread re-took it.
 *   Likewise, a repeated HV_ERROR on ONE IPA is a symptom of that
 *   release-and-retake loop, not evidence of a leaked stage-2 extent.
 *
 * PROVIDER ABI FACTS qualified live on this host
 *   - Provider is per-PID (`carrick<pid>:::`), so the `carrick*:::` glob is
 *     REQUIRED; a bare `carrick:::` matches nothing.
 *   - `-Z` is REQUIRED: the carrier that owns the VM is a CHILD of the
 *     `carrick run` you launch and does not exist when dtrace starts.
 *   - `execname` scoping is useless (parent, carrier and other agents' runs
 *     all share the name). Key on the probe and post-filter by `pid` — on a
 *     shared box this WILL pick up other people's carrick processes.
 *   - The stage-2 probe fires only on rc == 0, so it is an inventory of
 *     SUCCESSFUL edges. Failures appear only via `hv-vm-map-alias` arg3.
 *   - Zero rows means the capture failed, never "no stage-2 edges happened".
 *
 * PERTURBATION
 *   Low but not zero: a few hundred to a few thousand events per short run
 *   (per stage-2 edge, not per syscall). Safe for a correctness repro; do not
 *   quote wall-clock ratios taken under it.
 *
 * USAGE
 *   sudo dtrace -Zs scripts/dtrace/hvpatch-global-frame-stage2-inventory.d
 *   ...then run the guest AS YOUR OWN USER in another shell. Do NOT let
 *   `carrick trace` sudo the guest for you: a test that drops privileges
 *   (LTP `nftw01` runs as `nobody`) is a different experiment under root.
 *
 * FOLLOW-UP
 *   This belongs in `carrick trace` as a `TraceProfileKind` (AGENTS.md: a
 *   `.d` should arrive as a Rust-owned profile with a hashed program and a
 *   parser), together with the host-side `mmap`/`hv_vm_map` correlation that
 *   supplied the host prot/flags and the dup->open chain during this
 *   investigation.
 */

#pragma D option quiet
#pragma D option bufsize=128m
#pragma D option dynvarsize=64m
#pragma D option switchrate=10hz

carrick*:::hvpatch-global-frame-stage2
{
	printf("%d %s ipa=0x%llx len=0x%llx host=0x%llx perms=%d\n",
	    pid, arg0 == 0 ? "MAP  " : "UNMAP",
	    (unsigned long long)arg1, (unsigned long long)arg2,
	    (unsigned long long)arg3, (int)arg4);
}

carrick*:::hv-vm-map-alias
{
	printf("%d ALIAS va=0x%llx ipa=0x%llx size=0x%llx rc=0x%x forked=%d\n",
	    pid, (unsigned long long)arg0, (unsigned long long)arg1,
	    (unsigned long long)arg2, (int)arg3, (int)arg4);
}
