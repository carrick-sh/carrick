# S3-T3 sol3 current checkpoint (NOT accepted)

Branch work/s3-t3b, HEAD c0538ccbf. Strict fork VA->IPA check unchanged.

Commits: 39480a8f7 production projection builder red witness on bd1f11c53;
dcdfb6fda private-overlay aperture retention; d8ac6db91/f65d15c08 reviewed
inventory reconciliations; 91a8a938c mmap unknown-bit host route;
cf3205b49 typed exact-bit refinement; 43073e330 correct broad typed route per
director, mixed protection red cf3205 green and EL1 lib193pass;
c0538ccbf failure-only descriptor grant preparation refusal phase23.

Build current c0538ccbf foreground session37901 is in flight, log
/tmp/s3t3-sol3-grant-diagnostic-build.log. Wait before guest runs or edits.

Previous CLI signed artifact cf3205b49 just build green9m51s, identity
/tmp/s3t3-sol3-final-cli-identity.log. Its current-file-refusal trace reproduces
mmapprivatefiletrack pathname openat EFAULT, no phase21/22 backing refusal;
/tmp/s3t3-sol3-current-file-refusal.{log,out}, scoped cleanup receipt .log.
Next: trace current diagnostic artifact with host-copyout-efault-origin.d;
phase23 names Prepare refusal (already replaces Retired, rejects Prepared).
Hypothesis only: grant span mixing old prepared neighbors may refuse whole,
then fallback first-touch repairs only faulting page. Do not weaken checks.

Final generic cf3205 log /tmp/s3t3-sol3-final-generic.log exited1:
shard1 deadline epollstopcont60s before mapfixed/memflagmatrix cases;
shard2 musl4DIFF exitgroupthreads forkexecstorm killrt splicepipeempty;
shard0 musl9DIFF coredumpbit forkfault futexforkwakegroups mmapcluster
mmapv8align msyncalign nxwritableimage rlimitasdata roprotect.
No GNU reached for failed shards. Cleanup zero. Sibling Rust builds active;
do not classify deadline without quiet-host attribution.
Earlier focused signed mapfixed/memflagmatrix/abortdeath both-libc green at
91a8a938c (/tmp/s3t3-sol3-prot-probes.log); exact main signed attribution twice
GREEN for mapfixed memflagmatrix mmapprivatefiletrack exitgroupthreads
forkexecstorm (/tmp/s3t3-sol3-mainattr*.log).

Acceptance earlier39480 EL1 suite only4 allowed failures, dedicatedcase33
pass. Host dcdf/f65 just test-kernel, hvf697pass3ignored, clippy, reviewed
reconcile+cleanlint pass. just test RED two scm_rights tests parallel; serial
isolation3x HEAD and base6550c4f49 allpass is NOT closure. Full gates must
rerun current/final. No review-ready, no tests_passing true.

Temporary attribution worktree .worktrees/main-attr at exactmain839f92126,
clean tracked, reflink target and probes ignored. Remove when no longerneeded.
Never Docker: director owns full just --no-deps conformance-probes and any
mixed-protection Docker qualification. Worker cached signed2batches only.
No quiet-window request received yet; mailbox check naturalbreakpoints.

## New diagnostic checkpoint cd7d4b335

c0538ccbf signed build passed7m25s; identity
/tmp/s3t3-sol3-diagnostic-cli-identity.log. Descriptor-refusal reduction
still EFAULT, no phase23 event: do NOT call this qualified absence.
/tmp/s3t3-sol3-descriptor-refusal.{out,log}, cleanup zero.
Director requested every candidate site in ONE next build.
cd7d4b335 adds lazy el1-mapping-leaf USDT phase0 prep,1submitted,2hostpub,
3appliedreceipt-beforebackend,4aftersettlement,5beforeunmap,6afterunmap.
Fields phase,exactMMkey,VA,spanlen,livePTE; focused page+neighbor sampled.
Existingwritefault phase24 names refused/rolledbackreceipt. Combined
host-copyout-efault-origin.d now includes readfaults and lifecycle, bound60s,
exit/error/drop summary. No descriptorbehavior changes. cargo checkruntime
GREEN /tmp/s3t3-sol3-batched-diagnostic-check-fixed.log; earlier checkfailed
Result inference then annotation initially matchedwrongOk, correctedbefore
commit. Build currently FOREGROUND session20715 log
/tmp/s3t3-sol3-batched-diagnostic-build.log: wait, then identity + one trace
with runid s3t3-sol3-batched-grant; scopedkill aftercompletion.

## Latest stop: cd7d4b335, NOT review-ready

Combined diagnostic build passed (/tmp/s3t3-sol3-batched-diagnostic-build.log).
Combined trace /tmp/s3t3-sol3-batched-grant.out proves BOTH retired pages
6000004000/6000005000 were replaced by grant 2 and remained replaced after
backend settlement. openat still EFAULT; no pathname-page raw-read fault.
The later retired page sample was cleanup AFTER EFAULT: earlier retired-leaf
diagnosis is withdrawn. Trace had 44 mapping events, target exit 1, errors=0,
drops=0; scoped cleanup zero. Identity receipt batched-cli-identity.log.

Director says MemoryProtections mirror is forbidden as a second admitted-MM
permission owner. Do NOT synchronize it from EL1. Host buffers on admitted
roots must authenticate live stage-1 + exact MM owner generation. Keep
mirror only where host is editor; add deletion to step-2 plan inventory.
This is a hypothesis, not yet a demonstrated cause. No mirror fix landed.

Dirty draft tests: el1_host_copyout.rs and fixtures/embed-copyout/src/main.rs,
new reuse command/two-live-process fixture. Three pre-fix variants ALL GREEN:
MAP_FIXED /tmp/s3t3-sol3-reuse-red.log, ordinary ANY4P reuse-any-red.log,
stock-adoption sequence reuse-stock-red.log. Current third variant signed
script exited 0, negative control passed, explicit scoped kill cleanup zero.
These are NOT red witnesses. Do not claim regression coverage from them.
No active guest/test session remains. Next: reproduce exact failing probe
allocation sequence or instrument outer protection gate; do not change live
permission enforcement on an unproved diagnosis.

Current full probe acceptance remains RED (logs final-generic.log); host
just test had two parallel SCM_RIGHTS failures despite serial greens. All
required final gates need rerun on final fix. No review-ready posted.

## Narrow turn complete: clean 1cf7568e1

WIP tests committed a2f1ccdca; intervention 690383cc8 rejected internal
EL1 identity bootstrap and reverted 1cf7568e1. No cause proved. Restored
just build passed; full generic ONCE 13 musl DIFF + epollstopcont deadline,
GNU not reached; case ONCE 33/33 green. Scoped cleanups zero. Exact groups
and receipts: /tmp/s3t3-narrow-report.md. No active guest/test sessions.
No further fixes; director decides land-versus-subsume in N1.
