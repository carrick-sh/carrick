# x86 order 5 entry mapping

Order 5 moves entry ownership; orders 6–9 retain their family bodies behind
`PendingFamilies`. There is one Linux routing/return-work owner in
`carrick-personality-linux::dispatch`. EL1 implements named family hooks;
its native wrapper translates the selected route to `Action`. The common
robust-list entry uses that same dispatcher, not another ordinal switch.

## Result and refusal preservation

All signed family results cross as the identical `i64`; native return registers
retain their two's-complement bits. No errno is translated by core.

| Pre-move condition / result | Order 5 boundary / exact result |
| --- | --- |
| Robust-list native x86 273 / ARM 99, length 24: served `0` | Linux codec → Linux robust-list policy over real EL1 metadata venue → sole Linux finish; served `0`, one publication |
| Admitted robust-list length other than 24: served `-22` (`EINVAL`) | Same body returns `-22`; no head publication or sibling mutation |
| Missing task or cleared ordinary execution generation: Forward | Core ordinary admission refuses; Forward before family effects |
| Closed lifecycle gate, setup hatch off, absent exact lifecycle slot: Forward | Pending family refuses; Forward, unchanged head and arguments |
| Unported native x86 ordinal, including numeric ARM alias 99: Forward | Linux x86 codec maps only 273; every other value stays unported, no family effect |
| Unported ARM ordinal: Forward | Sole Linux family table explicitly returns Unported; unchanged arguments |
| Ordinary completion with changed task, host generation, MM or thread serial | Core returns `WrongGeneration`; no second completion or result publication; native fail-stop transport prevents replay of effects |
| Born record with host generation zero, exact owned OnCpu claim | Distinct lifetime-bound `BornEntryCompletion`; see finding below; original Linux result retained |
| Born admission with wrong MM, serial, record owner, installed MM or adopted generation | Refused before effects; no ordinary generation-zero token is issued |
| Born completion after owner/record/claim-seq/incarnation change | `WrongGeneration`, not a Linux errno or Forward-after-effects |
| Host request arrives after Born admission: same-owner OnCpuRequested | Completion accepts only unchanged claim seq/incarnation and exact binding; request remains pending until subsequent native handback |
| Plain served result with pending return work | ServedWithWork, Linux `SERVED_WAKES_OWED = 1`; completed syscall cannot be redispatched |
| Metadata commit owed, original argument 0 needed | ServedWithWork, Linux `SERVED_COMMIT_OWED = 2`; same preserved argument; a later wake cannot downgrade 2 to 1 |
| Pending work at entry, no retained operation/setup exception | Forward before fresh family or descriptor lookup; same decline accounting |
| Pending work plus retained IPC operation | Original operation offered before fresh fd lookup; progress and endpoint custody retained |
| IPC explicit decline | File fallback only after Forward; Handback cannot fall through or replay the operation |
| Family parks or native scheduler switches the running record | Exact initiating binding/record authenticated against an owned receipt from successful scheduler/wait publication or retirement; token consumed once, existing continuation retained |
| IPC/lifecycle/futex returned value, signed failure or positive byte/count/TID result | Named pending hook returns identical `i64`; native argument preservation and register install unchanged |
| IPC idle / handback | Idle / Forward respectively; retained operation authority unchanged |
| Anonymous Forward / Return(value) / Work / Unavailable(reason) | Exact variants retained by shared Linux helper; counters publish only for Forward/Return; owned work/refusal unchanged |
| Delegated anonymous completion/decline; prepared wait | Resource primitive publishes no entry counter; Linux publishes exactly one served/forwarded count. Prepared park retains its historical uncounted suspension; result and work flags are unchanged |
| Delegated read/write/lseek/pread/pwrite and inotify refusal | Forward unchanged; per-family locking, notifications, fd pinning and all signed results unchanged |
| Unsupported/misaligned futex op, zero MM, invalid user word or disallowed timed wait | Forward (`None`), unchanged frame; no wait submission |
| Futex value mismatch | Exact `-11` (`EAGAIN`), selected in Linux scheduler policy |
| Futex timed wait expires | Exact `-110` (`ETIMEDOUT`), selected in Linux scheduler policy; native IRQ/clock/idle mechanics retain it as opaque return bits |
| Invalid relative timespec (negative seconds/nanos or nanos ≥ 1e9) | Forward unchanged; no deadline or wait submission |
| Valid relative futex deadline | Same saturating seconds × frequency + nanos ticks, minimum one tick; absolute native clock deadline retained |
| Allocator control disabled | Forward, same unported diagnostic ordinal |
| Allocator test control enabled without a loaded task | Existing diagnostic result retained through private AllocatorDiagnostic authority; no fabricated task/MM or guest Linux admission |

`Accounted*` is temporary counter transport for the order-7 MM bodies, not
another entry owner. The retained `serve_locked_file_op` is a file-family
operation selector for order 9; it owns neither common routing nor completion.

## Co-evolution finding: Born is not host adoption

The predecessor robust-list-only admission required nonzero host generation.
The real ARM family path exposed three red lifecycle tests: child exit returned
Forward, and its existing decline accounting never ran. An in-zone Born record
intentionally carries host generation zero until executor adoption. Accepting
all zero generations would conflate an unissued task with a live owned record.

Core now has two distinct constructors/token types: ordinary `admit` and
`admit_born_in_zone`. Born admission authenticates the live OnCpu owner, slot,
record id, claim sequence, record incarnation, installed MM, task and thread
serial, and the scheduler's existing unadopted-birth authority. Its token keeps
the scheduler region's lifetime. Ordinary completion cannot accept that token.
After adoption, Born admission refuses and the normal host-generation path
applies. Completion may observe same-owner OnCpuRequested solely for settlement
of an already admitted turn. It neither consumes nor clears the host request.

Red-first witnesses:

- Real EL1 pending family name absent: AE witness fails to compile before cut.
- Linux futex module absent: policy witness fails to compile before extraction.
- Core handoff/record admission absent: entry-completion witnesses fail to compile.
- Weakening exact ordinary completion to task-only: `Ok(())` versus expected
  `WrongGeneration`, caught by stale generation/MM/thread cases.
- Removing Born/adoption guards: adopted Born admission incorrectly succeeds.
- Literal-OnCpu-only completion: a request arriving after admission incorrectly
  yields `WrongGeneration`; same-owner settlement now preserves the request.
- Wait-owner suspension/resume uses real `park_object_record`, notification,
  switch and `take_object_operation`, at scales 1/2/8; one result write and
  completion per operation, second take empty. Compile-fail covers token reuse.

The native migration fixture now publishes the new record's host generation,
as a real executor/native context load does. Its Linux results and decline
assertions are preserved, rather than supplying inconsistent task/record facts.

## Physical ABI and native adapter fence

`CurrentTask` is a native aggregate of neutral `ExecutionIdentity` and
`ExecutionMm`, Linux `LinuxTaskState` and `LinuxTaskMetadata`, and the original
reserved padding. Size 128, alignment 8, stride shift 7, hash
`3ff0698f9f1a67f1` are asserted unchanged. Every original byte offset is asserted:

| Word | Offset |
| --- | ---: |
| execution generation / task | 0 / 8 |
| Linux file table / fixup PC / original argument 0 | 16 / 24 / 32 |
| pending work / served work flags | 40 / 44 |
| MM / thread serial | 48 / 56 |
| lifecycle page / control slot | 64 / 72 |
| reserved padding | 80 |

`TrapFrame`, ESR/IRQ classification, fixed-region acquisition, native CPU state,
x8/rax extraction and x0/rax return remain native. Hardware `EntryArch` now
returns a full native snapshot with ISA/profile and opaque native return bits;
`CanonicalCall`, its six Linux arguments, ordinals and errno result live in
Linux ABI. x86 production exposes its full frame, not a universal six-argument
hardware ABI.

Audit the deleted native entry routing/completion (first section only; the
order-9 file-family selector is deliberately retained):

```sh
sed '/^pub unsafe fn serve_locked_file_op/,$d' crates/carrick-el1/src/personality/dispatch.rs | rg -n 'route_aarch64|dispatch_aarch64_family|match nr|fn finish|completion_route\('
rg -n 'CanonicalCall|CanonicalOrdinal|SyscallResult' crates/carrick-guest-arch/src/lib.rs
rg -n 'carrick_core::entry::complete' crates/carrick-x86-cpl0/src/entry.rs
```

All three searches must produce no matches. Pending families have no completion
token constructor or ordinal-to-family table. No rebase was performed; all
predecessor fixes remain on this branch.

## Gate scope

X4 uses real EL1 family bodies under both native codecs, scales 1/2/8, two live
MMs and reused visible IDs, malformed/unported refusals, exact identities and
pending work. KVM execution qualifies native SYSCALL/IRET and real shared entry;
observation/kick doorbells are fixture transport, never host Linux serving.
There is no Docker oracle or runtime-ratio claim on x86-w1. X4's x86 admission
denominator is exactly native 273. Orders 6–9 have not been admitted to x86.
macOS compiler capture and unchanged-ARM signed packet belong to the director.

## X4 executing witness

The KVM X4 case boots two native tasks with the same visible ID, distinct
execution generations/MM keys/thread serials and separate retained lifecycle
pages. At 1/2/8 it observes 4 × scale served calls, 2 × scale publications,
exact native returns, preserved stack/RBX, and one entry/completion per call.
Every call receives entry and return kicks; work exits never replay effects.
Unknown native 39 and 99, and an unloaded native-273 task, publish/complete
nothing; the host records the explicit refusal and supplies no Linux result.

A duplicate-completion image is red in real KVM after the correct first result
and stored head: observed `[2, 0]`, expected `[1, 0]`. Restore/rebuild gives
MATCH; full retained CPL0 entry (6 tests) and progress (2 tests) also pass.
The VM-free ARM portion crosses the actual TrapFrame/EL1 PendingFamilies
adapter, while x86 crosses NativeFrame's full snapshot and Linux codec.

The director confirmed that executing X1–X3 MM/fork/protocol requalification
belongs to integration with `work/x86-x1a`: those KVM targets are absent here.
This lane requalifies its existing X1 bootstrap, complete entry/progress suites
and the VM-free predecessor matrices; it makes no executing X1–X3 MM claim.

## Authorized mechanical MM-fence lines

The director authorized only field-path changes needed for the physical ABI
split. This is the complete changed-line inventory, including tests and rustfmt
wrapping; no MM admission, editor, fault, COW or retirement body is restructured.

```diff
diff --git a/crates/carrick-el1/src/cow.rs b/crates/carrick-el1/src/cow.rs
index 1091ab6bd..af387d4f9 100644
--- a/crates/carrick-el1/src/cow.rs
+++ b/crates/carrick-el1/src/cow.rs
@@ -959 +959 @@ mod tests {
-        task.zone_mm.store(MM, Ordering::Release);
+        task.mm.key.store(MM, Ordering::Release);
@@ -1127 +1127 @@ mod tests {
-        task.zone_mm.store(MM, Ordering::Release);
+        task.mm.key.store(MM, Ordering::Release);
diff --git a/crates/carrick-el1/src/fault.rs b/crates/carrick-el1/src/fault.rs
index 1f050c497..5ec83545b 100644
--- a/crates/carrick-el1/src/fault.rs
+++ b/crates/carrick-el1/src/fault.rs
@@ -406 +406,2 @@ pub fn serve_descriptor_txns<X: DescriptorTxnApplier>(
-        .zone_mm
+        .mm
+        .key
@@ -735 +736 @@ pub fn drain_before_el0<X: DescriptorTxnApplier>(
-    let mm_key = task.zone_mm.load(Ordering::Acquire);
+    let mm_key = task.mm.key.load(Ordering::Acquire);
@@ -975 +976 @@ pub fn dispatch_fault_with_prepared<P: PreparedPageResolver, C: CowResolver>(
-        let mm_key = task.zone_mm.load(Ordering::Acquire);
+        let mm_key = task.mm.key.load(Ordering::Acquire);
@@ -1015 +1016 @@ pub fn dispatch_fault_with_prepared<P: PreparedPageResolver, C: CowResolver>(
-    let mm_key = task.zone_mm.load(Ordering::Acquire);
+    let mm_key = task.mm.key.load(Ordering::Acquire);
@@ -1175 +1176 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1292 +1293 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1349 +1350 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1416 +1417 @@ mod tests {
-                task.zone_mm.store(mm, Ordering::Release);
+                task.mm.key.store(mm, Ordering::Release);
@@ -1516 +1517 @@ mod tests {
-        task.zone_mm.store(7, Ordering::Release);
+        task.mm.key.store(7, Ordering::Release);
@@ -1574 +1575 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1623 +1624 @@ mod tests {
-            task.zone_mm.store(mm, Ordering::Release);
+            task.mm.key.store(mm, Ordering::Release);
@@ -1625 +1626 @@ mod tests {
-            tasks[1].zone_mm.store(mm, Ordering::Release);
+            tasks[1].mm.key.store(mm, Ordering::Release);
@@ -1724 +1725 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1753 +1754 @@ mod tests {
-        task.zone_mm.store(9, Ordering::Release);
+        task.mm.key.store(9, Ordering::Release);
@@ -1782 +1783 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1815 +1816 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -2008 +2009 @@ mod tests {
-            task.zone_mm.store(mm, Ordering::Release);
+            task.mm.key.store(mm, Ordering::Release);
@@ -2150 +2151 @@ mod tests {
-            task.zone_mm.store(mm, Ordering::Release);
+            task.mm.key.store(mm, Ordering::Release);
@@ -2271 +2272 @@ mod tests {
-                tasks[0].served_with_work.load(Ordering::Acquire),
+                tasks[0].linux.served_with_work.load(Ordering::Acquire),
diff --git a/crates/carrick-el1/src/memory.rs b/crates/carrick-el1/src/memory.rs
index 8ee168776..962a7faa0 100644
--- a/crates/carrick-el1/src/memory.rs
+++ b/crates/carrick-el1/src/memory.rs
@@ -73 +73 @@ impl ReservationOrigin {
-        let raw = current.task_id.load(Ordering::Acquire);
+        let raw = current.execution.task.load(Ordering::Acquire);
@@ -77,2 +77,2 @@ impl ReservationOrigin {
-            serial: NonZeroU64::new(current.thread_serial.load(Ordering::Acquire))?,
-            mm: carrick_el1_abi::ReservationMm::new(current.zone_mm.load(Ordering::Acquire))?,
+            serial: NonZeroU64::new(current.mm.thread_generation.load(Ordering::Acquire))?,
+            mm: carrick_el1_abi::ReservationMm::new(current.mm.key.load(Ordering::Acquire))?,
@@ -879 +879 @@ pub fn delegated_anonymous_root(
-    let mm_key = current.zone_mm.load(Ordering::Acquire);
+    let mm_key = current.mm.key.load(Ordering::Acquire);
@@ -915 +915 @@ pub fn try_serve_munmap<E: AnonymousRetirementEditor>(
-    let mm_key = task.zone_mm.load(Ordering::Acquire);
+    let mm_key = task.mm.key.load(Ordering::Acquire);
@@ -978 +978 @@ pub fn try_serve_mprotect<E: AnonymousPermissionEditor>(
-    let mm_key = task.zone_mm.load(Ordering::Acquire);
+    let mm_key = task.mm.key.load(Ordering::Acquire);
@@ -1049 +1049 @@ mod tests {
-        task.zone_mm.store(mm, Ordering::Release);
+        task.mm.key.store(mm, Ordering::Release);
@@ -1345,3 +1345,3 @@ mod tests {
-            task.task_id.store(key + 100, Ordering::Relaxed);
-            task.thread_serial.store(11, Ordering::Relaxed);
-            task.zone_mm.store(key, Ordering::Relaxed);
+            task.execution.task.store(key + 100, Ordering::Relaxed);
+            task.mm.thread_generation.store(11, Ordering::Relaxed);
+            task.mm.key.store(key, Ordering::Relaxed);
diff --git a/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs b/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs
index cdfd201f6..7e726d885 100644
--- a/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs
+++ b/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs
@@ -23 +23 @@ pub fn park_prepared_edit<C: ThreadCpu, U: UserWord>(
-    let mm = ReservationMm::new(sched.task.zone_mm.load(Ordering::Acquire))?;
+    let mm = ReservationMm::new(sched.task.mm.key.load(Ordering::Acquire))?;
@@ -77 +77,5 @@ pub fn park_prepared_edit<C: ThreadCpu, U: UserWord>(
-            sched.task.orig_arg0.store(frame.x[0], Ordering::Relaxed);
+            sched
+                .task
+                .linux
+                .orig_arg0
+                .store(frame.x[0], Ordering::Relaxed);
diff --git a/crates/carrick-el1/src/personality/mm_portal/tests.rs b/crates/carrick-el1/src/personality/mm_portal/tests.rs
index 46c6fb4d8..61a8c37f2 100644
--- a/crates/carrick-el1/src/personality/mm_portal/tests.rs
+++ b/crates/carrick-el1/src/personality/mm_portal/tests.rs
@@ -3063,2 +3063,2 @@ fn prepared_copy_el1_edit_parks_then_commit_or_cancel_wakes_exact_saved_syscall(
-            task.zone_mm.store(mm.raw(), Ordering::Release);
-            task.thread_serial.store(1101, Ordering::Release);
+            task.mm.key.store(mm.raw(), Ordering::Release);
+            task.mm.thread_generation.store(1101, Ordering::Release);
@@ -3349,2 +3349,2 @@ fn schedulerless_settlement_preserves_prepared_permit(cancel: bool) {
-    task.zone_mm.store(mm.raw(), Ordering::Release);
-    task.thread_serial.store(1101, Ordering::Release);
+    task.mm.key.store(mm.raw(), Ordering::Release);
+    task.mm.thread_generation.store(1101, Ordering::Release);
```


## Final entry-policy cut and production census

The eleven frame-independent dispatch assertions now reside in
`carrick-personality-linux/tests/x86_wave2/dispatch.rs`; their native fixture
hooks still execute the real `El1PendingFamilies` implementation. EL1 retains
nine native/diagnostic dispatch witnesses. The Linux entry owner now also
owns file/inotify fallback, original-argument publication, owed-wake lowering,
accounted scheduler-result lowering and delegated-anonymous ordering. The
native hooks retain validated copying, region lookup, native frames and the
unchanged family primitives scheduled for orders 6–9. `Served` is neutral
execution progress in core ABI, without Linux results or completion authority.
The redundant `CurrentTask` Linux-work facades are deleted; all callers use
its physically separate Linux state, with the same atomic ordering.

| New boundary | Exact retained result / refusal / effect |
| --- | --- |
| IPC/futex progress → Linux transfer lowering | Forward remains Forward; Handback remains Handback (never file fallback); Idle suspends; switched return does not overwrite its successor's original argument; unswitched return records the original argument and preserves every signed result |
| Native file operation → Linux file entry | `None` forwards without result/work/original-argument publication; `Some(i64)` preserves its exact signed value; read alone falls back to inotify after native file refusal |
| Watch add/remove → Linux work lowering | Add never marks an owed wake; remove marks it only after a served operation with an owed wake; native result precedes original-argument store, pending-work Release publication and entry completion |
| Anonymous delegated operation → Linux ordering | NotDelegated alone permits permission/retirement fallback; PreparedConflict enrolls once or hands back; Served/Forward are resource outcomes; sole Linux finish publishes their one completion/forward counter |
| Anonymous permission/retirement → Linux result | Every returned signed result is unchanged; permission CommitOwed and retirement Retired install 0 and preserve original argument before requesting replay; the historical missing-task permission return and retirement forwarding remain distinct |
| Native scheduler → accounted entry lowering | Returned(false), Returned(true), Idle map one-to-one to AccountedComplete, AccountedSwitched, AccountedSuspended; no new continuation ledger |
| Lifecycle entry-work refusal → Linux diagnostic | Exact native exit (93) and clone (220) decline cells increment once, with no effect or errno change |

The initial real-path red control inverts the owed-wake condition in the moved
Linux file entry. `dispatch::test_in_guest_read_queues_in_access_and_owes_an_observed_waiter_a_wake`
then fails (Served versus ServedWithWork). Restoring that condition passes all
nineteen Linux entry/dispatch witnesses, including the original-argument check.
This is additional evidence to the generation, Born and physical KVM completion
red controls recorded above.

Production and tests are counted separately against integrated N1 `56bf8c0ca`.
Count Rust source lines containing lexical tokens (including multiline literal
contents), excluding comments/blank lines. Strict cfg(test) items and their
attributes, test-support items, tests directories and named test files belong
to tests; code enabled in ordinary native builds remains production. This uses
`check-dispatch-lock-authority.py`'s existing lexer and production mask, with
strict test-only attributes removed alongside their items.

| ARM-resident source | Before production | After production | Before tests | After tests |
| --- | ---: | ---: | ---: | ---: |
| carrick-el1 | 8,613 | 8,579 | 15,536 | 15,029 |
| carrick-el1-abi | 7,066 | 7,055 | 3,876 | 3,885 |
| carrick-aarch64 | 10,491 | 10,491 | 5,229 | 5,229 |
| Total | 26,170 | 26,125 | 24,641 | 24,143 |

Net production reduction is **45 lines**; net test reduction is **498 lines**.
This falls far short of the plan's 1,700–2,100 production forecast. The entry
cut removes policy bodies but replaces them with explicit exact-binding,
Born authentication, result-transport and pending-family native hooks; later
family primitives remain in ARM as required. The eleven relocated portable
tests account for most of the apparent source reduction and are not counted
as production. No family primitive was moved merely to meet the forecast.

The following additional MM-fence substitutions only remove displaced Linux
state facades; there is no editor, fault, COW or portal algorithm change:

```diff
diff --git a/crates/carrick-el1/src/fault.rs b/crates/carrick-el1/src/fault.rs
index 5ec83545b..1739c0252 100644
--- a/crates/carrick-el1/src/fault.rs
+++ b/crates/carrick-el1/src/fault.rs
@@ -751 +751,2 @@ pub fn drain_before_el0<X: DescriptorTxnApplier>(
-            task.leave_served_with_work()
+            task.linux.record_completed_with_work();
+            Action::ServedWithWork
diff --git a/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs b/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs
index 7e726d885..e20b5bce7 100644
--- a/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs
+++ b/crates/carrick-el1/src/personality/mm_portal/edit_wait.rs
@@ -86 +86 @@ pub fn park_prepared_edit<C: ThreadCpu, U: UserWord>(
-            if sched.task.has_pending_host_work() {
+            if sched.task.linux.has_pending_host_work() {
diff --git a/crates/carrick-el1/src/personality/mm_portal/tests.rs b/crates/carrick-el1/src/personality/mm_portal/tests.rs
index 61a8c37f2..0d353ed5b 100644
--- a/crates/carrick-el1/src/personality/mm_portal/tests.rs
+++ b/crates/carrick-el1/src/personality/mm_portal/tests.rs
@@ -3065 +3065 @@ fn prepared_copy_el1_edit_parks_then_commit_or_cancel_wakes_exact_saved_syscall(
-            task.mark_pending_host_work(); // deterministic leave, no WFI.
+            task.linux.mark_pending_host_work(); // deterministic leave, no WFI.
@@ -3351 +3351 @@ fn schedulerless_settlement_preserves_prepared_permit(cancel: bool) {
-    task.mark_pending_host_work();
+    task.linux.mark_pending_host_work();
```

Reproduction (run from the repository root on the reviewed checkout):

```python
import importlib.util,json,re,subprocess,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('authority_count','scripts/migrate/check-dispatch-lock-authority.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
roots=['el1','el1-abi','aarch64']
for ref in ['56bf8c0ca','WORKTREE']:
 names=subprocess.check_output(['git','ls-tree','-r','--name-only','56bf8c0ca' if ref=='56bf8c0ca' else 'HEAD','crates'],text=True).splitlines()
 totals={n:{'production':0,'test':0} for n in roots};details={}
 for p in names:
  owner=next((n for n in roots if p.startswith('crates/carrick-'+n+'/')),None)
  if not owner or not p.endswith('.rs'):continue
  s=subprocess.check_output(['git','show',ref+':'+p],text=True) if ref!='WORKTREE' else Path(p).read_text()
  lines=s.splitlines();counted={i+1 for i,l in enumerate(lines) if l.strip() and not l.lstrip().startswith(('//','/*','*','*/'))}
  path=Path(p);whole_test=('/tests/' in p or path.stem in ['tests','test_support'] or path.stem.endswith('_tests'))
  tokens=m.lex_rust(s);mask=m.production_mask(tokens)
  # The authority gate keeps an item's attribute visible for lexical checks;
  # the source census excludes strict test-only attributes with their items.
  for i,t in enumerate(tokens):
   if t.text=='#' and i+1<len(tokens) and tokens[i+1].text=='[':
    end=m._matching_delimiter(tokens,i+1,'[',']')
    if m._is_test_only_attribute(tokens,i+2,end):
     mask[i:end+1]=[False]*(end+1-i)
  counted=set()
  for t in tokens:
   counted.update(range(t.line,t.line+t.text.count('\n')+1))

  production=set()
  if not whole_test:
   for t,on in zip(tokens,mask):
    if on:production.update(range(t.line,t.line+t.text.count('\n')+1))
  prod=len(counted & production);test=len(counted)-prod
  totals[owner]['production']+=prod;totals[owner]['test']+=test
  details[p]={'production':prod,'test':test}
 Path('/tmp/ord5-'+('before' if ref=='56bf8c0ca' else 'after')+'-census.json').write_text(json.dumps({'totals':totals,'files':details},indent=2)+'\n')
 print(ref,json.dumps(totals))
b=json.loads(Path('/tmp/ord5-before-census.json').read_text())['files'];a=json.loads(Path('/tmp/ord5-after-census.json').read_text())['files']
for p in a:
 d=a[p]['production']-b[p]['production']
 if d:print(d,p)
```

## Director review: authenticating handoff and removing residual entry owners

The three review findings are fixed in separate commits. Their controls use the
real `El1PendingFamilies`, not a synthetic family implementation.

| Review boundary | Preserved answer / newly enforced ownership |
| --- | --- |
| Pending host work and gettid 178 | Forward with unchanged x0/original argument, zero served/work publication; only 99/132/135 remain setup exceptions |
| Ordinary suspended/switched turn | Authenticate all execution/MM words and scheduler-region/slot/record epoch against the owned receipt from the actual successful park or retirement |
| Born suspended/switched turn | Authenticate exact owner, slot, task/MM/thread serial, pre-publication claim sequence and incarnation; no current/successor record substitutes for the initiating record |
| Lifecycle primitive return | Decoded `LifecycleCall` in, typed `LifecycleOutcome` out. Linux stages the identical signed result and saved argument, authenticates completion, then installs x0 and original argument and selects completion/work |
| Lifecycle exit switches/parks | Primitive returns neutral progress and successor's opaque result; Linux uses the handoff receipt, preserves successor frame/original argument and chooses switched/suspended completion |
| Anonymous settlement/refusal | Native resource authentication, rollback, root completion and exact 0/brk/-12/other result remain unchanged; resource primitive no longer publishes served/forwarded counters. Linux final owner publishes once |
| Anonymous PreparedConflict / unavailable/busy/declined root | Same enrollment/refusal and diagnostic leave reason; counters retain their historical final values and park remains uncounted |
| Robust-list setup | Length, closed-gate/hatch ordering, 0/-22/refusal and publication budget moved once to Linux. Native metadata venue performs only lookup and supplied head/length storage |

`EntryHandoffReceipt` is non-copying historical evidence, issued by core only
around an actual existing park/retirement transition. It is not a new scheduler
or continuation ledger. It retains the initiating record epoch before ownership
can transfer; no post-publication record read tries to authenticate a successor.
The core token borrows its exact scheduler region. Real futex controls cover
ordinary generation drift and Born claim-sequence/incarnation drift, both
idle and switched paths, at scales 1/2/8. They fail the old unconditional handoff
path; weakening only Born handoff authentication reproduces a stale suspension
failure. Restored authentication passes all 228 EL1 library witnesses.

The gettid control fails the old setup exception (ServedWithWork versus Forward)
and restores all 21 lifecycle witnesses. The real lifecycle result control
changes the loaded generation during native venue lookup and observes that
InvalidCompletion leaves x0, original argument, served counter and work flags
untouched. Reinstating result installation before authentication makes it fail
again (41 versus saved 0xfeed). Native anonymous resource witnesses fail when a
counter publisher is reinstated; their fixtures then model the Linux caller's
boundary and retain every original final-counter assertion. Those are actual
resource primitives, not a KVM anonymous-family admission or host-side substitute
for that admission (which remains order 7).

Order 6 still owns extraction of clone birth, clear-tid/exit, signal-mask and
altstack semantic bodies and lifecycle publication. The native selector matches
only an already-decoded operation enum; it has no ordinal routing, final-result
store, original-argument store, host-work choice or entry completion. The
frame-independent robust-list policy was moved here because X4 already admits it;
there is one body shared by ARM and x86. Native IRQ/idle/save/restore remain ISA
mechanics. No order-4b protect/retire/editor algorithm was changed: director review
explicitly requested removing the resource entry counters and nested routing.

Additional owner greps, excluding test modules, must yield no matches:

```sh
sed '/^\/\/\/ The running thread/,$d' crates/carrick-el1/src/personality/lifecycle.rs | rg -n 'match nr|FamilyCompletion|completion_route|has_pending_host_work|orig_arg0|frame\.x\[0\] =|is_lifecycle_syscall'
sed '/^#\[cfg(test)\]/,$d' crates/carrick-el1/src/memory.rs | rg -n 'counters\.(served|forwarded)|dispatch_anonymous_with_reservations'
rg -n 'pub fn serve\b|is_lifecycle_syscall' crates/carrick-el1/src/personality/lifecycle.rs
```

The complete resource counter/routing patch (no editor bodies) follows:

```diff
diff --git a/crates/carrick-el1/src/memory.rs b/crates/carrick-el1/src/memory.rs
index 962a7faa0..2a13ca548 100644
--- a/crates/carrick-el1/src/memory.rs
+++ b/crates/carrick-el1/src/memory.rs
@@ -100,3 +100,2 @@ impl PendingReservationSyscall {
         current: &CurrentTask,
-        counters: &carrick_el1_abi::Counters,
         model: &mut reservations::Reservations<'_>,
@@ -104,3 +103,3 @@ impl PendingReservationSyscall {
     ) -> Result<(), reservations::Refusal> {
-        self.complete_as(frame, current, counters, model, completion, None)
+        self.complete_as(frame, current, model, completion, None)
     }
@@ -114,3 +113,2 @@ impl PendingReservationSyscall {
         current: &CurrentTask,
-        counters: &carrick_el1_abi::Counters,
         model: &mut reservations::Reservations<'_>,
@@ -119,3 +117,3 @@ impl PendingReservationSyscall {
     ) -> Result<(), reservations::Refusal> {
-        self.complete_as(frame, current, counters, model, completion, Some(slot))
+        self.complete_as(frame, current, model, completion, Some(slot))
     }
@@ -125,3 +123,2 @@ impl PendingReservationSyscall {
         current: &CurrentTask,
-        counters: &carrick_el1_abi::Counters,
         model: &mut reservations::Reservations<'_>,
@@ -141,3 +138,2 @@ impl PendingReservationSyscall {
         frame.x[0] = result;
-        counters.served[self.syscall as usize].fetch_add(1, Ordering::Relaxed);
         Ok(())
@@ -156,3 +152,2 @@ impl PendingReservationSyscall {
         current: &CurrentTask,
-        counters: &carrick_el1_abi::Counters,
         model: &mut reservations::Reservations<'_>,
@@ -168,3 +163,2 @@ impl PendingReservationSyscall {
         };
-        counters.served[self.syscall as usize].fetch_add(1, Ordering::Relaxed);
         Ok(())
@@ -667,3 +661,3 @@ pub enum DelegatedAnonymous {
 /// receipt at its next boundary. Everything else refuses the proposal and
-/// forwards. Counts served or forwarded exactly once.
+/// forwards. The Linux entry owner publishes the completion/refusal counter.
 pub fn serve_delegated_anonymous<E: AnonymousDescriptorEditor>(
@@ -682,3 +676,2 @@ pub fn serve_delegated_anonymous<E: AnonymousDescriptorEditor>(
     let forward = |why: carrick_el1_abi::AnonymousLeave| {
-        counters.forwarded[nr as usize].fetch_add(1, Ordering::Relaxed);
         counters.anonymous_leaves[why as usize].fetch_add(1, Ordering::Relaxed);
@@ -691,22 +684,13 @@ pub fn serve_delegated_anonymous<E: AnonymousDescriptorEditor>(
     };
-    let mut pending = match crate::personality::dispatch::dispatch_anonymous_with_reservations(
-        frame, counters, current, &mut model,
-    ) {
-        crate::personality::dispatch::AnonymousReservationRoute::Action(
-            carrick_el1_abi::Action::Served,
-        ) => return DelegatedAnonymous::Served,
-        // `forwarded[nr]` counted by the route.
-        crate::personality::dispatch::AnonymousReservationRoute::Action(_) => {
-            counters.anonymous_leaves[Leave::RootDeclined as usize].fetch_add(1, Ordering::Relaxed);
-            return DelegatedAnonymous::Forward;
+    let mut pending = match decide_anonymous_syscall(frame, current, &mut model) {
+        ReservationDisposition::Return(value) => {
+            frame.x[0] = value as u64;
+            return DelegatedAnonymous::Served;
         }
-        crate::personality::dispatch::AnonymousReservationRoute::Unavailable(
-            reservations::Refusal::PreparedConflict,
-        ) => {
+        ReservationDisposition::Forward => return forward(Leave::RootDeclined),
+        ReservationDisposition::Unavailable(reservations::Refusal::PreparedConflict) => {
             return DelegatedAnonymous::PreparedConflict;
         }
-        crate::personality::dispatch::AnonymousReservationRoute::Unavailable(_) => {
-            return forward(Leave::RootUnavailable);
-        }
-        crate::personality::dispatch::AnonymousReservationRoute::Work(pending) => pending,
+        ReservationDisposition::Unavailable(_) => return forward(Leave::RootUnavailable),
+        ReservationDisposition::Work(pending) => pending,
     };
@@ -841,7 +825,6 @@ pub fn serve_delegated_anonymous<E: AnonymousDescriptorEditor>(
     let completed = match (completion, owed_return) {
-        (Some(completion), Some(slot)) => pending
-            .complete_deferring_return(frame, current, counters, &mut model, completion, slot),
-        (Some(completion), None) => {
-            pending.complete(frame, current, counters, &mut model, completion)
+        (Some(completion), Some(slot)) => {
+            pending.complete_deferring_return(frame, current, &mut model, completion, slot)
         }
+        (Some(completion), None) => pending.complete(frame, current, &mut model, completion),
         (None, slot) => {
@@ -1446,2 +1429,4 @@ mod tests {
             frame.x[..6].copy_from_slice(&args);
+            let served_before = counters.served[nr as usize].load(Ordering::Relaxed);
+            let forwarded_before = counters.forwarded[nr as usize].load(Ordering::Relaxed);
             let route = serve_delegated_anonymous(
@@ -1454,2 +1439,23 @@ mod tests {
             );
+            assert_eq!(
+                counters.served[nr as usize].load(Ordering::Relaxed),
+                served_before,
+                "resource primitive cannot publish entry completion"
+            );
+            assert_eq!(
+                counters.forwarded[nr as usize].load(Ordering::Relaxed),
+                forwarded_before,
+                "resource primitive cannot publish entry refusal"
+            );
+            // This fixture models the caller's Linux boundary after the actual
+            // resource primitive, keeping all historical final-count assertions.
+            let entry = carrick_personality_linux::dispatch::EntryCounters {
+                served: &counters.served,
+                forwarded: &counters.forwarded,
+            };
+            match route {
+                DelegatedAnonymous::Served => entry.served(nr),
+                DelegatedAnonymous::Forward => entry.forwarded(nr),
+                _ => {}
+            }
             (route, frame.x[0] as i64)
```

The final x86-none warning-strict check exposed the old `setup_open` predicate
as dead code after robust-list policy left the shared metadata view. Move that
unchanged predicate beside its retained ARM signal/altstack callers, not behind
an allow or new policy path. `cargo clippy --locked -p carrick-x86-cpl0 --release
--target x86_64-unknown-none -- -D warnings` fails red on the old location and
passes after the move. The separate production/test census is unchanged.
