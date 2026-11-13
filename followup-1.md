title: x86 CPL0 #PF: MM editor contention between two CPUs is fatal instead of an owner wait (blocks py-thread after #2217)
parent: #2266

**What happens (real KVM, head of #2266 `059752685`).**

```
python:3.12-slim python3 -P -c 'import _thread; _thread.start_new_thread(print,("x",)); import time; time.sleep(1)'
```

This exits 125 with `kernel fault policy refused on CPU 0: reason 9, FaultDoorbellRecord { vector: 14, error_code: 20, rip: 0x8840..., ... }`. It happens in every run (5 of 5). The root thread on CPU 0 takes an instruction-fetch first touch on a prepared page while the new thread on CPU 1 is faulting on the same MM.

**Root cause (instrumented build; the diagnostics are not committed).**
- In `crates/carrick-el1/src/fault.rs` `dispatch_classified_fault`, the prepared-page arm calls `FaultSupply::editor`. `try_begin_edit_cause` refuses with `EditAdmissionRefusal::Editor`, and the holder word is `2`: CPU 1 (`slot + 1`) holds the exact-MM editor.
- `crates/carrick-x86-cpl0/src/linux_personality.rs` `supply_user_fault` builds `OwnerFaultSupply::new(portal)` **without** `with_handle`. So `FaultSupply::contend` takes its `probe().ok()` fallback, contention never becomes `OwnerFaultSupplyOutcome::Wait`, and the outcome stays `Unavailable`. That maps to `UserFaultSupply::Unresolved(9)`, and the fault doorbell ends the run. "Busy" has become fatal.

**Existing mechanism to reuse (ARM).**
- `crates/carrick-el1-linux/src/cow_resolver.rs` `dispatch_fault` attaches `admitted_fault_mm_handle` and gets `Wait(PortalOwnerWait)`.
- `park_fault_owner_wait` then parks the record on `PortalWaitEnrollment::for_owner`, with the saved PC at the faulting instruction (`SavedSyscallPc::AtSyscall`), and reruns the fault on release.
- x86 already mints the same handle for user copies (`crates/carrick-x86-cpl0/src/native_process.rs` `service_mm_handle`, `portal().admitted_handle`).

**What x86 lacks (ISA mechanics, plus seam #1078).**
1. A park from the `#PF` entry. It must:
   - clear the per-CPU in-fault guard (`gs:[136]`);
   - save the fault frame and XSAVE as a full IRET context; the frame order already matches `ParkedContextWords`;
   - park through `carrick_core::wait::park_object_record`;
   - settle owed work, then call `Personality::schedule`.
2. A typed "resume at the faulting instruction" position in x86 `ParkedContextWords`. There is spare room in `_xsave_align`. Today `saved_syscall_pc()` is always `AfterSyscall`, and replay paths call `restart_syscall` (RIP minus 2), which would corrupt a fault resume.
3. Signal, exit and cancellation handling while a fault is parked: the native fault-wait cancellation in #1078. Compare `native_process_runtime/service.rs` `park_owner_wait`.
4. The host-loaded root on CPU 0 must survive this park through the same handoff its syscall parks already use (`cpl0_entry::production_anonymous_editor_busy_once_parks_and_completes`).

**Acceptance.**
- A red-first KVM witness: two live threads first-touch the same prepared page on CPU 0 and CPU 1. It must be red on main with `reason 9`, and green when the loser parks once and reruns, with no carrier fatal and no errno.
- The `_thread` reproducer above prints `x` and exits 0.
- `py-thread` reaches its next stop. Today it stops earlier, at #2217 (`import threading` segfaults, 139).
