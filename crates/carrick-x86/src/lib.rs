//! `carrick-x86` — the shared x86_64 VMM-backend engine scaffold (Axis 2).
//!
//! This crate sits ABOVE `carrick-hal`/`carrick-mem`/`carrick-guest-mem` and
//! BELOW the per-VMM backend crates (`carrick-vmm-bhyve`, `carrick-vmm-kvm`'s KVM
//! lane, `carrick-vmm-nvmm`). Its job is to own — ONCE — everything the x86 VMM
//! backends currently re-implement by copy: the trap loop, the register walk,
//! the long-mode bring-up, the snapshot/restore triple, and the run-elf service
//! loop, all parameterized over the thin [`X86Vmm`] + [`X86Vcpu`] trait pair.
//!
//! ## Status: Stage 1 — scaffold only, NO callers
//!
//! Per the portability staging plan (design doc §5), Stage 1 defines the trait
//! pair, the value types ([`X86Exit`]/[`MsrInstall`]/[`ForkRamStrategy`]/
//! [`WindowPlan`]/[`X86Reg`]/[`X86Seg`]), and hoists the pure ISA byte-emitters
//! ([`msr_init_blob`]/[`fp_stub_bytes`]) plus the [`run_fp_stub`] driving logic.
//!
//! NOTHING consumes this crate yet — it compiles standalone. The engine itself
//! (`X86EngineCore<V>` implementing `SyscallTrap`/`RegAccess`/`GuestMemory`/
//! `ThreadedEngine`) and the backend impls land in Stages 2–5; no backend is
//! migrated here, so all four live backends keep building unchanged.

pub mod bringup;
pub mod bringup_fns;
pub mod engine;
pub mod fault;
pub mod vdso;
pub mod vmm;

pub use bringup::{fp_stub_bytes, msr_init_blob, run_fp_stub};
pub use bringup_fns::{
    BringupLayout, LongModeSegmentState, X86VcpuSnapshot, build_pml4, long_mode_segment_state,
    plan_windows, program_longmode_entry, program_user_segments, restore, run_elf_service_loop,
    seed_entry, snapshot, write_bringup_images,
};
pub use engine::X86EngineCore;
pub use fault::{
    FAULT_DOORBELL_PORT, FP_STUB_DOORBELL_PORT, FaultDoorbellRecord, FaultMemoryRecord,
    X86_FAULT_MEMORY_RECORD_BYTES, X86_FAULT_RECORD_U32_WORDS, X86_FAULT_SLOTS, add_fault_windows,
    fault_exit_from_record, fault_idt_base, fault_record_base, fault_slot_gpa, fault_stack_base,
    fault_stub_base, fault_tss_base, program_fault_segments, write_fault_tables,
    write_fault_tables_with, write_memory_record_fault_tables,
    write_memory_record_fault_tables_with,
};
pub use vmm::{
    ForkRamStrategy, MsrInstall, WindowPlan, WindowRegion, X86_PML4_CAPACITY, X86Exit,
    X86FaultKind, X86Reg, X86Seg, X86Vcpu, X86Vmm, XSAVE_AVX_OFFSET, XSAVE_LEN, fxsave_to_xsave,
};
