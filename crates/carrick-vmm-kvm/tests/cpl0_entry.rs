//! Executing KVM bindings for kernel.el1.task-load-entry,
//! kernel.syscall.captured-stack, kernel.vcpu.kick-el0-boundary and lifecycle
//! control-slot ownership. Linux set_robust_list(2): length 24 returns 0;
//! any other length returns EINVAL(22), preserving the previous head.
//! Budgets: one entry/completion per call, one publication per success,
//! zero semantic host forwards. Control observation/kicks are separate.
//! Missing KVM or an image is a failure; no Docker, retries or timing claims.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
use carrick_sched_core::{ParkedContextWords, SlotId, ThreadIdentity, ZoneTables};
use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_entry::{
    OBSERVE_ALLOCATOR, OBSERVE_DESCRIPTOR_PROTECT, OBSERVE_MMU_DRAIN, OBSERVE_MMU_ROOT,
    OBSERVE_NATIVE,
};
use carrick_x86::cpl0_scheduler::{
    ContextBinding, InterruptFrame, NativeContext, XsaveArea, admit_context, park_native_context,
    restore_native_context,
};
use std::num::NonZeroU64;
use std::path::PathBuf;

fn user_access_program(index: u64) -> (Vec<u8>, Vec<i64>) {
    let mapped = 0x3_1000 + index * 0x1_0000;
    let code = 0x1_0000 + index * 0x1000;
    let unmapped_edge = mapped + 0xff8;
    let mut bytes = Vec::new();
    let calls = [
        (mapped, 2_u64, 0_i64),
        (mapped, 0, 0x51ab_cdef_1234_5678_i64),
        (mapped, 1, 0x51ab_cdef_1234_5678_i64),
        (mapped, 8, 0x51ab_cdef_1234_5678_i64), // typed chunk copy-in
        (mapped, 9, 0),                         // typed chunk copy-out
        (mapped, 0, 0x6ace_b00c_1234_5678_i64),
        (mapped, 10, 0), // wrong MM incarnation consumes no kernel bytes
        (mapped, 14, 0), // changed thread generation also refuses
        (mapped, 12, 0), // unsupported word width is typed InvalidWidth
        (mapped, 13, 0), // foreign task cannot validate this live CR3
        (mapped, 3, 0x1234_5678_i64),
        (mapped, 4, 16),
        (mapped, 5, 16),
        (code, 4, 16),
        (code, 5, 0),
        (0xffff_ffff_8000_0000, 4, 0), // mapped supervisor image is outside user range
        (0xffff_ffff_8000_0000, 0, -14),
        (0xffff_ffff_8000_0000, 1, -14),
        (0xffff_ffff_8000_0000, 2, -14),
        (0x0000_7fff_ffff_fffc, 0, -14), // eight-byte word crosses the ceiling
        (0x0000_7fff_ffff_fffc, 4, 0),   // validation rejects whole crossed range
        (u64::MAX - 3, 1, -14),          // wrapped copy cannot alias kernel
        (u64::MAX - 3, 8, -14),          // typed transfer refuses wrapped range
        (unmapped_edge, 4, 8),           // prefix ends at the unmapped next page
        (unmapped_edge, 5, 8),
        (unmapped_edge + 4, 1, -14), // preflight refuses a cross-page copy-in
        (unmapped_edge + 4, 2, -14), // preflight refuses a cross-page copy-out
        (0x7_0000, 0, -14),
        (0x7_0000, 11, 0), // mapped trait returns typed fault, not zero data
        (0x7_0000, 1, -14),
        (0x7_0000, 2, -14),
        (0x7_0000, 6, -14), // execute the #PF recovery path after bypassing preflight
        (0x7_0000, 7, -14),
        (0x7_0000, 4, 0),
        (0x7_0000, 5, 0),
    ];
    for (address, mode, _) in calls {
        bytes.extend_from_slice(&[0x48, 0xbf]); // mov rdi, user VA
        bytes.extend_from_slice(&address.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xbe]); // mov rsi, operation
        bytes.extend_from_slice(&mode.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xb8]);
        bytes.extend_from_slice(&0xffff_ffff_ffff_ff10_u64.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]); // syscall into shared kernel witness
        bytes.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]);
        bytes.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]);
    }
    bytes.extend_from_slice(&[0x0f, 0x0b]);
    (
        bytes,
        calls.into_iter().map(|(_, _, expected)| expected).collect(),
    )
}

fn exercise_shared_kernel_user_access(smap: bool) {
    // Before the user-access leaf was bound, the first mapped call hit UD2.
    // Both live tasks use distinct stack pages and task-local fixup records.
    let (a, expected_a) = user_access_program(0);
    let (b, expected_b) = user_access_program(1);
    let mut carrier = Cpl0Carrier::boot(&image(), [&a, &b]).expect("real KVM + shared CPL0 image");
    if smap {
        carrier.enable_smap().expect("guest SMAP capability");
    }
    for (round, (expected_a, expected_b)) in expected_a.into_iter().zip(expected_b).enumerate() {
        for (task, expected) in [(0, expected_a), (1, expected_b)] {
            assert_eq!(
                carrier.observe(task).expect("bounded user access").result,
                expected,
                "task {task}, round {round}"
            );
        }
    }
}

#[test]
fn shared_kernel_user_access_recovers_from_bad_va() {
    exercise_shared_kernel_user_access(false);
}

#[test]
fn shared_kernel_user_access_restores_smap_ac() {
    exercise_shared_kernel_user_access(true);
}

fn image() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0-fixture")
}

#[test]
fn production_image_rejects_fixture_syscalls() {
    let production = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0");
    let bytes = std::fs::read(&production).expect("production CPL0 image built");
    let plan =
        carrick_mem::elf::plan_elf_load_bytes_for(&bytes, 62).expect("production CPL0 load image");
    for syscall in [
        0xffff_ffff_ffff_ff10_u64,
        0xffff_ffff_ffff_ff20,
        0xffff_ffff_ffff_ff30,
        0xffff_ffff_ffff_ff40,
    ] {
        assert!(
            !plan.segments.iter().any(|segment| {
                let start = segment.file_offset as usize;
                let end = start + segment.file_size as usize;
                bytes[start..end]
                    .windows(8)
                    .any(|window| window == syscall.to_le_bytes())
            }),
            "production image contains fixture syscall {syscall:#x}"
        );
    }
    let probe = transport_program(0);
    let mut carrier =
        Cpl0Carrier::boot(&production, [&probe, &probe]).expect("production image on real KVM");
    let err = carrier
        .observe(0)
        .expect_err("synthetic syscall must not dispatch");
    assert!(
        err.to_string().contains("unported CPL0 native call"),
        "{err}"
    );
}

fn program(calls: &[(u64, u64)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &(head, len) in calls {
        bytes.extend_from_slice(&[0x48, 0xbb]); // mov rbx, per-call state
        bytes.extend_from_slice(&head.to_le_bytes());
        bytes.push(0x53); // push rbx: syscall must capture this live user SP
        bytes.extend_from_slice(&[0x48, 0xbf]); // mov rdi, head
        bytes.extend_from_slice(&head.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xbe]); // mov rsi, len
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&[0xb8, 0x11, 0x01, 0, 0, 0x0f, 0x05]); // native 273; syscall
        bytes.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]); // mov rdi, rax; observation
        bytes.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]);
        bytes.push(0x5b); // pop rbx after observation resumes
    }
    bytes.extend_from_slice(&[0x0f, 0x0b]); // running past the fixture is a fault
    bytes
}

#[test]
fn shared_kernel_mmu_reports_live_cr3_root() {
    let mut program = vec![0x48, 0xb8]; // mov rax, fixture MMU observation
    program.extend_from_slice(&OBSERVE_MMU_ROOT.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0xb8]);
    program.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    let mut carrier = Cpl0Carrier::boot(&image(), [&program, &program]).expect("KVM image");
    for task in 0..2 {
        let observed = carrier
            .observe(task)
            .expect("MMU root read and observation");
        assert_eq!(observed.result as u64, 0x60_0000);
        assert_eq!(observed.semantic_host_exits, 0);
    }
}

#[test]
fn shared_kernel_allocator_serves_two_live_cpl0_tasks() {
    let mut program = vec![0x48, 0xb8];
    program.extend_from_slice(&OBSERVE_ALLOCATOR.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0xb8]);
    program.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    let mut carrier = Cpl0Carrier::boot(&image(), [&program, &program]).expect("KVM image");
    for task in 0..2 {
        let observed = carrier.observe(task).expect("allocator and observation");
        assert_eq!(observed.result, 1);
        assert_eq!(observed.semantic_host_exits, 0);
    }
}

#[test]
fn shared_kernel_drain_receipt_requires_the_live_root() {
    let program = |root: u64| {
        let mut bytes = vec![0x48, 0xbf]; // mov rdi, user page
        bytes.extend_from_slice(&0x3_0000_u64.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xbe]); // mov rsi, requested root
        bytes.extend_from_slice(&root.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xb8]);
        bytes.extend_from_slice(&OBSERVE_MMU_DRAIN.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0xb8]);
        bytes.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        bytes
    };
    let good = program(0x60_0000);
    let stale = program(0x70_0000);
    let mut carrier = Cpl0Carrier::boot(&image(), [&good, &stale]).expect("KVM image");
    assert_eq!(
        carrier.observe(0).expect("live root receipt").result as u64,
        0x60_0000
    );
    assert_eq!(carrier.observe(1).expect("stale root refused").result, -1);
}

#[test]
fn shared_kernel_x86_descriptor_protects_a_user_page() {
    let mut program = vec![0x48, 0xb8];
    program.extend_from_slice(&OBSERVE_DESCRIPTOR_PROTECT.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0xb8]);
    program.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    let mut carrier = Cpl0Carrier::boot(&image(), [&program, &program]).expect("KVM image");
    assert_eq!(
        carrier
            .observe(0)
            .expect("descriptor edit and observation")
            .result,
        1
    );
    let leaf = carrier
        .fixture_user_leaf(0x3_0000)
        .expect("4 KiB user leaf");
    assert_ne!(leaf & 1, 0, "mapping remains present");
    assert_eq!(leaf & 2, 0, "RW is cleared by the shared-kernel edit");
    assert_ne!(leaf & (1 << 63), 0, "NX is set by the shared-kernel edit");
}

// Observe each task in turn while both lifecycle slots remain live. Registration
// must store even NULL, unmapped and noncanonical heads without accessing them.
fn assert_opaque_registrations(calls: [&[(u64, u64)]; 2]) {
    assert_eq!(calls[0].len(), calls[1].len());
    let a = program(calls[0]);
    let b = program(calls[1]);
    let mut carrier = Cpl0Carrier::boot(&image(), [&a, &b]).expect("real KVM + CPL0 image");
    let mut heads = [(0, 0); 2];
    let mut entries = [0; 2];
    let mut publications = [0; 2];
    for (round, (&(head_a, len_a), &(head_b, len_b))) in
        calls[0].iter().zip(calls[1].iter()).enumerate()
    {
        for (task, (head, len)) in [(0, (head_a, len_a)), (1, (head_b, len_b))] {
            let observation = carrier.observe(task).expect("bounded native entry/return");
            if len == 24 {
                heads[task] = (head, 24);
                publications[task] += 1;
            }
            entries[task] += 1;
            assert_eq!(
                observation.result,
                if len == 24 { 0_i64 } else { -22_i64 },
                "full result: task {task}, round {round}, len {len:#x}"
            );
            assert_eq!(
                observation.heads, heads,
                "opaque heads and unchanged sibling: task {task}, round {round}"
            );
            assert_eq!(observation.entries, entries);
            assert_eq!(observation.completions, entries);
            assert_eq!(observation.publications, publications);
            assert_eq!(observation.served, entries[0] + entries[1]);
            assert_eq!(observation.forwarded, 0, "zero semantic forwards per call");
            assert_eq!(
                observation.semantic_host_exits, 0,
                "no host serving scaffold"
            );
            let stack = 0x3_1fe8 + task as u64 * 0x1_0000;
            assert_eq!(observation.captured_stack, stack);
            assert_eq!(observation.returned_stack, stack);
            assert_eq!(observation.preserved_rbx, head);
        }
    }
}

#[test]
fn two_live_tasks_register_full_width_heads_without_dereferencing() {
    // Deliberately share low 32 bits across tasks: truncation destroys their
    // distinct opaque identities. Neither high address is mapped by this image.
    let a = [
        (0x0000_1234_0000_a000, 24),
        (0x8000_1234_0000_a000, 24),
        (0, 24),
        (u64::MAX, 24),
        (0x0000_1234_0000_dead, 23),
    ];
    let b = [
        (0x0000_5678_0000_a000, 24),
        (0x8000_5678_0000_a000, 24),
        (u64::MAX, 24),
        (0, 24),
        (0x8000_5678_0000_beef, 25),
    ];
    assert_opaque_registrations([&a, &b]);
}

#[test]
fn two_live_tasks_reject_length_with_high_bits_preserving_both_heads() {
    // Low heads in the first round isolate RSI truncation from RDI truncation:
    // the negative control reaches a completed call with the wrong result.
    let a = [
        (0, 24),
        (0x8000_1234_0000_dead, 0x1_0000_0018),
        (0x0000_1234_0000_a000, 24),
        (u64::MAX, 0x1_0000_0018),
        (0, 24),
    ];
    let b = [
        (0xb000, 24),
        (0x0000_5678_0000_beef, 0x1_0000_0018),
        (0x8000_5678_0000_a000, 24),
        (0, 0x1_0000_0018),
        (0x0000_5678_0000_a000, 24),
    ];
    assert_opaque_registrations([&a, &b]);
}

#[test]
fn two_live_tasks_serve_robust_lists_without_host_forwards() {
    let a = program(&[(0xa000, 24), (0xa040, 24), (0xdead, 23), (0xdead, 0)]);
    let b = program(&[(0xb000, 24), (0xb040, 24), (0xbeef, 25), (0xbeef, u64::MAX)]);
    let mut carrier = Cpl0Carrier::boot(&image(), [&a, &b]).expect("real KVM + CPL0 image");
    let mut heads = [(0, 0); 2];
    let mut entries = [0; 2];
    let mut publications = [0; 2];
    let mut forwards = 0;
    let mut host_exits = 0;
    let mut served = 0;
    for round in 0..4 {
        for task in 0..2 {
            let observation = carrier.observe(task).expect("bounded native entry/return");
            if round < 2 {
                heads[task] = (if task == 0 { 0xa000 } else { 0xb000 } + round * 0x40, 24);
                publications[task] += 1;
            }
            entries[task] += 1;
            assert_eq!(observation.result, if round < 2 { 0 } else { -22 });
            assert_eq!(
                observation.heads, heads,
                "both stored heads after success/error"
            );
            assert_eq!(observation.entries, entries);
            assert_eq!(observation.completions, entries);
            assert_eq!(observation.publications, publications);
            let stack = 0x3_1fe8 + task as u64 * 0x1_0000;
            assert_eq!(observation.captured_stack, stack);
            assert_eq!(observation.returned_stack, stack);
            assert_eq!(
                observation.preserved_rbx,
                match (round, task) {
                    (0..2, 0) => 0xa000 + round * 0x40,
                    (0..2, _) => 0xb000 + round * 0x40,
                    (_, 0) => 0xdead,
                    _ => 0xbeef,
                }
            );
            forwards = observation.forwarded;
            host_exits = observation.semantic_host_exits;
            served = observation.served;
        }
    }
    // Inspect every result/head first: red must be a structural serving defect,
    // not a missing symbol, broken boot, wrong return or unexecuted fixture.
    assert_eq!(forwards, 0, "semantic host forwards must be zero");
    assert_eq!(host_exits, 0, "no host serving scaffold");
    assert_eq!(served, 8, "one common completion per success/error");
}

#[test]
fn x4_linux_common_entry() {
    use carrick_el1_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    };
    for scale in [1_u64, 2, 8] {
        let calls: [Vec<(u64, u64)>; 2] = core::array::from_fn(|task| {
            (0..2 * scale)
                .map(|round| {
                    (
                        0x0000_1234_0000_a000 + task as u64 * 0x1000 + round * 0x40,
                        if round % 2 == 0 { 24 } else { 0x1_0000_0018 },
                    )
                })
                .collect()
        });
        let a = program(&calls[0]);
        let b = program(&calls[1]);
        let mut carrier = Cpl0Carrier::boot(&image(), [&a, &b]).expect("X4 real KVM carrier");
        let bindings = core::array::from_fn::<_, 2, _>(|task| ExecutionBinding {
            task: EntryTaskKey::from_raw(41),
            generation: EntryGeneration::from_raw(100 + task as u64),
            mm: EntryMmKey::from_raw(77 + task as u64),
            thread_generation: EntryThreadGeneration::from_raw(101 + task as u64),
        });
        for (task, binding) in bindings.into_iter().enumerate() {
            carrier.bind_execution(task, binding).unwrap();
        }
        let mut heads = [(0, 0); 2];
        let mut entries = [0; 2];
        let mut publications = [0; 2];
        for round in 0..2 * scale {
            for task in 0..2 {
                carrier.inject_boundary_kicks(task).unwrap();
                let observed = carrier
                    .observe(task)
                    .expect("X4 bounded entry and native return");
                entries[task] += 1;
                if round % 2 == 0 {
                    heads[task] = (calls[task][round as usize].0, 24);
                    publications[task] += 1;
                }
                assert_eq!(observed.result, if round % 2 == 0 { 0 } else { -22 });
                assert_eq!(observed.heads, heads);
                assert_eq!(observed.entries, entries);
                assert_eq!(
                    observed.completions, entries,
                    "one shared completion per native syscall"
                );
                assert_eq!(observed.publications, publications);
                assert_eq!(observed.served, entries[0] + entries[1]);
                assert_eq!(observed.forwarded, 0);
                assert_eq!(observed.semantic_host_exits, 0, "no host Linux serving");
                assert_eq!(observed.kicks, 2 * (entries[0] + entries[1]));
                assert_eq!(observed.work_exits, entries[0] + entries[1]);
                assert_eq!(observed.captured_stack, 0x3_1fe8 + task as u64 * 0x1_0000);
                assert_eq!(observed.returned_stack, observed.captured_stack);
                assert_eq!(observed.preserved_rbx, calls[task][round as usize].0);
                assert_eq!(carrier.entry_state().bindings, bindings);
            }
        }
    }
    // Native numbers are not canonical ARM ordinals. Refusals never call a
    // family or receive a synthetic host result; inspect the stopped owner.
    for native in [39_u32, 99, 273] {
        let mut code = program(&[(0xdead, 24)]);
        let needle = [0xb8, 0x11, 0x01, 0, 0, 0x0f, 0x05];
        let offset = code
            .windows(needle.len())
            .position(|bytes| bytes == needle)
            .unwrap();
        code[offset + 1..offset + 5].copy_from_slice(&native.to_le_bytes());
        let peer = program(&[(0xbeef, 24)]);
        let mut carrier = Cpl0Carrier::boot(&image(), [&code, &peer]).unwrap();
        if native == 273 {
            carrier.unload_execution(0).unwrap();
        }
        assert!(carrier.observe(0).is_err());
        let stopped = carrier.entry_state();
        assert_eq!(stopped.entries, [1, 0]);
        assert_eq!(stopped.publications, [0, 0]);
        assert_eq!(stopped.completions, [0, 0]);
        assert_eq!(stopped.heads, [(0, 0); 2]);
        assert_eq!(stopped.served, 0);
        assert_eq!(
            stopped.host_forwards, 1,
            "one explicit refusal, no host emulation"
        );
    }
}

#[test]
fn entry_and_return_kicks_never_republish_or_recomplete() {
    let a = program(&[(0xa000, 24), (0xdead, 23)]);
    let b = program(&[(0xb000, 24), (0xbeef, 25)]);
    let mut carrier = Cpl0Carrier::boot(&image(), [&a, &b]).unwrap();
    let mut heads = [(0, 0); 2];
    let mut entries = [0; 2];
    let mut publications = [0; 2];
    let mut forwards = 0;
    for round in 0..2 {
        for task in 0..2 {
            carrier.inject_boundary_kicks(task).unwrap();
            let observation = carrier.observe(task).unwrap();
            if round == 0 {
                heads[task] = (if task == 0 { 0xa000 } else { 0xb000 }, 24);
                publications[task] += 1;
            }
            entries[task] += 1;
            assert_eq!(observation.result, if round == 0 { 0 } else { -22 });
            assert_eq!(observation.heads, heads);
            assert_eq!(observation.entries, entries);
            assert_eq!(observation.completions, entries);
            assert_eq!(observation.publications, publications);
            assert_eq!(
                observation.captured_stack,
                0x3_1fe8 + task as u64 * 0x1_0000
            );
            assert_eq!(observation.returned_stack, observation.captured_stack);
            assert_eq!(observation.kicks, (entries[0] + entries[1]) * 2);
            assert_eq!(observation.work_exits, entries[0] + entries[1]);
            forwards = observation.forwarded + observation.semantic_host_exits;
        }
    }
    let observation_count = entries[0] + entries[1];
    assert_eq!(observation_count, 4);
    assert_eq!(forwards, 0, "kicks cannot forward a served call");
}

#[test]
fn x1_boot_shared_substrate() {
    let p = program(&[(0xa000, 24), (0xdead, 23)]);
    let dummy = &[0x0f, 0x0b];
    let mut carrier = Cpl0Carrier::boot(&image(), [&p, dummy]).expect("real KVM + CPL0 image");

    // Shared substrate ZoneTables and AddressSpaces claims
    let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
    let zone = unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    };
    let slot = SlotId::new(0);
    zone.drive(slot, 1);
    zone.publish_slot(slot, 11, Some(0), 0);
    zone.enter_guest(slot);

    let mm = 11u64;
    let root = RootGpa::page_aligned(FrameGpa::new(0x60_0000)).unwrap();
    let space = zone
        .spaces
        .publish_closed(mm, root.address().raw(), 0)
        .unwrap();
    zone.spaces.open(space);

    let record = zone
        .alloc_record(ThreadIdentity {
            mm,
            tid: 41,
            serial: 101,
            generation: 5,
            ..Default::default()
        })
        .unwrap();
    let address = AddressContext {
        root,
        mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
        generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
    };
    let native = NativeContext {
        frame: InterruptFrame {
            gpr: [0; 15],
            rip: carrick_vmm_kvm::cpl0_boot::USER_CODE,
            cs: 0x23,
            flags: 0x202,
            rsp: 0x3_1ff0,
            ss: 0x1b,
        },
        address,
        fs_base: 0x1000,
        gs_base: 0x2000,
        xsave: XsaveArea::ZERO,
    };
    // SAFETY: this new record remains host-owned until requeue.
    unsafe { *zone.record(record).ctx_mut() = park_native_context(&native) };
    zone.requeue_preempted(slot, record);
    let on_cpu = zone.switch_in(slot).unwrap();
    assert_eq!(on_cpu, record);

    let binding = ContextBinding {
        record: zone.record_ref(record),
        address,
    };

    // 1. Admit context under shared ZoneTables and AddressSpaces claims
    assert!(admit_context(&zone, slot, &binding));
    assert_eq!(zone.installed_space(slot), mm);

    // 2. Execute CPL3 bytes and verify shared robust-list serving
    // Call 1: valid length 24
    let obs1 = carrier.observe(0).expect("bounded native entry/return");
    assert_eq!(obs1.result, 0, "set_robust_list(24) should return 0");
    assert_eq!(obs1.heads[0], (0xa000, 24));
    assert_eq!(obs1.forwarded, 0);
    assert_eq!(obs1.semantic_host_exits, 0);

    // Call 2: invalid length 23
    let obs2 = carrier.observe(0).expect("bounded native entry/return");
    assert_eq!(
        obs2.result, -22,
        "set_robust_list(23) should return -EINVAL (-22)"
    );
    assert_eq!(obs2.heads[0], (0xa000, 24), "previous head preserved");

    // 3. Preserve native context / TLS / XSAVE
    assert_eq!(obs1.captured_stack, 0x3_1fe8);
    assert_eq!(obs1.returned_stack, 0x3_1fe8);
    assert_eq!(obs1.preserved_rbx, 0xa000);
    assert_eq!(obs2.preserved_rbx, 0xdead);
    // SAFETY: test fixture uniquely owns the zone table and no guest CPU is running.
    let words = unsafe { *zone.record(record).ctx_mut() };
    let restored = restore_native_context(words, binding.address).expect("restored native context");
    assert_eq!(restored.fs_base, 0x1000);
    assert_eq!(restored.gs_base, 0x2000);

    // 4. Reject recycled record / root identity (zone-record reuse/admission error detection)
    // Recycled record incarnation defect
    let mut stale = ContextBinding {
        record: binding.record,
        address: binding.address,
    };
    stale.record.incarnation += 1;
    assert!(
        !admit_context(&zone, slot, &stale),
        "stale incarnation must be rejected"
    );

    // Wrong root identity defect
    let mut wrong_root = ContextBinding {
        record: binding.record,
        address: binding.address,
    };
    wrong_root.address.root = RootGpa::page_aligned(FrameGpa::new(0x70_0000)).unwrap();
    assert!(
        !admit_context(&zone, slot, &wrong_root),
        "mismatched root must be rejected"
    );
    assert_eq!(zone.installed_space(slot), 0, "refusal vacates occupancy");

    // Wrong MM identity defect
    let mut wrong_mm = ContextBinding {
        record: binding.record,
        address: binding.address,
    };
    wrong_mm.address.mm = MmGeneration::new(NonZeroU64::new(99).unwrap());
    assert!(
        !admit_context(&zone, slot, &wrong_mm),
        "wrong MM must be rejected"
    );

    // Re-admitting with valid binding restores space
    assert!(admit_context(&zone, slot, &binding));
    assert_eq!(zone.installed_space(slot), mm);

    // Closed space defect
    zone.release_space(slot);
    zone.spaces.close(space);
    assert!(
        !admit_context(&zone, slot, &binding),
        "closed space must be rejected"
    );
}

fn transport_program(op: u64) -> Vec<u8> {
    const TRANSPORT_WITNESS: u64 = 0xffff_ffff_ffff_ff20;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x48, 0xbf]); // mov rdi, op
    bytes.extend_from_slice(&op.to_le_bytes());
    bytes.extend_from_slice(&[0x48, 0xb8]); // mov rax, TRANSPORT_WITNESS
    bytes.extend_from_slice(&TRANSPORT_WITNESS.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x05]); // syscall into shared kernel witness
    bytes.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]); // mov rdi, rax; mov rax, OBSERVE_NATIVE
    bytes.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
    bytes.extend_from_slice(&[0x0f, 0x05]);
    bytes.extend_from_slice(&[0x0f, 0x0b]);
    bytes
}

#[test]
fn shared_kernel_transport_yield_and_fatal() {
    let yield_prog = transport_program(0);
    let fatal_prog = transport_program(1);
    let mut carrier =
        Cpl0Carrier::boot(&image(), [&yield_prog, &fatal_prog]).expect("real KVM + CPL0 image");
    let obs = carrier.observe(0).expect("yield should resume and succeed");
    assert_eq!(obs.result, 0);
    assert_eq!(obs.host_yields, 1);
    let fatal_err = carrier.observe(1).expect_err("fatal must exit with error");
    assert!(
        fatal_err.to_string().contains("CPL0 fatal exit"),
        "expected fatal exit, got {fatal_err}"
    );
}

fn context_program() -> Vec<u8> {
    const CONTEXT_WITNESS: u64 = 0xffff_ffff_ffff_ff30;
    let mut bytes = Vec::new();
    for op in [0_u64, 1_u64] {
        bytes.extend_from_slice(&[0x48, 0xbf]); // mov rdi, op
        bytes.extend_from_slice(&op.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xb8]); // mov rax, CONTEXT_WITNESS
        bytes.extend_from_slice(&CONTEXT_WITNESS.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]); // syscall into shared kernel witness
        bytes.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]); // mov rdi, rax; mov rax, OBSERVE_NATIVE
        bytes.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]);
    }
    bytes.extend_from_slice(&[0x0f, 0x0b]);
    bytes
}

#[test]
fn shared_kernel_context_stack_slot_and_thread_cpu() {
    let p0 = context_program();
    let p1 = context_program();
    let mut carrier = Cpl0Carrier::boot(&image(), [&p0, &p1]).expect("real KVM + CPL0 image");
    for task in 0..2 {
        let obs_stack = carrier.observe(task).expect("stack slot observation");
        assert_eq!(obs_stack.result, task as i64, "stack slot for task {task}");
        let obs_cpu = carrier.observe(task).expect("thread cpu observation");
        assert_eq!(obs_cpu.result, task as i64, "thread cpu for task {task}");
    }
}

fn interrupt_program() -> Vec<u8> {
    const INTERRUPT_WITNESS: u64 = 0xffff_ffff_ffff_ff40;
    let mut bytes = Vec::new();
    for (op, arg) in [
        (0_u64, 0_u64),       // frequency
        (1_u64, 0_u64),       // arm_timer(None)
        (1_u64, 100_000_u64), // arm_timer(Some(100_000))
        (3_u64, 0_u64),       // ack_interrupt (no interrupt pending => 0)
        (2_u64, 1_u64),       // send_wake to CPU 1 => 0
        (2_u64, 2_u64),       // no published CPU slot 2: refuse wake
    ] {
        bytes.extend_from_slice(&[0x48, 0xbe]); // mov rsi, arg
        bytes.extend_from_slice(&arg.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xbf]); // mov rdi, op
        bytes.extend_from_slice(&op.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0xb8]); // mov rax, INTERRUPT_WITNESS
        bytes.extend_from_slice(&INTERRUPT_WITNESS.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]); // syscall into shared kernel witness
        bytes.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]); // mov rdi, rax; mov rax, OBSERVE_NATIVE
        bytes.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x05]);
    }
    bytes.extend_from_slice(&[0x0f, 0x0b]); // ud2
    bytes
}

#[test]
fn shared_kernel_interrupt_leaves() {
    let p0 = interrupt_program();
    let p1 = interrupt_program();
    let mut carrier = Cpl0Carrier::boot_with_interrupts(&image(), [&p0, &p1])
        .expect("real KVM + CPL0 image with interrupts");
    let obs_freq = carrier.observe(0).expect("frequency observation");
    assert!(obs_freq.result > 0, "frequency must be non-zero");
    let obs_disarm = carrier.observe(0).expect("disarm timer observation");
    assert_eq!(obs_disarm.result, 0, "disarm timer succeeded");
    let obs_arm = carrier.observe(0).expect("arm timer observation");
    assert_eq!(obs_arm.result, 0, "arm timer succeeded");
    if carrier.has_tsc_deadline(0).expect("installed CPUID") {
        assert_eq!(
            carrier
                .lapic_register(0, 0x320)
                .expect("stopped local timer")
                & (3 << 17),
            1 << 18,
            "TSC deadline mode must use absolute TSC units"
        );
    } else {
        assert_eq!(
            carrier
                .lapic_register(0, 0x3e0)
                .expect("stopped timer divider")
                & 0b1111,
            0b1011,
            "calibrated APIC timer uses the measured undivided rate"
        );
    }
    let obs_ack = carrier.observe(0).expect("ack interrupt observation");
    assert_eq!(obs_ack.result, 0, "no pending interrupt acked");
    let obs_wake = carrier.observe(0).expect("send wake observation");
    assert_eq!(obs_wake.result, 0, "send wake to CPU 1 succeeded");
    let obs_unknown = carrier.observe(0).expect("unknown-slot wake observation");
    assert_eq!(obs_unknown.result, -1, "unknown CPU slot must be refused");
}
