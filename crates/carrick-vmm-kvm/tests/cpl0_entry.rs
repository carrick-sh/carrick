//! Executing KVM bindings for kernel.el1.task-load-entry,
//! kernel.syscall.captured-stack, kernel.vcpu.kick-el0-boundary and lifecycle
//! control-slot ownership. Linux set_robust_list(2): length 24 returns 0;
//! any other length returns EINVAL(22), preserving the previous head.
//! Budgets: one entry/completion per call, one publication per success,
//! zero semantic host forwards. Control observation/kicks are separate.
//! Missing KVM or an image is a failure; no Docker, retries or timing claims.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_entry::OBSERVE_NATIVE;
use std::path::PathBuf;

fn image() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0")
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
