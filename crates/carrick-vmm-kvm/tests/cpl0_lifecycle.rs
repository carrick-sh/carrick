//! Executing Linux clone/exit through the same neutral lifecycle owner.
//! No host callback answers clone, futex wait/wake, clear or exit. Host only
//! stocks issued identities and folds completed retirements while CPUs stop.
//! This bounded context fixture does not qualify production-pool exhaustion.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "common/physical_inventory.rs"]
mod physical_inventory;
use physical_inventory::physical_inventory;

use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_entry::OBSERVE_NATIVE;
use carrick_x86::cpl0_lifecycle::LIFECYCLE_DATA;
use std::path::PathBuf;

fn image() -> PathBuf {
    PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"))
}
fn mov(bytes: &mut Vec<u8>, opcode: &[u8], value: u64) {
    bytes.extend_from_slice(opcode);
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn program(index: u64) -> Vec<u8> {
    let mut p = Vec::new();
    mov(&mut p, &[0x48, 0xbb], LIFECYCLE_DATA + 0x180);
    p.extend_from_slice(&[0xf3, 0x44, 0x0f, 0x6f, 0x3b]); // parent's XMM15

    mov(&mut p, &[0x48, 0xbf], 0x003d_0f00 | 0x0100_0000); // RDI flags
    mov(&mut p, &[0x48, 0xbe], 0x3_0fe0 + index * 0x1_0000); // RSI child stack
    mov(&mut p, &[0x48, 0xba], LIFECYCLE_DATA); // RDX parent tid
    mov(&mut p, &[0x49, 0xba], LIFECYCLE_DATA + 8); // R10 child tid: x86 order
    mov(&mut p, &[0x49, 0xb8], LIFECYCLE_DATA + 0x100); // R8 TLS
    p.extend_from_slice(&[0xb8, 56, 0, 0, 0, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x0f, 0x84]);
    let branch = p.len();
    p.extend_from_slice(&0i32.to_le_bytes());
    p.extend_from_slice(&[0x48, 0x89, 0xc2]); // RDX clone result, expected tid
    mov(&mut p, &[0x48, 0xbf], LIFECYCLE_DATA + 8);
    p.extend_from_slice(&[
        0xbe, 128, 0, 0, 0, 0x45, 0x31, 0xd2, 0xb8, 202, 0, 0, 0, 0x0f, 0x05,
    ]);
    mov(&mut p, &[0x48, 0xbb], LIFECYCLE_DATA + 0x30);
    p.extend_from_slice(&[0xf3, 0x44, 0x0f, 0x7f, 0x3b]); // resumed parent's extended context
    p.extend_from_slice(&[0x48, 0x89, 0xc7]);
    mov(&mut p, &[0x48, 0xb8], OBSERVE_NATIVE);
    p.extend_from_slice(&[0x0f, 0x05, 0xe9]);
    let restart = p.len();
    p.extend_from_slice(&(-(restart as i32 + 4)).to_le_bytes());
    let child = p.len();
    p[branch..branch + 4].copy_from_slice(&((child - branch - 4) as i32).to_le_bytes());
    mov(&mut p, &[0x48, 0xbb], LIFECYCLE_DATA + 0x20);
    p.extend_from_slice(&[0xf3, 0x44, 0x0f, 0x7f, 0x3b, 0x45, 0x0f, 0x57, 0xff]);
    // Child writes inherited XMM15, then destroys it before exit. Parent restore
    // must use its own exact retained context, not the child's live registers.
    // Actual child loads its installed FS base and writes private-MM bytes.
    p.extend_from_slice(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0]);
    mov(&mut p, &[0x48, 0xbb], LIFECYCLE_DATA + 16);
    p.extend_from_slice(&[
        0x48, 0x89, 0x03, 0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    p
}
#[test]
fn x5_shared_clone_exit() {
    let a = program(0);
    let b = program(1);
    for births in [16, 64, 256] {
        let mut carrier = Cpl0Carrier::boot_lifecycle(physical_inventory(), &image(), [&a, &b])
            .expect("real CPL0 lifecycle binding");
        for round in 0..births {
            for index in 0..2 {
                let entry = carrier.stock_lifecycle(index).unwrap();
                let observation = carrier.observe(index).unwrap_or_else(|error| {
                    panic!(
                        "bounded clone/child/join/exit execution: {error:?}; lifecycle {:?}",
                        carrier.lifecycle_state(index)
                    )
                });
                assert_eq!(observation.result, 0);
                let state = carrier.lifecycle_state(index).unwrap();
                assert_eq!(state.births, round + 1);
                assert_eq!(state.retirements, round + 1);
                assert_eq!(state.wakes, round + 1);
                assert_eq!(state.live, 1);
                assert_eq!(
                    state.state,
                    Some((
                        entry.generation(),
                        carrick_el1_abi::EntryState::ExitedInZone
                    ))
                );
                assert_eq!(state.entries, 3 * (round + 1));
                assert_eq!(state.completions, state.entries);
                assert_eq!(state.forwards, 0);
                assert_eq!(state.words[0], 7);
                assert_eq!(state.words[1], 0);
                assert_eq!(state.words[2], 0xf500 + index as u64);
                let extended = u64::from_le_bytes([0x5a + index as u8; 8]);
                assert_eq!(
                    &state.words[4..8],
                    &[extended; 4],
                    "child inheritance and exact parent extended-context restoration"
                );
                let total = 2 * round + index as u64 + 1;
                assert_eq!(state.served, [total; 3]);
                let peer = carrier.lifecycle_state(1 - index).unwrap();
                assert_eq!(peer.live, 1);
                assert_eq!(
                    peer.words[2],
                    if index == 0 && round == 0 {
                        0
                    } else {
                        0xf500 + (1 - index) as u64
                    }
                );
                carrier.reap_lifecycle(index, entry).unwrap();
            }
        }
        println!(
            "X5 births={births} per MM; CPL0 entries={} completions={} forwards=0; production executor-pool binding remains unqualified",
            6 * births,
            6 * births
        );
    }
}
