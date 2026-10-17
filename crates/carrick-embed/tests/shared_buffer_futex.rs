//! Cross-boundary shared memory and futex synchronization tests.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs the test
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and runs
//! it under `RUST_TEST_THREADS=1`.
#![allow(clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use carrick_embed::{
    Carrier, ContainerId, ContainerResult, EmbedError, ImageStore, PullPolicy, RunId, SharedBuffer,
    SharedBufferError,
};

static SHARED_CARRIER: std::sync::Mutex<Option<Carrier>> = std::sync::Mutex::new(None);

const GUEST_DONE: u32 = 1 << 31;

// Publish container completion on the same futex the host awaits for pong.
// The guard also runs when the guest runner unwinds.
struct GuestCompletion {
    _buffer: SharedBuffer,
    pong_word: *const AtomicU32,
    pong_location: carrick_hal::SharedFutexLocation,
    futex: carrick_thread::platform_futex::SharedFutexTable,
}

// SAFETY: `_buffer` keeps the `MAP_SHARED` mapping alive for the lifetime of `GuestCompletion`,
// and `pong_word` points to the 4-byte aligned word at offset 4 inside that mapping.
unsafe impl Send for GuestCompletion {}

impl Drop for GuestCompletion {
    fn drop(&mut self) {
        let pong = unsafe { &*self.pong_word };
        pong.fetch_or(GUEST_DONE, Ordering::AcqRel);
        let _ = self.futex.table().wake(
            carrick_thread::platform_futex::carrier_shared_futex_key(self.pong_location),
            1,
        );
    }
}

fn fail_before_pong(guest: thread::JoinHandle<ContainerResult>, round: u32) -> ! {
    let when = if round == 1 {
        "first pong".to_owned()
    } else {
        format!("pong round {round}")
    };
    match guest.join() {
        Ok(result) => panic!(
            "guest exited {} before {when}: stderr={}",
            result.exit_code,
            result.stderr_utf8()
        ),
        Err(_) => panic!("guest runner panicked before {when}"),
    }
}

fn carrier_or_fail() -> Option<Carrier> {
    let mut guard = SHARED_CARRIER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(carrier) = guard.as_ref() {
        return Some(carrier.clone());
    }
    let carrier_res = Carrier::new();
    let not_entitlement = !matches!(carrier_res, Err(EmbedError::Entitlement));
    assert!(
        not_entitlement,
        "HV_DENIED (0xfae94007): this test executable lacks \
         com.apple.security.hypervisor. Run it through `just test-embed` \
         (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
         can never boot a guest."
    );
    assert!(
        carrier_res.is_ok(),
        "carrier create failed: {:?}",
        carrier_res.as_ref().err()
    );
    let carrier = carrier_res.ok()?;
    *guard = Some(carrier.clone());
    Some(carrier)
}

/// Zero-copy shared memory round-trip: host writes sentinel, guest reads and updates it.
#[test]
fn shared_buffer_host_write_guest_read_round_trip() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
    // Host writes greeting sentinel at offset 0
    let host_msg = b"HELLO_CARRIER";
    buf.write_from(0, host_msg).expect("write greeting");

    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .shared_buffer("bench", &buf)
        .command([
            "/bin/sh",
            "-c",
            "VAL=$(dd if=/dev/carrick/shm/bench bs=1 count=13 2>/dev/null); \
             if [ \"$VAL\" != \"HELLO_CARRIER\" ]; then \
                 echo \"unexpected value: '$VAL'\" >&2; \
                 exit 1; \
             fi; \
             printf \"GUEST_REPLY_OK\" | dd of=/dev/carrick/shm/bench seek=0 bs=1 count=14 conv=notrunc 2>/dev/null",
        ])
        .run_blocking();

    let result = common::run_or_fail(outcome);
    assert_eq!(
        result.exit_code,
        0,
        "guest script failed: stderr={}",
        result.stderr_utf8()
    );

    // Host reads the updated value written by guest
    let mut guest_reply = [0u8; 14];
    buf.read_into(0, &mut guest_reply)
        .expect("read guest reply");
    assert_eq!(
        &guest_reply,
        b"GUEST_REPLY_OK",
        "host must see guest zero-copy mutation: got {:?}",
        String::from_utf8_lossy(&guest_reply)
    );
}

/// Lease retirement fail-closed verification: operations after container termination are rejected.
#[test]
fn shared_buffer_lease_after_retirement_fails_closed() {
    let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
    let run_id = RunId::new("retirement-test");
    let container_id = ContainerId::allocate();

    let retired = Arc::new(AtomicBool::new(false));
    let current_gen = Arc::new(AtomicU64::new(1));

    let lease = buf.lease_with_witness(
        run_id,
        container_id,
        1,
        Arc::clone(&retired),
        Arc::clone(&current_gen),
        carrick_thread::platform_futex::SharedFutexTable::new(),
    );

    // 1. While active, operations succeed
    assert!(lease.write_from(0, &[1, 2, 3, 4]).is_ok());
    let mut data = [0u8; 4];
    assert!(lease.read_into(0, &mut data).is_ok());
    assert_eq!(data, [1, 2, 3, 4]);

    // 2. Container retires
    retired.store(true, Ordering::Release);

    // 3. All operations fail closed
    assert!(matches!(
        lease.read_into(0, &mut data),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.write_from(0, &[5, 6, 7, 8]),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.as_ptr(),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.as_mut_ptr(),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.futex_wait(0, 0, Some(Duration::from_millis(10))),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.futex_wake(0, 1),
        Err(SharedBufferError::Retired { .. })
    ));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PongObservation {
    CompletedRound,
    GuestExitedEarly,
    NeedsWait(u32),
}

fn observe_pong_round(
    lease: &carrick_embed::SharedBufferLease,
    pong: &carrick_embed::SharedAtomicU32,
    pong_word: *const AtomicU32,
    round: u32,
    before_retirement_check: impl FnOnce(),
) -> PongObservation {
    let pong_value = match pong.load(Ordering::Acquire) {
        Ok(value) => value,
        Err(SharedBufferError::Retired { .. }) => unsafe { (*pong_word).load(Ordering::Acquire) },
        Err(error) => panic!("read pong round {round} failed: {error}"),
    };
    if pong_value & !GUEST_DONE == round {
        return PongObservation::CompletedRound;
    }
    before_retirement_check();
    if pong_value & GUEST_DONE != 0 || lease.is_retired() {
        let final_pong = unsafe { (*pong_word).load(Ordering::Acquire) };
        if final_pong & !GUEST_DONE == round {
            return PongObservation::CompletedRound;
        }
        return PongObservation::GuestExitedEarly;
    }
    PongObservation::NeedsWait(pong_value)
}

/// Deterministic witness for the final-round preemption window: if the host reads `pong = 99`
/// via a live lease and is preempted while the guest writes `pong = 100`, sets `GUEST_DONE`,
/// and retires the lease before the host checks `lease.is_retired()`, re-loading `pong` raw
/// once recognizes the completed round instead of reporting a false early exit.
#[test]
fn pong_observation_reloads_when_retirement_races_final_store() {
    let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
    let retired = Arc::new(AtomicBool::new(false));
    let current_gen = Arc::new(AtomicU64::new(1));
    let lease = buf.lease_with_witness(
        RunId::new("pong-retirement-race"),
        ContainerId::allocate(),
        1,
        Arc::clone(&retired),
        current_gen,
        carrick_thread::platform_futex::SharedFutexTable::new(),
    );

    let pong = lease.atomic_u32(4).expect("pong word");
    pong.store(99, Ordering::Release).expect("seed round 99");
    let pong_word = unsafe {
        lease
            .as_ptr()
            .expect("validated base pointer")
            .add(4)
            .cast::<AtomicU32>()
    };

    let outcome = observe_pong_round(&lease, &pong, pong_word, 100, || {
        unsafe {
            (*pong_word).store(100 | GUEST_DONE, Ordering::Release);
        }
        retired.store(true, Ordering::Release);
    });
    assert_eq!(outcome, PongObservation::CompletedRound);

    // Conversely, if the guest genuinely exits before writing round 100, the reload
    // still observes 99 and classifies the retirement as an early guest exit.
    retired.store(false, Ordering::Release);
    pong.store(99, Ordering::Release).expect("reset round 99");
    let early_exit = observe_pong_round(&lease, &pong, pong_word, 100, || {
        unsafe {
            (*pong_word).fetch_or(GUEST_DONE, Ordering::AcqRel);
        }
        retired.store(true, Ordering::Release);
    });
    assert_eq!(early_exit, PongObservation::GuestExitedEarly);
}

/// Shared futex pingpong latency benchmark: 100 rounds of bidirectional handoff crossing hypervisor boundary.
#[test]
fn shared_buffer_futex_pingpong_latency() {
    let _guest = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(90));
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
    const ROUNDS: u32 = 100;
    const PONG_DEADLINE: Duration = Duration::from_secs(30);

    let builder = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command([
            "/opt/carrick/interceptor-probe",
            "futex-pingpong",
            "/dev/carrick/shm/bench",
            "100",
        ])
        .vfs_mount(
            "/opt/carrick",
            Box::new(common::interceptor_probe_vfs(None)),
        )
        .shared_buffer("bench", &buf);
    let prepared = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build image-resolution runtime")
        .block_on(builder.prepare())
        .expect("prepare pingpong container");
    let lease = prepared
        .shared_buffer_lease("bench")
        .expect("lease for prepared pingpong container");

    // Offset 0: ping word (written by host, awaited by guest)
    // Offset 4: pong word (written by guest, awaited by host)
    lease
        .write_from(0, &0u32.to_ne_bytes())
        .expect("write ping initial");
    lease
        .write_from(4, &0u32.to_ne_bytes())
        .expect("write pong initial");

    let base_ptr = lease.as_ptr().expect("validated base pointer");
    let pong_word = unsafe { base_ptr.add(4).cast::<AtomicU32>() };
    let pong_location = lease.shared_futex_location(4).expect("pong location");
    let completion = GuestCompletion {
        _buffer: buf.clone(),
        pong_word,
        pong_location,
        futex: carrier.shared_futex().clone(),
    };
    let guest_handle = thread::spawn(move || {
        let _completion = completion;
        let outcome = prepared.execute();
        common::run_or_fail(outcome)
    });

    let start = Instant::now();
    let deadline = start + PONG_DEADLINE;
    let pong = lease.atomic_u32(4).expect("pong word");
    let ping = lease.atomic_u32(0).expect("ping word");
    for round in 1..=ROUNDS {
        // Host writes round to ping (offset 0) and wakes guest. If the guest
        // already exited and retired the lease before this round, report its exit.
        match ping.store(round, Ordering::Release) {
            Ok(()) => {}
            Err(SharedBufferError::Retired { .. }) => fail_before_pong(guest_handle, round),
            Err(error) => panic!("write ping round {round} failed: {error}"),
        }
        match lease.futex_wake(0, 1) {
            Ok(_) | Err(SharedBufferError::Retired { .. }) => {}
            Err(error) => panic!("futex wake for ping round {round} failed: {error}"),
        }

        // Host waits for guest to echo round on pong (offset 4).
        // `prepared.execute()` retires the lease as soon as the container finishes,
        // which can race the final round's pong read or an early guest exit.
        loop {
            let pong_value = match observe_pong_round(&lease, &pong, pong_word, round, || {}) {
                PongObservation::CompletedRound => break,
                PongObservation::GuestExitedEarly => fail_before_pong(guest_handle, round),
                PongObservation::NeedsWait(value) => value,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for pong round {round}"
            );
            match lease.futex_wait(4, pong_value, Some(remaining)) {
                Ok(())
                | Err(SharedBufferError::TimedOut)
                | Err(SharedBufferError::Retired { .. }) => {}
                Err(error) => panic!("futex wait for pong round {round} failed: {error}"),
            }
        }
    }

    let elapsed = start.elapsed();
    let guest_res = guest_handle.join().expect("join guest runner thread");
    assert_eq!(
        guest_res.exit_code,
        0,
        "guest pingpong failed: stderr={}",
        guest_res.stderr_utf8()
    );

    let per_round_us = elapsed.as_micros() as f64 / (ROUNDS as f64);
    eprintln!(
        "cross-boundary host-guest shared futex pingpong: {} rounds in {:.2?}, {:.2} µs/round",
        ROUNDS, elapsed, per_round_us
    );

    // Assert round-trip latency ceiling across hypervisor boundary (5 ms / round in debug build)
    assert!(
        per_round_us < 5000.0,
        "cross-boundary shared futex pingpong round-trip {per_round_us} µs exceeds 5000 µs ceiling"
    );
}
