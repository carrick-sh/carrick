//! Cross-boundary shared memory and futex synchronization tests.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs the test
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and runs
//! it under `RUST_TEST_THREADS=1`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use carrick_embed::{
    Carrier, ContainerId, EmbedError, ImageStore, PullPolicy, RunId, SharedBuffer,
    SharedBufferError,
};

static SHARED_CARRIER: std::sync::Mutex<Option<Carrier>> = std::sync::Mutex::new(None);

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

    let mut buf = SharedBuffer::new(4096).expect("allocate shared buffer");
    // Host writes greeting sentinel at offset 0
    let host_msg = b"HELLO_CARRIER";
    buf.as_mut_slice()[..host_msg.len()].copy_from_slice(host_msg);

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
    let guest_reply = &buf.as_slice()[..14];
    assert_eq!(
        guest_reply,
        b"GUEST_REPLY_OK",
        "host must see guest zero-copy mutation: got {:?}",
        String::from_utf8_lossy(guest_reply)
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

    let mut lease = buf.lease_with_witness(
        run_id,
        container_id,
        1,
        Arc::clone(&retired),
        Arc::clone(&current_gen),
    );

    // 1. While active, operations succeed
    assert!(lease.write_at(0, &[1, 2, 3, 4]).is_ok());
    let mut data = [0u8; 4];
    assert!(lease.read_at(0, &mut data).is_ok());
    assert_eq!(data, [1, 2, 3, 4]);

    // 2. Container retires
    retired.store(true, Ordering::Release);

    // 3. All operations fail closed
    assert!(matches!(
        lease.read_at(0, &mut data),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.write_at(0, &[5, 6, 7, 8]),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.as_slice(),
        Err(SharedBufferError::Retired { .. })
    ));
    assert!(matches!(
        lease.as_mut_slice(),
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

/// Shared futex pingpong latency benchmark: 100 rounds of bidirectional handoff crossing hypervisor boundary.
#[test]
fn shared_buffer_futex_pingpong_latency() {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return;
    };

    let buf = SharedBuffer::new(4096).expect("allocate shared buffer");
    let run_id = RunId::new("pingpong-test");
    let container_id = ContainerId::allocate();
    let lease = buf.lease(run_id, container_id, 1);

    // Offset 0: ping word (written by host, awaited by guest)
    // Offset 4: pong word (written by guest, awaited by host)
    lease
        .write_at(0, &0u32.to_ne_bytes())
        .expect("write ping initial");
    lease
        .write_at(4, &0u32.to_ne_bytes())
        .expect("write pong initial");

    const ROUNDS: u32 = 100;

    // Launch guest probe inside carrier container
    let container = carrier
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

    let guest_handle = thread::spawn(move || {
        let outcome = container.run_blocking();
        common::run_or_fail(outcome)
    });

    let start = Instant::now();
    for round in 1..=ROUNDS {
        // Host writes round to ping (offset 0) and wakes guest
        let ping_ptr = lease.as_ptr() as *mut AtomicU32;
        unsafe {
            (*ping_ptr).store(round, Ordering::Release);
        }
        let _ = lease.futex_wake(0, 1);

        // Host waits for guest to echo round on pong (offset 4)
        let pong_ptr = unsafe { (lease.as_ptr().add(4)) as *const AtomicU32 };
        while unsafe { (*pong_ptr).load(Ordering::Acquire) } != round {
            let _ = lease.futex_wait(4, round - 1, Some(Duration::from_millis(50)));
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
