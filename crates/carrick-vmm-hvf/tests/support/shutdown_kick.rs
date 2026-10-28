//! Raw HVF qualification, deliberately bypassing Carrick's kick/IRQ adapters.
//! A timeout is a failed qualification, never recovered with another kick.
use applevisor_sys as hv;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(2);
const CHILD: &str = "CARRICK_HVF_EXIT_QUALIFICATION_CHILD";
const GPA: u64 = 0x10000;
const SIZE: usize = 0x4000;

/// The child owns the VM. Kill/reap it on failure: joining a thread blocked
/// in hv_vcpu_run would turn a failed qualification into another hang.
fn isolated(name: &str, body: fn()) {
    if std::env::var_os(CHILD).is_some() {
        body();
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", name, "--nocapture"])
        .env(CHILD, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn signed qualification child");
    let pid = i32::try_from(child.id()).unwrap();
    let stdout = child.stdout.take().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (read_tx, read_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            println!("{line}");
            if line.contains("HVF_EXIT_QUALIFICATION RUN_ENTER") {
                let _ = started_tx.send(());
            }
        }
        let _ = read_tx.send(());
    });
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = done_tx.send(child.wait());
    });
    let started = started_rx.recv_timeout(Duration::from_secs(4));
    let start = Instant::now();
    let outcome = if started.is_ok() {
        done_rx.recv_timeout(LIMIT)
    } else {
        done_rx
            .try_recv()
            .map_err(|_| mpsc::RecvTimeoutError::Timeout)
    };
    let timed_out = outcome.is_err();
    let status = match outcome {
        Ok(status) => status,
        Err(_) => {
            eprintln!(
                "HVF_EXIT_QUALIFICATION TIMEOUT started={} elapsed={:?}; no returned exit reason",
                started.is_ok(),
                start.elapsed()
            );
            // SAFETY: this is our unreaped child; its PID cannot be reused.
            let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
            done_rx
                .recv_timeout(LIMIT)
                .unwrap_or_else(|error| panic!("SIGKILL rc={rc}: {error}"))
        }
    };
    waiter.join().unwrap();
    read_rx
        .recv_timeout(LIMIT)
        .expect("child output closed after reap");
    reader.join().unwrap();
    assert!(
        !timed_out && status.unwrap().success(),
        "{name}: qualification failed"
    );
}

/// One host page with a code loop and a release/acquire guest-entered marker.
/// Bounded observation of the marker is qualification instrumentation only:
/// production shutdown does not poll, and this test sends exactly one kick.
fn qualify(before_entry: bool) {
    // SAFETY: fresh subprocess, one VM and one owner-thread vCPU. Every SDK
    // result is checked, including entitlement refusal (never a skip).
    unsafe {
        assert_eq!(
            hv::hv_vm_create(std::ptr::null_mut()),
            0,
            "hv_vm_create (HV_DENIED is a failure)"
        );
        let memory = libc::mmap(
            std::ptr::null_mut(),
            SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        );
        assert_ne!(memory, libc::MAP_FAILED);
        // mov x0,#1; adr x1,marker; stlr x0,[x1]; then WFI or b .
        // Raw-VM WFI can trap: the in-run mirror must spin until kicked.
        // The marker at +0x100 proves the mirror kick follows guest execution.
        let code = [
            0xd2800020_u32,
            0x100007e1,
            0xc89ffc20,
            if before_entry { 0xd503207f } else { 0x14000000 },
            0x17ffffff,
        ];
        for (i, instruction) in code.into_iter().enumerate() {
            memory.cast::<u32>().add(i).write(instruction);
        }
        let marker = memory.cast::<u8>().add(0x100).cast::<AtomicU64>();
        marker.write(AtomicU64::new(0));
        assert_eq!(
            hv::hv_vm_map(
                memory,
                GPA,
                SIZE,
                hv::HV_MEMORY_READ | hv::HV_MEMORY_WRITE | hv::HV_MEMORY_EXEC
            ),
            0
        );
        let mut vcpu = 0;
        let mut exit = std::ptr::null();
        assert_eq!(
            hv::hv_vcpu_create(&mut vcpu, &mut exit, std::ptr::null_mut()),
            0
        );
        assert_eq!(hv::hv_vcpu_set_reg(vcpu, hv::hv_reg_t::PC, GPA), 0);
        // EL1h, IRQ/FIQ masked, translation off. The before-entry latch
        // must return CANCELED before executing this raw VM's WFI.
        assert_eq!(hv::hv_vcpu_set_reg(vcpu, hv::hv_reg_t::CPSR, 0x3c5), 0);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (kick_tx, kick_rx) = mpsc::channel();
        // Address only; the mapping remains live until the kicker has joined.
        let marker_address = marker as usize;
        let entered = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&entered);
        let kicker = std::thread::spawn(move || {
            ready_rx.recv_timeout(LIMIT).expect("owner ready");
            if !before_entry {
                let deadline = Instant::now() + LIMIT;
                // There is no host notification instruction in this tiny raw
                // guest. Observe its single store with a bounded diagnostic
                // loop, rather than assuming that a host sleep proves entry.
                while (&*(marker_address as *const AtomicU64)).load(Ordering::Acquire) == 0 {
                    assert!(Instant::now() < deadline, "guest never reached spin loop");
                    std::thread::yield_now();
                }
                observed.store(1, Ordering::Release);
            }
            let rc = hv::hv_vcpus_exit(&vcpu, 1);
            kick_tx.send(rc).unwrap();
        });
        ready_tx.send(()).unwrap();
        if before_entry {
            assert_eq!(
                kick_rx
                    .recv_timeout(LIMIT)
                    .expect("pre-entry kick completed"),
                0
            );
        }
        println!("HVF_EXIT_QUALIFICATION RUN_ENTER before_entry={before_entry}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let start = Instant::now();
        // Independent process watchdog bounds a stuck run without delivering
        // a second kick (which would invalidate the answer being measured).
        let rc = hv::hv_vcpu_run(vcpu);
        let elapsed = start.elapsed();
        let reason = (*exit).reason;
        eprintln!(
            "HVF_EXIT_QUALIFICATION before_entry={before_entry} rc={rc:#x} reason={reason:?} elapsed={elapsed:?}"
        );
        assert_eq!(rc, 0);
        assert!(elapsed < LIMIT, "run exceeded {LIMIT:?}: {elapsed:?}");
        assert_eq!(reason, hv::hv_exit_reason_t::CANCELED);
        if !before_entry {
            assert_eq!(
                entered.load(Ordering::Acquire),
                1,
                "mirror kick preceded guest entry"
            );
            assert_eq!(
                kick_rx.recv_timeout(LIMIT).expect("in-run kick completed"),
                0
            );
        }
        kicker.join().unwrap();
        assert_eq!(hv::hv_vcpu_destroy(vcpu), 0);
        assert_eq!(hv::hv_vm_unmap(GPA, SIZE), 0);
        assert_eq!(libc::munmap(memory, SIZE), 0);
        assert_eq!(hv::hv_vm_destroy(), 0);
    }
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_shutdown_kick_before_entry() {
    isolated(
        "shutdown_kick::trap_engine_hvf_shutdown_kick_before_entry",
        || qualify(true),
    );
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf-trap-engine"]
fn trap_engine_hvf_shutdown_kick_in_run() {
    isolated(
        "shutdown_kick::trap_engine_hvf_shutdown_kick_in_run",
        || qualify(false),
    );
}
