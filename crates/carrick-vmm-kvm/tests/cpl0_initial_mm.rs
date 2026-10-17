//! Live KVM witness: a static x86 ELF enters through the shared CPL0 MM owner.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]

#[path = "common/physical_inventory.rs"]
mod physical_inventory;
use physical_inventory::physical_inventory;

use carrick_mem::x86_initial_image::prepare_x86_elf;
use carrick_vmm_kvm::cpl0_boot::{Cpl0Carrier, InitialReservationLimits, InitialTaskBinding};
#[path = "common/kvm_pool_fixture.rs"]
mod kvm_pool_fixture;
use carrick_x86::cpl0_entry::OBSERVE_INITIAL_MM;
use kvm_pool_fixture::{run_pool_fixture, run_pool_fixture_with};
use std::path::PathBuf;

const ELF_X86_64_MACHINE: u16 = 62;
const ELF_LOAD_VA: u64 = 0x400000;
const X86_SYS_WRITE: u8 = 1;
const X86_SYS_EXIT_GROUP: u8 = 231;

fn native_exit_fixture(name: &str) -> Vec<u8> {
    native_exit_fixture_with_flags(name, &[])
}

fn native_exit_fixture_with_flags(name: &str, flags: &[&str]) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("fixture directory");
    let output = dir.path().join("guest");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let compiled = std::process::Command::new("timeout")
        .args([
            "10",
            "cc",
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
        ])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(&output)
        .output()
        .expect("assemble native witness");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::read(output).expect("fixture ELF")
}

fn native_exit_workers(
    elf: &[u8],
) -> (
    carrick_vmm_kvm::cpl0_boot::ProductionWorkerParts,
    carrick_el1_abi::El1TaskId,
) {
    let program = carrick_mem::elf::ElfProgram::load(elf, ELF_X86_64_MACHINE, &|_| None)
        .expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    let extent = Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("extent");
    let mut carrier = Cpl0Carrier::boot_production(physical_inventory(), extent).expect("real KVM");
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let issued = dispatcher.capture_one_task_context().expect("issued root");
    carrier
        .bind_initial_task_identity(InitialTaskBinding {
            task: issued.task().key(),
            mm: carrick_guest_arch::MmGeneration::new(issued.shared().mm().id().nonzero()),
            thread: carrick_sched_core::ThreadIdentity {
                tid: issued.thread().key().tid.raw() as u64,
                serial: issued.thread().key().serial.raw(),
                mm: 0,
                file_table: issued.resources().files().id().raw(),
                generation: 1,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("issued root binding");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("guest MM");
    assert!(
        carrier.initial_thread_custody(),
        "actual initial native record"
    );
    (
        carrier.into_worker_parts(128).expect("physical workers"),
        carrick_el1_abi::El1TaskId::from_linux_tid(issued.thread().key().tid.raw()),
    )
}

fn run_to_marker(
    cpu: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
    task: carrick_guest_arch::TaskIdentity,
    expected: u8,
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
) {
    use carrick_guest_mem::GuestMemory;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    for _ in 0..128 {
        let exit = cpu
            .fixture_run_loaded(task)
            .expect("native runtime progress")
            .exit;
        match exit {
            CarrierRunExit::SyscallTrap => {
                let ((bytes, fork_result), token) = cpu
                    .capture_forward(task, |venue, frame| {
                        assert_eq!(frame.rax, 1, "only the rendezvous write may cross");
                        assert_eq!((frame.rdi, frame.rdx), (1, 1));
                        Ok((
                            venue.read_bytes_raw(frame.rsi, 1).expect("marker byte"),
                            frame.r12 as i32,
                        ))
                    })
                    .expect("real write crossing");
                assert!(
                    expected == 0 || fork_result > 0,
                    "guest fork result: {fork_result}; refusal {:?}; stock {:?}",
                    factory.fork_admission_refusal(),
                    factory.fork_stock_counters()
                );
                assert_eq!(
                    bytes,
                    [expected],
                    "guest assertions must reach the next marker"
                );
                cpu.complete_forward(task, token, 1)
                    .expect("write completion");
                return;
            }
            CarrierRunExit::PhysicalDoorbell { .. } => {
                let outcome = cpu
                    .service_physical_doorbell(task, &exit, |_, _| {
                        panic!("unexpected completed host work before marker")
                    })
                    .expect("physical service");
                assert!(
                    outcome.is_none(),
                    "guest exited before marker {expected}: {outcome:?}"
                );
            }
            CarrierRunExit::Kick => {}
            other => panic!("unexpected native exit: {other:?}"),
        }
    }
    panic!("marker exit budget");
}

fn run_until_wait_enrolled(
    cpu: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
    task: carrick_guest_arch::TaskIdentity,
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    tid: carrick_el1_abi::El1TaskId,
    peer: bool,
) {
    run_until_wait_enrolled_with_boundary(cpu, task, factory, tid, peer, false);
}

fn run_until_wait_enrolled_with_boundary(
    cpu: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
    task: carrick_guest_arch::TaskIdentity,
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    tid: carrick_el1_abi::El1TaskId,
    peer: bool,
    idle_boundary: bool,
) {
    use carrick_hal::VcpuKick;
    use carrick_sched_core::Claim;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
    let stopped = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let claim = factory
                    .fixture_native_wait_state(tid)
                    .expect("native enrollment")
                    .0;
                if matches!(claim, Claim::Parked { .. })
                    && (!idle_boundary
                        || factory
                            .fixture_native_cpu_idle(carrick_guest_arch::CpuId::new(u32::from(
                                peer,
                            )))
                            .expect("idle enrollment boundary"))
                {
                    kick.kick();
                    return true;
                }
                if stopped.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    kick.kick();
                    return false;
                }
                std::thread::yield_now();
            }
        });
        let exit = if peer {
            cpu.fixture_run_idle_peer().expect("enroll peer wait")
        } else {
            cpu.fixture_run_until_native_kick(task)
                .expect("enroll actual wait")
        };
        stopped.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            watcher.join().expect("bounded enrollment watcher"),
            "wait must enroll before retirement completes"
        );
        assert_eq!(exit, CarrierRunExit::Kick);
    });
}

fn run_idle_peer_until_kick(peer: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease) {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    for _ in 0..128 {
        match peer.fixture_run_idle_peer().expect("idle peer progress") {
            CarrierRunExit::Kick => return,
            exit @ CarrierRunExit::PhysicalDoorbell { .. } => {
                assert!(
                    peer.service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("idle peer physical service")
                        .is_none()
                );
            }
            other => panic!("unexpected idle peer exit: {other:?}"),
        }
    }
    panic!("idle peer kick budget");
}

#[test]
fn native_runtime_wait_wakes_once_only_after_real_mm_retirement() {
    use carrick_sched_core::Claim;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_exit_order.S");
    let (parts, root_tid) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory();
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let newborn_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 2);
    let mut parent = factory.claim(0).expect("root executor");
    let mut child = factory.claim(1).expect("idle peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place child on peer");
    let retiring = (0..128)
        .find_map(|_| {
            let exit = child.fixture_run_idle_peer().expect("child on idle peer");
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                Some(exit)
            } else {
                assert!(
                    child
                        .service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("peer physical service")
                        .is_none()
                );
                None
            }
        })
        .expect("real retire_mm must cross before exit notification");
    let (_, _, wakes_before) = factory
        .fixture_native_wait_state(root_tid)
        .expect("parent record");
    // This marker follows actual wait4(WNOHANG)==0 and a successful fork.
    // Retirement is still held at its stopped physical crossing.
    run_to_marker(&mut parent, task, 2, &factory);
    factory
        .fixture_place_native_thread(newborn_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place sibling on peer");
    assert!(
        factory
            .fork_admission_refusal()
            .expect("admission evidence")
            .is_none()
    );
    run_until_wait_enrolled(&mut parent, task, &factory, root_tid, false);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("pending wait");
    assert!(matches!(claim, Claim::Parked { .. }));
    assert!(
        matches!(claim, Claim::Parked { seq: 1 }),
        "one wait enrollment: {claim:?}"
    );
    assert_eq!(
        wakes, wakes_before,
        "pending retirement cannot wake the waiter"
    );
    assert!(
        child
            .service_idle_peer_doorbell(&retiring, |_, _| {})
            .expect("retire physical MM")
            .is_none()
    );
    // Resume retire_mm to publish slot absence, then runtime readiness/channel.
    // Stop at the next sibling retirement, which has not published a wake.
    let next_retire = (0..128)
        .find_map(|_| {
            let exit = child.fixture_run_idle_peer().expect("finish child exit");
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                Some(exit)
            } else {
                assert!(
                    child
                        .service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("peer completion")
                        .is_none()
                );
                None
            }
        })
        .expect("sibling remains stopped at retirement");
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("completed wait");
    assert!(
        matches!(claim, Claim::Queued { .. }),
        "real waiter must be runnable: {claim:?}"
    );
    assert_eq!(
        wakes,
        wakes_before + 1,
        "one exit publishes exactly one wake"
    );
    run_to_marker(&mut parent, task, 3, &factory);
    assert_eq!(
        factory
            .fixture_native_wait_state(root_tid)
            .expect("resumed wait")
            .2,
        wakes_before + 1
    );
    drop(next_retire);
}

#[test]
fn work_port_services_bound_tasks_on_loaded_and_idle_peer_lanes() {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_exit_order.S");
    let (parts, root_tid) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory();
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("idle peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);

    factory
        .fixture_mark_current_host_work(carrick_guest_arch::CpuId::new(0))
        .expect("publish root work");
    let mut loaded_deliveries = Vec::new();
    for _ in 0..128 {
        let exit = parent
            .fixture_run_loaded(task)
            .expect("loaded boundary")
            .exit;
        if let CarrierRunExit::PhysicalDoorbell { port, .. } = exit {
            parent
                .service_physical_doorbell(task, &exit, |served, pending| {
                    loaded_deliveries.push((served, pending));
                })
                .expect("loaded service");
            if port == carrick_x86::cpl0_entry::WORK_PORT {
                break;
            }
        }
    }
    assert_eq!(loaded_deliveries.len(), 1);
    assert!(loaded_deliveries[0].1, "loaded task's host work delivered");

    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place child on peer");
    // Enter once to bind the child, then publish a host wake against that
    // exact task while the vCPU is stopped at a real physical doorbell.
    let first = peer.fixture_run_idle_peer().expect("bind idle peer child");
    assert!(matches!(first, CarrierRunExit::PhysicalDoorbell { .. }));
    peer.service_idle_peer_doorbell(&first, |_, _| {})
        .expect("first peer service");
    factory
        .fixture_mark_current_host_work(carrick_guest_arch::CpuId::new(1))
        .expect("publish peer work");
    let mut idle_deliveries = Vec::new();
    for _ in 0..128 {
        let exit = peer.fixture_run_idle_peer().expect("idle peer boundary");
        if let CarrierRunExit::PhysicalDoorbell { port, .. } = exit {
            peer.service_idle_peer_doorbell(&exit, |served, pending| {
                idle_deliveries.push((served, pending));
            })
            .expect("idle peer service");
            if port == carrick_x86::cpl0_entry::WORK_PORT {
                break;
            }
        }
    }
    assert_eq!(idle_deliveries.len(), 1);
    assert!(idle_deliveries[0].1, "idle peer's host work delivered");
}

fn peer_retirement(
    peer: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
) -> carrick_vmm_kvm::carrier_cpu::CarrierRunExit {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    (0..128)
        .find_map(|_| {
            let exit = peer
                .fixture_run_idle_peer()
                .expect("child runtime progress");
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                Some(exit)
            } else {
                assert!(
                    peer.service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("physical service")
                        .is_none()
                );
                None
            }
        })
        .expect("child must reach actual MM retirement")
}

fn native_autoreap_waits_for_every_mm(flags: &[&str]) {
    use carrick_hal::VcpuKick;
    use carrick_sched_core::Claim;
    let elf = native_exit_fixture_with_flags("native_autoreap_exit.S", flags);
    let (parts, root_tid) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory();
    let first_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let second_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 2);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load parent");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_pin_native_thread(first_tid, carrick_guest_arch::CpuId::new(1))
        .expect("first child on peer");
    let first_retire = peer_retirement(&mut peer);
    // The parent forks successfully while its first child is retiring.
    run_to_marker(&mut parent, task, 2, &factory);
    factory
        .fixture_pin_native_thread(second_tid, carrick_guest_arch::CpuId::new(1))
        .expect("second child on peer");
    assert!(
        factory
            .fork_admission_refusal()
            .expect("fork evidence")
            .is_none()
    );
    run_until_wait_enrolled_with_boundary(&mut parent, task, &factory, root_tid, false, true);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("first wait");
    assert_eq!(claim, Claim::Parked { seq: 1 });
    assert_eq!(wakes, 0, "pending MM cannot wake wait");
    assert!(matches!(
        factory
            .fixture_native_wait_state(second_tid)
            .expect("peer-bound second child")
            .0,
        Claim::Queued { slot, .. } if slot == carrick_sched_core::SlotId::new(1)
    ));
    assert!(
        peer.service_idle_peer_doorbell(&first_retire, |_, _| {})
            .expect("first MM retirement")
            .is_none()
    );
    let second_retire = peer_retirement(&mut peer);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("first completion");
    assert!(matches!(claim, Claim::Queued { .. }));
    assert_eq!(wakes, 1);
    // A wake for the first child is insufficient: wait(-1) must enroll again
    // instead of returning ECHILD while the second child's MM is still charged.
    run_until_wait_enrolled_with_boundary(&mut parent, task, &factory, root_tid, false, true);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("remaining child");
    assert_eq!(claim, Claim::Parked { seq: 2 });
    assert_eq!(wakes, 1);
    assert!(
        peer.service_idle_peer_doorbell(&second_retire, |_, _| {})
            .expect("last MM retirement")
            .is_none()
    );
    // Stop only after the exit lane reaches idle, including its real wake IPI.
    // A queued claim alone precedes finish_wake and is not a safe stop boundary.
    // Neither observer changes the wait population or publishes a wake.
    let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
    let stopped = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let (claim, _, wakes) = factory
                    .fixture_native_wait_state(root_tid)
                    .expect("completion census");
                if matches!(claim, Claim::Queued { .. })
                    && wakes == 2
                    && factory
                        .fixture_native_cpu_idle(carrick_guest_arch::CpuId::new(1))
                        .expect("completed exit boundary")
                {
                    kick.kick();
                    return true;
                }
                if stopped.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    kick.kick();
                    return false;
                }
                std::thread::yield_now();
            }
        });
        run_idle_peer_until_kick(&mut peer);
        stopped.store(true, std::sync::atomic::Ordering::Release);
        assert!(watcher.join().expect("bounded completion observer"));
    });
    // Actual wait returns -10 only now, followed by another successful fork.
    run_to_marker(&mut parent, task, 3, &factory);
    run_to_marker(&mut parent, task, 4, &factory);
    assert!(
        factory
            .fork_admission_refusal()
            .expect("final fork evidence")
            .is_none()
    );
    let stock = factory.fork_stock_counters().expect("stock census");
    assert_eq!(stock.capacity_refusals, 0);
    assert_eq!(stock.retire_refusals, 0);
    assert_eq!(
        factory
            .fixture_native_wait_state(root_tid)
            .expect("resumed wait")
            .2,
        2
    );
}

#[test]
fn native_nocldwait_blocks_until_every_child_mm_retires() {
    native_autoreap_waits_for_every_mm(&[]);
}

#[test]
fn native_sigign_blocks_until_every_child_mm_retires() {
    native_autoreap_waits_for_every_mm(&["-DIGNORE_SIGCHLD"]);
}

#[test]
fn child_born_on_idle_peer_can_fault_and_retire_on_root_executor() {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_peer_birth.S");
    let (parts, root_tid) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory();
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let newborn_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 2);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("idle peer");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place child on peer");
    // CPU 1 runs the first child and performs the grandchild's real fork
    // loan and commit. CPU 0 stays stopped at the parent's marker.
    let mut stock_crossings = 0;
    for _ in 0..128 {
        let exit = peer.fixture_run_idle_peer().expect("fork on idle peer");
        if matches!(
            exit,
            CarrierRunExit::PhysicalDoorbell {
                port: carrick_el1_abi::FORK_STOCK_PORT,
                ..
            }
        ) {
            stock_crossings += 1;
        }
        assert!(
            peer.service_idle_peer_doorbell(&exit, |_, _| {})
                .expect("peer fork service")
                .is_none()
        );
        if stock_crossings == 2 {
            break;
        }
    }
    assert_eq!(
        stock_crossings, 2,
        "loan and commit must both occur on CPU 1"
    );
    let peer_marker = (0..128)
        .find_map(|_| {
            let exit = peer.fixture_run_idle_peer().expect("peer fork completion");
            if exit == CarrierRunExit::SyscallTrap {
                Some(exit)
            } else {
                assert!(
                    peer.service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("peer physical completion")
                        .is_none()
                );
                None
            }
        })
        .expect("peer parent marker");
    assert_eq!(
        peer.fixture_idle_peer_write(&peer_marker)
            .expect("peer stdout"),
        [2]
    );
    factory
        .fixture_place_native_thread(newborn_tid, carrick_guest_arch::CpuId::new(0))
        .expect("migrate peer-born child to root executor");
    run_until_wait_enrolled(&mut peer, task, &factory, child_tid, true);
    // The newborn is queued on CPU 0; its parent enrolled wait4 on CPU 1.
    // CPU 0 retains its root task lease as it schedules the grandchild.
    let mut root_grants = 0;
    let grandchild_retire = (0..128)
        .find_map(|_| {
            let stopped = parent
                .fixture_run_loaded(task)
                .expect("peer-born child on root executor");
            let exit = stopped.exit;
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                assert_ne!(
                    stopped.state.as_ref().unwrap().binding().task(),
                    task,
                    "physical image must belong to the grandchild"
                );
                Some(exit)
            } else {
                if matches!(
                    exit,
                    CarrierRunExit::PhysicalDoorbell {
                        port: carrick_x86::cpl0_entry::OWNER_GRANT_PORT,
                        ..
                    }
                ) {
                    root_grants += 1;
                }
                assert!(
                    parent
                        .service_physical_doorbell(task, &exit, |_, _| {
                            panic!("unexpected completed host work during grandchild retirement")
                        })
                        .expect("registered migrated MM physical service")
                        .is_none()
                );
                None
            }
        })
        .expect("grandchild retirement on CPU 0");
    assert!(
        root_grants > 0,
        "grandchild private first-touch requires physical grant"
    );
    assert!(
        parent
            .service_physical_doorbell(task, &grandchild_retire, |_, _| {
                panic!("unexpected completed host work during grandchild retirement")
            })
            .expect("grandchild MM retirement")
            .is_none()
    );
    let stock = factory
        .fork_stock_counters()
        .expect("retired grandchild stock");
    assert_eq!(stock.quarantined_children, 1);
    assert_eq!(stock.retire_refusals, 0);
    // The binding witness ends at the authenticated physical retirement.
    // Both vCPUs are stopped; dropping the carrier reclaims the remaining graph.
}

#[test]
fn initial_root_uses_issued_thread_and_file_table_identity() {
    fn assert_send<T: Send>() {}
    assert_send::<carrick_vmm_kvm::cpl0_boot::ProductionWorkerParts>();
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("initial grant extent");
    let mut carrier =
        Cpl0Carrier::boot_production(physical_inventory(), extent).expect("production KVM boot");
    carrier
        .bind_initial_task_identity(InitialTaskBinding {
            mm: carrick_guest_arch::MmGeneration::new(
                std::num::NonZeroU64::new(911).expect("issued fixture MM"),
            ),
            task: carrick_sched_core::process::TaskKey {
                id: carrick_personality_linux::identity::task_id_from_linux_pid(67)
                    .expect("fixture task id"),
                serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(
                    std::num::NonZeroU64::new(700).expect("fixture task serial"),
                ),
            },
            thread: carrick_sched_core::ThreadIdentity {
                tid: 67,
                serial: 701,
                mm: 0,
                file_table: 702,
                generation: 1,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("bind issued root");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("shared MM owner");
    assert!(carrier.initial_thread_custody());
    let workers = carrier.into_worker_parts(8).expect("worker handoff");
    assert_eq!(workers.root_state().binding().task().task.raw().get(), 700);
    assert_eq!(workers.root_state().state().mm_generation(), 911);
    let (root, factory) = workers.into_factory();
    let factory = std::sync::Arc::new(factory);
    let root_factory = std::sync::Arc::clone(&factory);
    std::thread::spawn(move || {
        let mut lease = root_factory.claim(0).expect("root CPU claim");
        assert_eq!(lease.physical_slot().map(|slot| slot.raw()), Some(0));
        assert!(root_factory.claim(0).is_err());
        lease.cpu_mut().audit_idle().expect("stopped root CPU");
        lease
            .cpu_mut()
            .load(root.clone())
            .expect("load issued root");
        let mut wrong = root.binding().task();
        wrong.execution = carrick_guest_arch::ExecutionGeneration::new(
            std::num::NonZeroU64::new(2).expect("other execution"),
        );
        let unknown = carrick_vmm_kvm::carrier_cpu::CarrierRunExit::PhysicalDoorbell {
            port: 0xffff,
            data: vec![],
        };
        let wrong_error = lease
            .service_physical_doorbell(wrong, &unknown, |_, _| {
                panic!("unexpected completed host work for wrong task")
            })
            .expect_err("wrong task cannot enter physical service");
        assert!(wrong_error.to_string().contains("task generation"));
        let port_error = lease
            .service_physical_doorbell(root.binding().task(), &unknown, |_, _| {
                panic!("unexpected completed host work for unknown port")
            })
            .expect_err("unknown physical crossing must fail closed");
        assert!(port_error.to_string().contains("unexpected physical"));
        let saved = lease
            .cpu_mut()
            .save_and_detach(root.binding().task())
            .expect("save issued root");
        assert_eq!(saved.state(), root.state());
        lease.cpu_mut().audit_idle().expect("detached root CPU");
    })
    .join()
    .expect("root worker ownership transfer");
    std::thread::spawn(move || {
        let mut lease = factory.claim(1).expect("peer CPU claim");
        assert_eq!(lease.physical_slot().map(|slot| slot.raw()), Some(1));
        assert!(factory.claim(1).is_err());
        lease.cpu_mut().audit_idle().expect("stopped peer CPU");
    })
    .join()
    .expect("peer worker ownership transfer");
}

fn image() -> PathBuf {
    PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"))
}

fn tiny_elf() -> Vec<u8> {
    let mut bytes = vec![0; 0xc0];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&ELF_X86_64_MACHINE.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_00b0_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    bytes[80..88].copy_from_slice(&ELF_LOAD_VA.to_le_bytes());
    bytes[96..104].copy_from_slice(&0xc0u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    // mov eax,231; mov edi,7; syscall; ud2. No libc or host ELF loader.
    bytes[0xb0..0xbe].copy_from_slice(&[
        0xb8,
        X86_SYS_EXIT_GROUP,
        0,
        0,
        0,
        0xbf,
        7,
        0,
        0,
        0,
        0x0f,
        0x05,
        0x0f,
        0x0b,
    ]);
    bytes
}

fn write_then_exit_elf(pointer: u64, count: u32) -> Vec<u8> {
    let mut bytes = tiny_elf();
    let mut code = vec![0xb8, X86_SYS_WRITE, 0, 0, 0, 0xbf, 1, 0, 0, 0];
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, pointer
    code.extend_from_slice(&pointer.to_le_bytes());
    code.push(0xba); // mov edx, count
    code.extend_from_slice(&count.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x89, 0xc7]); // syscall; mov edi, eax
    code.extend_from_slice(&[0xb8, X86_SYS_EXIT_GROUP, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]);
    let end = 0xb0 + code.len();
    bytes.resize(end, 0);
    bytes[96..104].copy_from_slice(&(end as u64).to_le_bytes());
    bytes[0xb0..end].copy_from_slice(&code);
    bytes
}

#[test]
fn initial_write_returns_prefix_or_efault_without_aborting_carrier() {
    for (pointer, count, expected_exit, expected_bytes) in [
        (0x400ff0, 0x10_0001, 16, 16),
        (0x7_0000, 32, 242, 0), // -EFAULT = -14, low exit byte 242
    ] {
        let elf = write_then_exit_elf(pointer, count);
        let outcome = run_pool_fixture(&elf, 8);
        assert_eq!(outcome.run.exit_code, expected_exit);
        assert_eq!(outcome.run.stdout.len(), expected_bytes);
    }
}

#[test]
fn explicit_initial_process_kick_preempts_and_resumes_under_pool() {
    let elf = tiny_elf();
    let outcome = run_pool_fixture_with(&elf, 8, |carrier| {
        carrier
            .fixture_cancel_next_run(0)
            .expect("cancel stopped vCPU");
    });
    assert_eq!(outcome.run.exit_code, 7);
}

#[test]
fn shared_guest_owner_loads_static_elf_and_exits_seven() {
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let plan = prepare_x86_elf(&program).expect("shared ELF parser");
    assert_eq!(
        (plan.entry, plan.phdr, plan.phent, plan.phnum),
        (0x4000b0, 0x400040, 56, 1)
    );
    assert_eq!(plan.regions.len(), 1);
    assert!(plan.regions[0].perms.execute && !plan.regions[0].perms.write);
    let mut program = vec![0x48, 0xbf]; // mov rdi, staged ELF pointer
    program.extend_from_slice(&0x10100u64.to_le_bytes());
    program.extend_from_slice(&[0x48, 0xbe]); // mov rsi, ELF length
    program.extend_from_slice(&(elf.len() as u64).to_le_bytes());
    program.extend_from_slice(&[0x48, 0xb8]); // mov rax, owner request
    program.extend_from_slice(&OBSERVE_INITIAL_MM.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    program.resize(0x100, 0x90);
    program.extend_from_slice(&elf);
    let mut carrier = Cpl0Carrier::boot(physical_inventory(), &image(), [&program, &program])
        .expect("real KVM image");
    let observed = carrier.observe(0).expect("static ELF exit");
    assert_eq!(observed.result, 7);
    assert_eq!(observed.semantic_host_exits, 0);
}

#[test]
fn production_static_pie_loads_above_low_stack_and_exits_seven() {
    let mut elf = tiny_elf();
    elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN without PT_INTERP
    elf[24..32].copy_from_slice(&0xb0u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0u64.to_le_bytes());
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let plan = prepare_x86_elf(&program).expect("static PIE parser");
    assert_eq!(plan.entry, carrick_mem::elf::LINUX_PIE_DEFAULT_BASE + 0xb0);
    let outcome = run_pool_fixture(&elf, 8);
    assert_eq!(outcome.run.exit_code, 7);
}

#[test]
fn production_enters_pt_interp_instead_of_executable_entry() {
    let mut elf = tiny_elf();
    elf.resize(0x200, 0);
    elf.copy_within(64..120, 120);
    elf[64..120].fill(0);
    elf[64..68].copy_from_slice(&3u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x180u64.to_le_bytes());
    let path = b"/lib/ld-test.so\0";
    elf[96..104].copy_from_slice(&(path.len() as u64).to_le_bytes());
    elf[0x180..0x180 + path.len()].copy_from_slice(path);
    elf[56..58].copy_from_slice(&2u16.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    elf[152..160].copy_from_slice(&0x200u64.to_le_bytes());
    elf[0x100..0x102].copy_from_slice(&[0x0f, 0x0b]); // Main must not enter ud2.

    let mut interpreter = tiny_elf();
    interpreter[16..18].copy_from_slice(&3u16.to_le_bytes());
    interpreter[24..32].copy_from_slice(&0xb0u64.to_le_bytes());
    interpreter[80..88].copy_from_slice(&0u64.to_le_bytes());
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|requested| {
        assert_eq!(requested, "/lib/ld-test.so");
        Some(interpreter.clone())
    })
    .expect("shared ELF loader");
    let outcome = kvm_pool_fixture::try_run_program_with(&program, 8, |_| {})
        .expect("PT_INTERP production entry");
    assert_eq!(outcome.run.exit_code, 7);
}

#[test]
fn production_bootstrap_stack_prefix_accepts_user_writes() {
    let mut elf = tiny_elf();
    let exit = elf[0xb0..0xbe].to_vec();
    elf.resize(0x100, 0);
    elf[96..104].copy_from_slice(&0x100u64.to_le_bytes());
    // sub rsp,8192; mov qword [rsp],0x5a; exit_group(7).
    let mut code = vec![
        0x48, 0x81, 0xec, 0, 0x20, 0, 0, 0x48, 0xc7, 0x04, 0x24, 0x5a, 0, 0, 0,
    ];
    code.extend_from_slice(&exit);
    elf[0xb0..0xb0 + code.len()].copy_from_slice(&code);
    assert_eq!(run_pool_fixture(&elf, 8).run.exit_code, 7);
}

#[test]
fn production_extent_cannot_alias_kernel_metadata() {
    use carrick_el1_abi::{EL1_DYNAMIC_METADATA_SIZE, X86_CPL0_DYNAMIC_METADATA_BASE};

    let extent_bytes = 192 * 1024 * 1024 + 4096;
    let mut carrier = Cpl0Carrier::boot_production(physical_inventory(), extent_bytes)
        .expect("production KVM image");
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("shared MM owner");

    let extent_va = carrick_core_abi::X86_CPL0_INITIAL_EXTENT_VA;
    let extent_end = extent_va + extent_bytes as u64;
    let metadata_end = X86_CPL0_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE;
    assert!(
        extent_end <= X86_CPL0_DYNAMIC_METADATA_BASE || extent_va >= metadata_end,
        "initial extent aliases the dynamic metadata aperture"
    );
}

#[test]
fn production_boot_binds_both_kvm_local_apics() {
    let carrier =
        Cpl0Carrier::boot_production(physical_inventory(), 0x20_000).expect("production KVM boot");
    assert!(
        carrier
            .bootstrap_lapic_mapped()
            .expect("bootstrap LAPIC table walk"),
        "production CPL0 needs a writable supervisor mapping to xAPIC MMIO"
    );
    for slot in 0..2 {
        let version = carrier
            .lapic_register(slot, 0x30)
            .expect("production vCPU needs a live local APIC");
        assert_ne!(version & 0xff, 0, "missing LAPIC version on slot {slot}");
    }
}

#[test]
fn production_irq_entry_retains_each_native_vector_from_live_user_mode() {
    for (vector, bit) in [(0xe0, 1), (0xe1, 2), (0xe2, 4), (0xe3, 8)] {
        let elf = tiny_elf();
        let outcome = run_pool_fixture_with(&elf, 8, |carrier| {
            carrier
                .fixture_inject_irq(0, vector)
                .expect("native IRQ edge into stopped vCPU");
        });
        assert_eq!(outcome.run.exit_code, 7, "vector {vector:#x}");
        assert_eq!(
            outcome.physical.fixture_pending_irqs(0).unwrap() & bit,
            bit,
            "vector {vector:#x}"
        );
    }
}

#[test]
fn production_initial_mm_admits_one_shared_reservation_root() {
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let plan = prepare_x86_elf(&program).expect("static ELF plan");
    let argv = vec!["/tiny".to_owned()];
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&plan, &argv, &[]).expect("typed initial extent");
    let mut carrier =
        Cpl0Carrier::boot_production(physical_inventory(), extent).expect("production CPL0 image");
    carrier
        .load_guest_mm(&plan, &argv, &[], InitialReservationLimits::UNLIMITED)
        .expect("guest initial MM publication");
    let mappings = carrier.initial_reservation_census().expect("fork census");
    assert_eq!(
        mappings.len(),
        plan.regions.len() + 1,
        "fork must inherit every ELF region and the stack"
    );
    for region in &plan.regions {
        assert!(
            mappings
                .iter()
                .any(|mapping| mapping.range.start() == region.start
                    && mapping.range.end() == region.end)
        );
    }
    assert!(mappings.iter().any(|mapping| {
        mapping.range.len() >= 4096
            && mapping
                .protection
                .permits(carrick_el1_abi::ReservationProtection::WRITE)
    }));
    assert!(carrier.initial_reservation_admitted());
    assert!(carrier.initial_inventory_custody());
    assert!(
        carrier.initial_thread_custody(),
        "initial x86 task must own one typed scheduler record"
    );
}

#[test]
fn production_user_page_fault_terminates_with_sigsegv_in_ring() {
    let elf = production_fault_elf();
    let outcome = run_pool_fixture(&elf, 32);
    assert!(outcome.fault_record.is_none(), "SIGSEGV stays in-ring");
    let exits = outcome.run.traps;
    assert_eq!(outcome.run.terminating_signal, Some(libc::SIGSEGV));
    assert_eq!(
        outcome.physical.user_fault_state(0).expect("fault custody"),
        (1, 0xdead000, 6, 0x4000b0 + 26, 0)
    );
    assert_eq!(exits, 2);
}

#[test]
fn block_then_user_page_fault_terminates_with_sigsegv_in_ring() {
    let elf = block_then_fault_elf();
    let outcome = run_pool_fixture(&elf, 32);
    assert!(outcome.fault_record.is_none(), "SIGSEGV stays in-ring");
    let exits = outcome.run.traps;
    assert_eq!(outcome.run.terminating_signal, Some(libc::SIGSEGV));
    assert_eq!(
        outcome.physical.user_fault_state(0).expect("fault custody"),
        (1, 0xdead000, 6, 0x4000b0 + 17, 0)
    );
    assert_eq!(exits, 1);
}

fn block_then_fault_elf() -> Vec<u8> {
    let mut elf = tiny_elf();
    let mut code = vec![0xb8, 24, 0, 0, 0, 0x0f, 0x05, 0x48, 0xb8];
    code.extend_from_slice(&0xdead000u64.to_le_bytes());
    code.extend_from_slice(&[0xc6, 0x00, 1, 0x0f, 0x0b]);
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf
}

fn production_fault_elf() -> Vec<u8> {
    let mut elf = tiny_elf();
    let mut code = vec![
        0xbf, 1, 0, 0, 0, 0x31, 0xf6, 0x31, 0xd2, 0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x48, 0xb8,
    ];
    code.extend_from_slice(&0xdead000u64.to_le_bytes());
    code.extend_from_slice(&[0xc6, 0x00, 1, 0x0f, 0x0b]);
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf
}

#[test]
fn file_region_guest_fork_dup_and_child_retirement_preserve_parent() {
    use carrick_el1_abi::fd_map_lookup;
    use carrick_hal::VcpuKick;
    use std::sync::atomic::Ordering;
    let elf = native_exit_fixture("native_file_fork.S");
    let (parts, root_tid) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory();
    let task = root.binding().task();
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("peer executor");
    parent.cpu_mut().load(root).expect("load issued root");
    run_to_marker(&mut parent, task, 0, &factory);
    let (stdout, incarnation) = factory
        .with_stopped_file_tables(|tables| {
            let slot = tables
                .fd_map()
                .iter()
                .find(|slot| {
                    slot.incarnation.load(Ordering::Acquire) != 0
                        && slot.fd.load(Ordering::Relaxed) == 1
                })
                .expect("initial stdout descriptor");
            let stdout = slot.handle.load(Ordering::Relaxed);
            let open = &tables.opens()[stdout as usize - 1];
            let incarnation = open.generation.load(Ordering::Acquire);
            assert_eq!(open.lifetime.ring_references(incarnation), Some(1));
            (stdout, incarnation)
        })
        .expect("pre-fork open lifetime");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_pin_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("child on independent physical lane");
    let retiring = peer_retirement(&mut peer); // real child dup then exit(3)
    let (parent_table, child_table, parent_slot, child_slot) = factory
        .with_stopped_file_tables(|tables| {
            let slots: Vec<_> = tables
                .fd_map()
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    s.incarnation.load(Ordering::Acquire) != 0 && s.fd.load(Ordering::Relaxed) == 3
                })
                .map(|(i, s)| (s.file_table.load(Ordering::Acquire), i))
                .collect();
            assert_eq!(
                slots.len(),
                2,
                "parent and child each published dup(stdout)"
            );
            let [(parent_table, parent_slot), (child_table, child_slot)] = slots[..] else {
                unreachable!()
            };
            assert_ne!(parent_table, child_table);
            assert_ne!(parent_slot, child_slot);
            let stdout = fd_map_lookup(tables.fd_map(), parent_table, 1)
                .expect("parent stdout")
                .0;
            for table in [parent_table, child_table] {
                assert_eq!(
                    fd_map_lookup(tables.fd_map(), table, 1)
                        .expect("inherited stdout")
                        .0,
                    stdout
                );
                assert_eq!(
                    fd_map_lookup(tables.fd_map(), table, 3)
                        .expect("independent dup reference")
                        .0,
                    stdout
                );
            }
            let open = &tables.opens()[stdout as usize - 1];
            assert_eq!(open.lifetime.ring_references(incarnation), Some(4));
            assert!(
                open.inode_handle.load(Ordering::Acquire) > 0,
                "stdout open must reside in the retained region"
            );
            assert!(open.is_bound_to(
                &tables.objects()[open.inode_handle.load(Ordering::Acquire) as usize - 1]
            ));
            (parent_table, child_table, parent_slot, child_slot)
        })
        .expect("both live tables in retained region");
    run_until_wait_enrolled(&mut parent, task, &factory, root_tid, false);
    assert!(
        peer.service_idle_peer_doorbell(&retiring, |_, _| {})
            .expect("real MM retirement")
            .is_none()
    );
    // Complete the real child's retirement and stop its now-idle executor.
    // The watcher only bounds the fixture; it does not complete guest exit.
    let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
    let stopped = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !factory
                .fixture_native_cpu_idle(carrick_guest_arch::CpuId::new(1))
                .expect("idle state")
            {
                if stopped.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                    kick.kick();
                    return false;
                }
                std::thread::yield_now();
            }
            kick.kick();
            true
        });
        run_idle_peer_until_kick(&mut peer);
        stopped.store(true, Ordering::Release);
        assert!(
            watcher.join().expect("idle watcher"),
            "child retirement deadline"
        );
    });
    run_to_marker(&mut parent, task, 2, &factory);
    factory
        .with_stopped_file_tables(|tables| {
            // The parent owns its issued file table (2) before and after
            // wait4; retiring the child table leaves only the parent's two
            // references (stdout and dup(stdout)).
            assert_eq!(parent_table, 2);
            assert_ne!(child_table, 2);
            assert_eq!(
                tables.opens()[stdout as usize - 1]
                    .lifetime
                    .ring_references(incarnation),
                Some(2)
            );
            assert_eq!(
                tables.fd_map()[child_slot]
                    .incarnation
                    .load(Ordering::Acquire),
                0
            );
            assert_eq!(
                tables.fd_map()[child_slot]
                    .file_table
                    .load(Ordering::Acquire),
                0
            );
            assert_eq!(
                tables.fd_map()[parent_slot]
                    .file_table
                    .load(Ordering::Acquire),
                parent_table
            );
            for fd in 0..=3 {
                assert!(
                    fd_map_lookup(tables.fd_map(), parent_table, fd).is_some(),
                    "parent fd {fd} survives"
                );
                assert!(
                    fd_map_lookup(tables.fd_map(), child_table, fd).is_none(),
                    "child fd {fd} retired"
                );
            }
        })
        .expect("parent survives child file-table retirement");
}
