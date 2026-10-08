//! Exclusive physical CPU actors. Linux task policy remains in the guest owner.
use crate::KvmVcpu;
use carrick_guest_arch::CpuId;
use carrick_hal::{TrapError, VcpuExit};

/// Coordinator decision after an exclusive physical CPU has stopped.
pub enum ActorDecision<R> {
    Resume,
    Park,
    Finish(R),
}
trait Cancel: Send {
    fn cancel(&self);
}
fn failed(message: &str) -> TrapError {
    TrapError::Hypervisor(message.into())
}
fn drive<'a, C: Send, E: Send, R, H: Cancel, G>(
    cpus: &'a mut [C; 2],
    initialize: impl Fn(&mut C) -> Result<(H, G), TrapError> + Sync,
    run: impl Fn(CpuId, &mut C) -> Result<E, TrapError> + Sync,
    mut service: impl FnMut(CpuId, &mut C, E) -> Result<ActorDecision<R>, TrapError>,
    mut interrupt_ready: impl FnMut(CpuId, &mut C) -> Result<bool, TrapError>,
) -> Result<R, TrapError> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    struct CpuLease<'a, C>(&'a mut C);
    enum Event<'a, C, E, H> {
        Ready(usize, CpuLease<'a, C>, H),
        Stopped(usize, CpuLease<'a, C>, Result<E, TrapError>),
        Failed(TrapError),
    }
    let stop = AtomicBool::new(false);
    let [first, second] = cpus;
    let lanes = [first, second];
    std::thread::scope(|scope| {
        let (events, receiver) = mpsc::sync_channel::<Event<'a, C, E, H>>(2);
        let mut commands = Vec::with_capacity(2);
        let mut workers = Vec::with_capacity(2);
        for (index, cpu) in lanes.into_iter().enumerate() {
            let (command, incoming) = mpsc::sync_channel::<CpuLease<'a, C>>(1);
            commands.push(command);
            let events = events.clone();
            let initialize = &initialize;
            let run = &run;
            let stop = &stop;
            let lease = CpuLease(cpu);
            workers.push(scope.spawn(move || {
                let work_events = events.clone();
                let work = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let (cancel, _guard) = initialize(&mut *lease.0)?;
                    work_events
                        .send(Event::Ready(index, lease, cancel))
                        .map_err(|_| failed("actor startup coordinator closed"))?;
                    while let Ok(lease) = incoming.recv() {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let exit = run(CpuId::new(index as u32), &mut *lease.0);
                        work_events
                            .send(Event::Stopped(index, lease, exit))
                            .map_err(|_| failed("actor exit coordinator closed"))?;
                    }
                    Ok::<(), TrapError>(())
                }));
                let failure = match work {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some(failed("physical CPU actor panicked")),
                };
                if let Some(error) = failure {
                    let _ = events.send(Event::Failed(error));
                }
            }));
        }
        drop(events);
        let mut controls: [Option<H>; 2] = [None, None];
        let mut stopped: [Option<CpuLease<'a, C>>; 2] = [None, None];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut startup_error = None;
            for _ in 0..2 {
                match receiver
                    .recv()
                    .map_err(|_| failed("actor startup channel closed"))?
                {
                    Event::Ready(index, cpu, cancel) => {
                        stopped[index] = Some(cpu);
                        controls[index] = Some(cancel);
                    }
                    Event::Failed(error) => startup_error = Some(error),
                    Event::Stopped(..) => return Err(failed("actor ran before admission")),
                }
            }
            if let Some(error) = startup_error {
                return Err(error);
            }
            for index in 0..2 {
                let cpu = stopped[index]
                    .take()
                    .ok_or_else(|| failed("missing admitted CPU lease"))?;
                commands[index]
                    .send(cpu)
                    .map_err(|_| failed("actor start command closed"))?;
            }
            loop {
                let Event::Stopped(index, cpu, exit) = receiver
                    .recv()
                    .map_err(|_| failed("actor exit channel closed"))?
                else {
                    return Err(failed("actor failed during execution"));
                };
                match service(CpuId::new(index as u32), &mut *cpu.0, exit?)? {
                    ActorDecision::Finish(result) => return Ok(result),
                    ActorDecision::Park => stopped[index] = Some(cpu),
                    ActorDecision::Resume => {
                        commands[index]
                            .send(cpu)
                            .map_err(|_| failed("actor resume command closed"))?;
                    }
                }
                // A physical notification licenses reentry. An unrelated host
                // exit merely permits this bounded inspection, never a wake.
                for peer_index in 0..2 {
                    if let Some(peer) = stopped[peer_index].take() {
                        if interrupt_ready(CpuId::new(peer_index as u32), &mut *peer.0)? {
                            commands[peer_index]
                                .send(peer)
                                .map_err(|_| failed("actor IRQ command closed"))?;
                        } else {
                            stopped[peer_index] = Some(peer);
                        }
                    }
                }
                if stopped.iter().all(Option::is_some) {
                    return Err(failed(
                        "all physical CPU actors parked without a wake source",
                    ));
                }
            }
        }));
        stop.store(true, Ordering::Release);
        for control in controls.iter().flatten() {
            control.cancel();
        }
        drop(commands);
        // Both stopped and running leases settle before scoped RAM/VM custody
        // can be released. Cancellation is durable across pre-run admission.
        for worker in workers {
            let _ = worker.join();
        }
        match outcome {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}
impl Cancel for crate::KvmKickHandle {
    fn cancel(&self) {
        carrick_hal::VcpuKick::kick(self);
    }
}

/// Actor threads are joined before their final host mask result is observed.
/// A failed restore cannot leak into another job on these dedicated threads.
#[derive(Default)]
struct ActorMaskRestoration(std::sync::atomic::AtomicI32);
impl ActorMaskRestoration {
    fn record(&self, error: std::io::Error) {
        self.0.store(
            error.raw_os_error().unwrap_or(libc::EIO),
            std::sync::atomic::Ordering::Release,
        );
    }
    fn result(&self) -> Result<(), TrapError> {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            0 => Ok(()),
            code => Err(TrapError::Hypervisor(format!(
                "actor signal mask restoration: {}",
                std::io::Error::from_raw_os_error(code)
            ))),
        }
    }
}

/// A signal queued before KVM_RUN remains pending until KVM atomically applies
/// its run mask. Restore the original thread mask only after the actor stops.
struct ActorInterruptMask {
    previous: libc::sigset_t,
    restoration: std::sync::Arc<ActorMaskRestoration>,
    run: [u8; 8],
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl ActorInterruptMask {
    fn block_kick(restoration: std::sync::Arc<ActorMaskRestoration>) -> Result<Self, TrapError> {
        // SAFETY: sigset APIs receive initialized, correctly sized host records.
        let (previous, run) = unsafe {
            let mut kick = std::mem::zeroed::<libc::sigset_t>();
            let mut previous = std::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&mut kick);
            libc::sigaddset(&mut kick, crate::kvm_kicker::kick_signal());
            let error = libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut previous);
            if error != 0 {
                return Err(TrapError::Hypervisor(
                    std::io::Error::from_raw_os_error(error).to_string(),
                ));
            }
            let mut bits = 0_u64;
            for signal in 1..=64 {
                if signal != crate::kvm_kicker::kick_signal()
                    && libc::sigismember(&previous, signal) == 1
                {
                    bits |= 1_u64 << (signal - 1);
                }
            }
            (previous, bits.to_ne_bytes())
        };
        Ok(Self {
            restoration,
            previous,
            run,
            _thread: std::marker::PhantomData,
        })
    }
}
impl Drop for ActorInterruptMask {
    fn drop(&mut self) {
        // SAFETY: the guard remains on the originating actor thread; the saved
        // mask is exactly the one returned by pthread_sigmask at admission.
        let error = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
        };
        if error != 0 {
            self.restoration
                .record(std::io::Error::from_raw_os_error(error));
        }
    }
}

fn configure_actor_run_mask(cpu: &kvm_ioctls::VcpuFd, run: [u8; 8]) -> Result<(), TrapError> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct RunMask {
        len: u32,
        signals: [u8; 8],
    }
    const _: () = assert!(std::mem::offset_of!(RunMask, signals) == 4);
    let mask = RunMask {
        len: 8,
        signals: run,
    };
    let request = vmm_sys_util::ioctl::ioctl_expr(
        vmm_sys_util::ioctl::_IOC_WRITE,
        0xae,
        0x8b,
        std::mem::size_of::<kvm_bindings::kvm_signal_mask>() as u32,
    );
    // SAFETY: the exclusive stopped CPU owns this fd; KVM_SET_SIGNAL_MASK
    // copies the 4-byte header and its exact 8-byte Linux kernel signal set.
    let result = unsafe { libc::ioctl(cpu.as_raw_fd(), request, &mask) };
    if result < 0 {
        return Err(TrapError::Hypervisor(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

/// Run two exclusive physical lanes concurrently; host service borrows only
/// the stopped lane. Parked lanes resume only on an explicit peer wake.
pub fn run_two_actors<R>(
    cpus: &mut [KvmVcpu; 2],
    run: impl Fn(CpuId, &mut KvmVcpu) -> Result<VcpuExit, TrapError> + Sync,
    service: impl FnMut(CpuId, &mut KvmVcpu, VcpuExit) -> Result<ActorDecision<R>, TrapError>,
    interrupt_ready: impl FnMut(CpuId, &mut KvmVcpu) -> Result<bool, TrapError>,
) -> Result<R, TrapError> {
    let restoration = std::sync::Arc::new(ActorMaskRestoration::default());
    let result = drive(
        cpus,
        |cpu| {
            let cancel = crate::KvmKickHandle::for_current_thread();
            let guard = ActorInterruptMask::block_kick(std::sync::Arc::clone(&restoration))?;
            configure_actor_run_mask(cpu.fd(), guard.run)?;
            Ok((cancel, guard))
        },
        run,
        service,
        interrupt_ready,
    );
    restoration.result()?;
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    struct Cpu {
        runs: usize,
    }
    struct Cancellation(Arc<(Mutex<bool>, Condvar)>);
    impl Cancel for Cancellation {
        fn cancel(&self) {
            let (lock, event) = &*self.0;
            *lock.lock().unwrap() = true;
            event.notify_all();
        }
    }
    #[test]
    fn two_exclusive_cpu_actors_run_concurrently_and_transfer_stopped_custody() {
        let mut cpus = [Cpu { runs: 0 }, Cpu { runs: 0 }];
        let cohort = (Mutex::new(0_usize), Condvar::new());
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let pending_irq = std::sync::atomic::AtomicBool::new(false);
        let result = drive(
            &mut cpus,
            |_| Ok((Cancellation(Arc::clone(&release)), ())),
            |slot, cpu| {
                cpu.runs += 1;
                if cpu.runs == 1 {
                    let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                    peak.fetch_max(now, Ordering::AcqRel);
                    let (lock, event) = &cohort;
                    let mut count = lock.lock().unwrap();
                    *count += 1;
                    event.notify_all();
                    let (count, deadline) = event
                        .wait_timeout_while(count, std::time::Duration::from_secs(5), |count| {
                            *count < 2
                        })
                        .unwrap();
                    assert_eq!(*count, 2);
                    assert!(!deadline.timed_out());
                    drop(count);
                    active.fetch_sub(1, Ordering::AcqRel);
                }
                if slot.raw() == 1 {
                    let (lock, event) = &*release;
                    let ready = lock.lock().unwrap();
                    let (ready, deadline) = event
                        .wait_timeout_while(ready, std::time::Duration::from_secs(5), |ready| {
                            !*ready
                        })
                        .unwrap();
                    assert!(*ready && !deadline.timed_out());
                }
                Ok(cpu.runs)
            },
            |slot, cpu, runs| {
                assert_eq!(cpu.runs, runs);
                if slot.raw() == 0 && runs == 1 {
                    let (lock, event) = &*release;
                    *lock.lock().unwrap() = true;
                    event.notify_all();
                    Ok(ActorDecision::Park)
                } else if slot.raw() == 1 {
                    pending_irq.store(true, Ordering::Release);
                    Ok(ActorDecision::Resume)
                } else {
                    Ok(ActorDecision::Finish(peak.load(Ordering::Acquire)))
                }
            },
            |slot, _| Ok(slot.raw() == 0 && pending_irq.swap(false, Ordering::AcqRel)),
        );
        assert_eq!(result.unwrap(), 2);
        assert_eq!(cpus[0].runs, 2);
        assert!(cpus[1].runs >= 1);
    }
    /// A cancellation queued after the final host check but before KVM_RUN
    /// must prevent even the first guest store. Missing KVM fails this gate.
    #[test]
    fn kvm_actor_cancellation_before_run_is_not_lost() {
        use carrick_hal::VcpuKick;
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut cpu = vm.create_vcpu(0).unwrap();
        let mut ram = crate::guest_setup::GuestRam::new();
        ram.add_window(0, 4096, crate::guest_setup::WindowKind::Private)
            .unwrap();
        let pointer = ram.host_ptr(0, 4096).unwrap();
        // mov byte [0x200],0x51; hlt, in real mode.
        unsafe {
            std::ptr::copy_nonoverlapping(
                [0xc6_u8, 0x06, 0x00, 0x02, 0x51, 0xf4].as_ptr(),
                pointer,
                6,
            );
        }
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: 4096,
                userspace_addr: pointer as u64,
                flags: 0,
            })
            .unwrap();
        }
        let mut sregs = cpu.get_sregs().unwrap();
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        cpu.set_sregs(&sregs).unwrap();
        cpu.set_regs(&kvm_bindings::kvm_regs {
            rip: 0,
            rflags: 2,
            ..Default::default()
        })
        .unwrap();
        let (ready, admitted) = std::sync::mpsc::channel();
        let (resume, start) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let cancel = crate::KvmKickHandle::for_current_thread();
                let guard =
                    ActorInterruptMask::block_kick(Arc::new(ActorMaskRestoration::default()))
                        .unwrap();
                configure_actor_run_mask(&cpu, guard.run).unwrap();
                ready.send(cancel).unwrap();
                start.recv().unwrap();
                match cpu.run() {
                    Err(error) => error.errno(),
                    Ok(exit) => panic!("cancellation was lost before guest entry: {exit:?}"),
                }
            });
            admitted
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .kick();
            resume.send(()).unwrap();
            assert_eq!(worker.join().unwrap(), libc::EINTR);
        });
        assert_eq!(unsafe { pointer.add(0x200).read() }, 0);
    }
}
