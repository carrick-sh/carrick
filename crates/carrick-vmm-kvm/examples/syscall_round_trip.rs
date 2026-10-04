//! Planning measurement, not a Linux conformance or carrier acceptance test.
//! Reuses the real KVM/x86 ELF bring-up and SyscallTrap path. The host arm
//! returns a fixed synthetic identity without kernel dispatch; the CPL0 control
//! does the same inside a benchmark-only LSTAR stub. Native uses libc getpid
//! (verify its uncached syscall instruction in the host libc before measuring).
//! Creation/ELF loading are outside timing; final exit/checksum is inside.
//! No tracing, retries, Docker, or production changes. Missing KVM is an error.
//! Encodings: Intel SDM vol. 2, SYSCALL/SYSRET, MOV, ADD, DEC, Jcc and OUT.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod benchmark {
    use carrick_abi::syscall::nr;
    use carrick_hal::{GuestVmBackend, SyscallTrap};
    use carrick_vmm_kvm::guest_setup_x86::{M01_BLOB_VA, X86_TRAMPOLINE_BASE};
    use carrick_x86::vmm::{X86Exit, X86Vcpu};
    use std::error::Error;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const CALLS: u32 = 50_000;
    const BATCHES: usize = 9;
    const IDENTITY: u32 = 123;

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // The guest accumulates every return value and reports the complete sum in
    // exit_group's argument. No libc, memory accesses, waits or hidden syscalls.
    fn guest_blob() -> Vec<u8> {
        let mut code = vec![0x41, 0xbc]; // mov r12d, CALLS
        code.extend_from_slice(&CALLS.to_le_bytes());
        code.extend_from_slice(&[
            0x45, 0x31, 0xed, // xor r13d, r13d
            0xb8, 39, 0, 0, 0, // loop: mov eax, native getpid
            0x0f, 0x05, // syscall
            0x49, 0x01, 0xc5, // add r13, rax
            0x41, 0xff, 0xcc, // dec r12d
            0x75, 0xf1, // jnz loop (-15)
            0x44, 0x89, 0xef, // mov edi, r13d (checksum, not OS exit status)
            0xb8, 231, 0, 0, 0, // mov eax, native exit_group
            0x0f, 0x05, // syscall
            0x0f, 0x0b, // ud2: exit must never return
        ]);
        code
    }

    fn fixture() -> Result<Fixture, Box<dyn Error>> {
        // Same one-segment ET_EXEC shape as tests/live_vcpu_x86.rs. Fields
        // follow the System V ELF64 ABI; the existing loader owns interpretation.
        let code = guest_blob();
        let mut elf = vec![0_u8; 120];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&M01_BLOB_VA.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5_u32.to_le_bytes()); // read + execute
        elf[72..80].copy_from_slice(&120_u64.to_le_bytes());
        elf[80..88].copy_from_slice(&M01_BLOB_VA.to_le_bytes());
        elf[88..96].copy_from_slice(&M01_BLOB_VA.to_le_bytes());
        elf[96..104].copy_from_slice(&(code.len() as u64).to_le_bytes());
        elf[104..112].copy_from_slice(&4096_u64.to_le_bytes());
        elf[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        elf.extend_from_slice(&code);
        let path =
            std::env::temp_dir().join(format!("carrick-kvm-round-trip-{}.elf", std::process::id()));
        // Refuse an existing path, rather than overwrite another run's fixture.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let guard = Fixture(path);
        file.write_all(&elf)?;
        Ok(guard)
    }

    fn kvm_batch(fixture: &Fixture, in_guest: bool) -> Result<f64, Box<dyn Error>> {
        let image = carrick_x86::load_x86_elf_image(&fixture.0)?;
        let mut engine = carrick_vmm_kvm::kvm_x86_engine::bring_up(&image)?;
        if in_guest {
            // Only getpid is handled locally; exit_group still rings the real
            // doorbell, and is consumed without returning. This is a latency
            // control, with no task graph, faults, scheduler or Linux policy.
            let mut stub = vec![
                0x83, 0xf8, 39, // cmp eax, native getpid
                0x75, 8,    // jne doorbell
                0xb8, // mov eax, IDENTITY
            ];
            stub.extend_from_slice(&IDENTITY.to_le_bytes());
            stub.extend_from_slice(&[
                0x48, 0x0f, 0x07, // sysretq
                0xe6, 0xc5, // doorbell: out al, 0xc5
                0x0f, 0x0b, // ud2: exit must never return
            ]);
            engine.vm().write_gpa(X86_TRAMPOLINE_BASE, &stub)?;
        }
        let start = Instant::now();
        let mut forwards = 0_u32;
        loop {
            let request = engine.next_syscall()?.ok_or("unexpected halt/kick")?;
            match request.number {
                nr::GETPID if !in_guest => {
                    forwards += 1;
                    if forwards > CALLS {
                        return Err("too many getpid requests".into());
                    }
                    engine.complete_syscall(i64::from(IDENTITY))?;
                }
                nr::EXIT_GROUP => {
                    let elapsed = start.elapsed();
                    if request.args[0] != u64::from(CALLS * IDENTITY)
                        || forwards != if in_guest { 0 } else { CALLS }
                    {
                        return Err("incomplete round trips or wrong checksum".into());
                    }
                    return Ok(elapsed.as_nanos() as f64 / f64::from(CALLS));
                }
                _ => return Err(format!("unexpected request: {request:?}").into()),
            }
        }
    }

    fn native_batch() -> Result<f64, Box<dyn Error>> {
        let start = Instant::now();
        let mut sum = 0_i64;
        let mut identity = 0_i64;
        for _ in 0..CALLS {
            // SAFETY: getpid has no pointer arguments or caller preconditions.
            identity = i64::from(unsafe { libc::getpid() });
            sum += std::hint::black_box(identity);
        }
        let elapsed = start.elapsed();
        if identity <= 0 || sum != identity * i64::from(CALLS) {
            return Err("native getpid checksum failed".into());
        }
        Ok(elapsed.as_nanos() as f64 / f64::from(CALLS))
    }

    fn exit_control_batch(fixture: &Fixture) -> Result<f64, Box<dyn Error>> {
        let image = carrick_x86::load_x86_elf_image(&fixture.0)?;
        let mut engine = carrick_vmm_kvm::kvm_x86_engine::bring_up(&image)?;
        // One real KVM_EXIT_IO per call, but no KVM_SET_REGS or engine CPU
        // accounting. A constant return follows OUT in the guest. This isolates
        // a minimal transport control, not host service or a production mailbox.
        let mut stub = vec![0xe6, 0xc5, 0xb8]; // out; mov eax, IDENTITY
        stub.extend_from_slice(&IDENTITY.to_le_bytes());
        stub.extend_from_slice(&[0x48, 0x0f, 0x07]); // sysretq
        engine.vm().write_gpa(X86_TRAMPOLINE_BASE, &stub)?;
        let start = Instant::now();
        let mut forwards = 0_u32;
        loop {
            match engine.vcpu_mut().run()? {
                X86Exit::Syscall { frame, .. } if frame.rax == 39 => {
                    forwards += 1;
                    if forwards > CALLS {
                        return Err("too many exit-control requests".into());
                    }
                }
                X86Exit::Syscall { frame, .. } if frame.rax == 231 => {
                    let elapsed = start.elapsed();
                    if forwards != CALLS || frame.rdi != u64::from(CALLS * IDENTITY) {
                        return Err("incomplete exit-control round trips".into());
                    }
                    return Ok(elapsed.as_nanos() as f64 / f64::from(CALLS));
                }
                exit => return Err(format!("unexpected exit: {exit:?}").into()),
            }
        }
    }

    fn report(arm: &str, samples: &mut [f64]) {
        println!("arm={arm} samples_ns_per_call={samples:.1?}");
        samples.sort_by(f64::total_cmp);
        println!(
            "arm={arm} min_ns={:.1} median_batch_ns={:.1} max_ns={:.1}",
            samples[0],
            samples[samples.len() / 2],
            samples[samples.len() - 1]
        );
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        for name in [
            "CARRICK_KVM_STATS",
            "CARRICK_KVM_EXIT_STATS",
            "CARRICK_X86_SYSCALL_STATS",
        ] {
            if std::env::var_os(name).is_some() {
                return Err(format!("unset {name} for an uninstrumented measurement").into());
            }
        }
        let (cancel, deadline) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if deadline.recv_timeout(Duration::from_secs(45)).is_err() {
                eprintln!("benchmark exceeded 45 s bound");
                std::process::exit(1);
            }
        });
        let result = (|| {
            let fixture = fixture()?;
            // One declared warmup, never a retry of failed measurements.
            native_batch()?;
            exit_control_batch(&fixture)?;
            kvm_batch(&fixture, false)?;
            kvm_batch(&fixture, true)?;
            let mut native = Vec::new();
            let mut exit_control = Vec::new();
            let mut host = Vec::new();
            let mut guest = Vec::new();
            println!("calls_per_batch={CALLS} batches={BATCHES} warmup_batches=1");
            // Serial, interleaved arms reduce drift. Pin with taskset externally.
            for _ in 0..BATCHES {
                native.push(native_batch()?);
                exit_control.push(exit_control_batch(&fixture)?);
                host.push(kvm_batch(&fixture, false)?);
                guest.push(kvm_batch(&fixture, true)?);
            }
            report("native_getpid", &mut native);
            report("kvm_exit_control", &mut exit_control);
            report("kvm_host_synthetic_identity", &mut host);
            report("kvm_cpl0_synthetic_identity", &mut guest);
            println!(
                "checksums=pass host_getpid_forwards_per_batch={CALLS} cpl0_getpid_forwards_per_batch=0"
            );
            Ok(())
        })();
        let _ = cancel.send(());
        watchdog.join().map_err(|_| "watchdog panicked")?;
        result
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return benchmark::run();
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    Err("requires Linux x86_64 and accessible /dev/kvm".into())
}
