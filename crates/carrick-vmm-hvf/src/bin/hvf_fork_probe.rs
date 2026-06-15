#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use applevisor_sys::{
        HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, hv_memory_flags_t, hv_reg_t, hv_return_t,
        hv_vcpu_create, hv_vcpu_destroy, hv_vcpu_exit_t, hv_vcpu_get_exec_time, hv_vcpu_run,
        hv_vcpu_set_reg, hv_vcpu_t, hv_vcpus_exit, hv_vm_config_create,
        hv_vm_config_get_max_ipa_size, hv_vm_config_set_ipa_size, hv_vm_create, hv_vm_destroy,
        hv_vm_map, os_release,
    };

    const HV_SUCCESS: hv_return_t = 0;
    const HV_ERROR: hv_return_t = 0xfae94001u32 as hv_return_t;
    const HV_BUSY: hv_return_t = 0xfae94002u32 as hv_return_t;
    const HV_NO_RESOURCES: hv_return_t = 0xfae94005u32 as hv_return_t;
    const HV_NO_DEVICE: hv_return_t = 0xfae94006u32 as hv_return_t;
    const HV_DENIED: hv_return_t = 0xfae94007u32 as hv_return_t;
    const HV_FAULT: hv_return_t = 0xfae94008u32 as hv_return_t;
    const HV_UNSUPPORTED: hv_return_t = 0xfae9400fu32 as hv_return_t;
    const SPIN_MEM_SIZE: usize = 0x4000;
    const SPIN_GUEST_ADDR: u64 = 0x10000;
    const SPIN_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x14]; // b .
    const PROBE_SIGNALS: &[libc::c_int] = &[
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGALRM,
        libc::SIGUSR1,
        libc::SIGUSR2,
    ];
    static SIGNAL_HITS: AtomicU64 = AtomicU64::new(0);

    extern "C" fn count_signal(_signum: libc::c_int) {
        SIGNAL_HITS.fetch_add(1, Ordering::Relaxed);
    }

    #[derive(Clone, Copy)]
    struct Vm {
        vcpu: hv_vcpu_t,
        exit: *const hv_vcpu_exit_t,
    }

    impl Vm {
        fn create() -> Result<(Self, Duration), hv_return_t> {
            let start = Instant::now();
            let mut max_ipa = 0u32;
            let rc = unsafe { hv_vm_config_get_max_ipa_size(&mut max_ipa) };
            if rc != HV_SUCCESS {
                return Err(rc);
            }
            let config = unsafe { hv_vm_config_create() };
            if config.is_null() {
                return Err(HV_ERROR);
            }
            let rc = unsafe { hv_vm_config_set_ipa_size(config, max_ipa) };
            if rc != HV_SUCCESS {
                unsafe { os_release(config.cast::<c_void>()) };
                return Err(rc);
            }
            let rc = unsafe { hv_vm_create(config) };
            unsafe { os_release(config.cast::<c_void>()) };
            if rc != HV_SUCCESS {
                return Err(rc);
            }
            let mut vcpu = 0;
            let mut exit: *const hv_vcpu_exit_t = ptr::null();
            let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null_mut()) };
            if rc != HV_SUCCESS {
                let _ = unsafe { hv_vm_destroy() };
                return Err(rc);
            }
            Ok((Self { vcpu, exit }, start.elapsed()))
        }

        fn destroy(self) -> (hv_return_t, hv_return_t, Duration) {
            let start = Instant::now();
            let vcpu_rc = unsafe { hv_vcpu_destroy(self.vcpu) };
            let vm_rc = unsafe { hv_vm_destroy() };
            (vcpu_rc, vm_rc, start.elapsed())
        }

        fn run_spin_for(&self, run_us: u64) -> Result<SpinRun, hv_return_t> {
            let _mem = SpinMem::map()?;
            let pc_rc = unsafe { hv_vcpu_set_reg(self.vcpu, hv_reg_t::PC, SPIN_GUEST_ADDR) };
            if pc_rc != HV_SUCCESS {
                return Err(pc_rc);
            }

            let vcpu = self.vcpu;
            let stopper = std::thread::spawn(move || {
                sleep_micros(run_us);
                unsafe { hv_vcpus_exit(&vcpu, 1) }
            });

            let start = Instant::now();
            let run_rc = unsafe { hv_vcpu_run(self.vcpu) };
            let elapsed = start.elapsed();
            let exit_reason = unsafe {
                self.exit
                    .as_ref()
                    .map(|exit| format!("{:?}", exit.reason))
                    .unwrap_or_else(|| "null".to_string())
            };
            let mut exec_ns = 0u64;
            let exec_rc = unsafe { hv_vcpu_get_exec_time(self.vcpu, &mut exec_ns) };
            let kick_rc = stopper.join().unwrap_or(HV_ERROR);

            Ok(SpinRun {
                run_rc,
                kick_rc,
                exec_rc,
                exec_ns,
                elapsed,
                exit_reason,
            })
        }
    }

    struct SpinMem {
        ptr: *mut c_void,
        size: usize,
    }

    impl SpinMem {
        fn map() -> Result<Self, hv_return_t> {
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    SPIN_MEM_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(HV_ERROR);
            }
            unsafe {
                ptr::copy_nonoverlapping(SPIN_CODE.as_ptr(), ptr.cast::<u8>(), SPIN_CODE.len());
            }
            let perms: hv_memory_flags_t = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
            let rc = unsafe { hv_vm_map(ptr.cast_const(), SPIN_GUEST_ADDR, SPIN_MEM_SIZE, perms) };
            if rc != HV_SUCCESS {
                unsafe {
                    libc::munmap(ptr, SPIN_MEM_SIZE);
                }
                return Err(rc);
            }
            Ok(Self {
                ptr,
                size: SPIN_MEM_SIZE,
            })
        }
    }

    impl Drop for SpinMem {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.ptr, self.size);
            }
        }
    }

    struct SpinRun {
        run_rc: hv_return_t,
        kick_rc: hv_return_t,
        exec_rc: hv_return_t,
        exec_ns: u64,
        elapsed: Duration,
        exit_reason: String,
    }

    pub fn main() {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let cmd = args.first().map(String::as_str).unwrap_or("help");
        match cmd {
            "live-fork" => live_fork(),
            "destroy-recreate" => {
                let delay = parse_u64_arg(&args, 1, 0);
                destroy_recreate(delay);
            }
            "recreate-loop" => {
                let iters = parse_u64_arg(&args, 1, 20);
                let delay = parse_u64_arg(&args, 2, 0);
                recreate_loop(iters, delay);
            }
            "run-once" => {
                let run_us = parse_u64_arg(&args, 1, 1_000);
                run_once(run_us);
            }
            "run-fork-churn" => {
                let iters = parse_u64_arg(&args, 1, 20);
                let run_us = parse_u64_arg(&args, 2, 1_000);
                let child_hold = parse_u64_arg(&args, 3, 0);
                run_fork_churn(iters, run_us, child_hold);
            }
            "signal-flood" => {
                let run_us = parse_u64_arg(&args, 1, 100_000);
                let block_internal = parse_u64_arg(&args, 2, 0) != 0;
                signal_flood(run_us, block_internal);
            }
            "fork-churn" => {
                let iters = parse_u64_arg(&args, 1, 20);
                let child_hold = parse_u64_arg(&args, 2, 0);
                fork_churn(iters, child_hold);
            }
            "parallel-recreate" => {
                let workers = parse_u64_arg(&args, 1, 8);
                parallel_recreate(workers);
            }
            _ => usage(),
        }
    }

    fn parse_u64_arg(args: &[String], index: usize, default: u64) -> u64 {
        args.get(index)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default)
    }

    fn usage() {
        println!("usage:");
        println!("  hvf_fork_probe live-fork");
        println!("  hvf_fork_probe destroy-recreate [delay_us]");
        println!("  hvf_fork_probe recreate-loop [iters] [delay_us]");
        println!("  hvf_fork_probe run-once [run_us]");
        println!("  hvf_fork_probe run-fork-churn [iters] [run_us] [child_hold_us]");
        println!("  hvf_fork_probe signal-flood [run_us] [block_internal=0|1]");
        println!("  hvf_fork_probe fork-churn [iters] [child_hold_us]");
        println!("  hvf_fork_probe parallel-recreate [workers]");
    }

    fn install_probe_signal_handlers() {
        for &signum in PROBE_SIGNALS {
            unsafe {
                let mut action: libc::sigaction = core::mem::zeroed();
                action.sa_sigaction = count_signal as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                action.sa_flags = libc::SA_RESTART;
                libc::sigaction(signum, &action, ptr::null_mut());
            }
        }
    }

    fn set_probe_signal_mask(how: libc::c_int) {
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut set);
            for &signum in PROBE_SIGNALS {
                libc::sigaddset(&mut set, signum);
            }
            if libc::pthread_sigmask(how, &set, ptr::null_mut()) != 0 {
                println!("pthread_sigmask=errno({})", errno());
            }
        }
    }

    fn live_fork() {
        println!("case=live-fork");
        let (vm, create_elapsed) = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!("parent_create={}", rc_label(rc));
                std::process::exit(1);
            }
        };
        println!("parent_create=ok create_us={}", create_elapsed.as_micros());

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("fork=errno({})", errno());
            let _ = vm.destroy();
            std::process::exit(1);
        }
        if pid == 0 {
            let vcpu_rc = unsafe { hv_vcpu_destroy(vm.vcpu) };
            let vm_destroy_rc = unsafe { hv_vm_destroy() };
            let create_rc = match Vm::create() {
                Ok((child_vm, elapsed)) => {
                    let (child_vcpu_destroy, child_vm_destroy, destroy_elapsed) =
                        child_vm.destroy();
                    println!(
                        "child_create=ok create_us={} child_vcpu_destroy={} child_vm_destroy={} child_destroy_us={}",
                        elapsed.as_micros(),
                        rc_label(child_vcpu_destroy),
                        rc_label(child_vm_destroy),
                        destroy_elapsed.as_micros()
                    );
                    HV_SUCCESS
                }
                Err(rc) => rc,
            };
            println!(
                "child_inherited_vcpu_destroy={} child_inherited_vm_destroy={} child_create={}",
                rc_label(vcpu_rc),
                rc_label(vm_destroy_rc),
                rc_label(create_rc)
            );
            unsafe { libc::_exit(if create_rc == HV_SUCCESS { 0 } else { 2 }) };
        }

        let mut status = 0;
        let wait_rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        let (vcpu_rc, vm_rc, destroy_elapsed) = vm.destroy();
        println!(
            "parent_wait={} status=0x{:x} parent_vcpu_destroy={} parent_vm_destroy={} parent_destroy_us={}",
            wait_rc,
            status,
            rc_label(vcpu_rc),
            rc_label(vm_rc),
            destroy_elapsed.as_micros()
        );
    }

    fn destroy_recreate(delay_us: u64) {
        println!("case=destroy-recreate delay_us={delay_us}");
        let (vm, create_elapsed) = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!("create1={}", rc_label(rc));
                std::process::exit(1);
            }
        };
        println!("create1=ok create1_us={}", create_elapsed.as_micros());
        let (vcpu_rc, vm_rc, destroy_elapsed) = vm.destroy();
        println!(
            "destroy1_vcpu={} destroy1_vm={} destroy1_us={}",
            rc_label(vcpu_rc),
            rc_label(vm_rc),
            destroy_elapsed.as_micros()
        );
        sleep_micros(delay_us);
        match Vm::create() {
            Ok((vm2, elapsed)) => {
                println!("create2=ok create2_us={}", elapsed.as_micros());
                let (vcpu_rc, vm_rc, destroy_elapsed) = vm2.destroy();
                println!(
                    "destroy2_vcpu={} destroy2_vm={} destroy2_us={}",
                    rc_label(vcpu_rc),
                    rc_label(vm_rc),
                    destroy_elapsed.as_micros()
                );
            }
            Err(rc) => {
                println!("create2={}", rc_label(rc));
                std::process::exit(2);
            }
        }
    }

    fn recreate_loop(iters: u64, delay_us: u64) {
        println!("case=recreate-loop iters={iters} delay_us={delay_us}");
        for i in 0..iters {
            match Vm::create() {
                Ok((vm, create_elapsed)) => {
                    let (vcpu_rc, vm_rc, destroy_elapsed) = vm.destroy();
                    println!(
                        "iter={} create=ok create_us={} destroy_vcpu={} destroy_vm={} destroy_us={}",
                        i,
                        create_elapsed.as_micros(),
                        rc_label(vcpu_rc),
                        rc_label(vm_rc),
                        destroy_elapsed.as_micros()
                    );
                    if vcpu_rc != HV_SUCCESS || vm_rc != HV_SUCCESS {
                        std::process::exit(3);
                    }
                }
                Err(rc) => {
                    println!("iter={} create={}", i, rc_label(rc));
                    std::process::exit(2);
                }
            }
            sleep_micros(delay_us);
        }
    }

    fn run_once(run_us: u64) {
        println!("case=run-once run_us={run_us}");
        let (vm, create_elapsed) = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!("create={}", rc_label(rc));
                std::process::exit(1);
            }
        };
        println!("create=ok create_us={}", create_elapsed.as_micros());
        match vm.run_spin_for(run_us) {
            Ok(run) => println!(
                "run={} kick={} exec={} exec_ns={} elapsed_us={} exit={}",
                rc_label(run.run_rc),
                rc_label(run.kick_rc),
                rc_label(run.exec_rc),
                run.exec_ns,
                run.elapsed.as_micros(),
                run.exit_reason
            ),
            Err(rc) => {
                println!("run_setup={}", rc_label(rc));
                let _ = vm.destroy();
                std::process::exit(2);
            }
        }
        let (vcpu_rc, vm_rc, destroy_elapsed) = vm.destroy();
        println!(
            "destroy_vcpu={} destroy_vm={} destroy_us={}",
            rc_label(vcpu_rc),
            rc_label(vm_rc),
            destroy_elapsed.as_micros()
        );
        if vcpu_rc != HV_SUCCESS || vm_rc != HV_SUCCESS {
            std::process::exit(3);
        }
    }

    fn run_fork_churn(iters: u64, run_us: u64, child_hold_us: u64) {
        println!("case=run-fork-churn iters={iters} run_us={run_us} child_hold_us={child_hold_us}");
        let (mut parent_vm, first_create) = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!("parent_initial_create={}", rc_label(rc));
                std::process::exit(1);
            }
        };
        println!(
            "parent_initial_create=ok create_us={}",
            first_create.as_micros()
        );

        let mut failures = 0u64;
        for i in 0..iters {
            match parent_vm.run_spin_for(run_us) {
                Ok(run) => println!(
                    "iter={} parent_prefork_run={} parent_prefork_kick={} parent_prefork_exec={} parent_prefork_exec_ns={} parent_prefork_elapsed_us={} parent_prefork_exit={}",
                    i,
                    rc_label(run.run_rc),
                    rc_label(run.kick_rc),
                    rc_label(run.exec_rc),
                    run.exec_ns,
                    run.elapsed.as_micros(),
                    run.exit_reason
                ),
                Err(rc) => {
                    println!("iter={} parent_prefork_run_setup={}", i, rc_label(rc));
                    std::process::exit(2);
                }
            }
            let (parent_vcpu_destroy, parent_vm_destroy, parent_destroy_elapsed) =
                parent_vm.destroy();
            println!(
                "iter={} parent_prefork_destroy_vcpu={} parent_prefork_destroy_vm={} parent_prefork_destroy_us={}",
                i,
                rc_label(parent_vcpu_destroy),
                rc_label(parent_vm_destroy),
                parent_destroy_elapsed.as_micros()
            );
            if parent_vcpu_destroy != HV_SUCCESS || parent_vm_destroy != HV_SUCCESS {
                std::process::exit(3);
            }

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                println!("iter={} fork=errno({})", i, errno());
                std::process::exit(1);
            }
            if pid == 0 {
                match Vm::create() {
                    Ok((child_vm, child_create_elapsed)) => {
                        match child_vm.run_spin_for(run_us) {
                            Ok(run) => println!(
                                "iter={} child_run={} child_kick={} child_exec={} child_exec_ns={} child_elapsed_us={} child_exit={}",
                                i,
                                rc_label(run.run_rc),
                                rc_label(run.kick_rc),
                                rc_label(run.exec_rc),
                                run.exec_ns,
                                run.elapsed.as_micros(),
                                run.exit_reason
                            ),
                            Err(rc) => {
                                println!("iter={} child_run_setup={}", i, rc_label(rc));
                                unsafe { libc::_exit(2) };
                            }
                        }
                        sleep_micros(child_hold_us);
                        let (child_vcpu_destroy, child_vm_destroy, child_destroy_elapsed) =
                            child_vm.destroy();
                        println!(
                            "iter={} child_create=ok child_create_us={} child_destroy_vcpu={} child_destroy_vm={} child_destroy_us={}",
                            i,
                            child_create_elapsed.as_micros(),
                            rc_label(child_vcpu_destroy),
                            rc_label(child_vm_destroy),
                            child_destroy_elapsed.as_micros()
                        );
                        unsafe {
                            libc::_exit(
                                if child_vcpu_destroy == HV_SUCCESS
                                    && child_vm_destroy == HV_SUCCESS
                                {
                                    0
                                } else {
                                    3
                                },
                            )
                        };
                    }
                    Err(rc) => {
                        println!("iter={} child_create={}", i, rc_label(rc));
                        unsafe { libc::_exit(2) };
                    }
                }
            }

            parent_vm = match Vm::create() {
                Ok((vm, parent_create_elapsed)) => {
                    println!(
                        "iter={} parent_postfork_create=ok parent_postfork_create_us={}",
                        i,
                        parent_create_elapsed.as_micros()
                    );
                    vm
                }
                Err(rc) => {
                    println!("iter={} parent_postfork_create={}", i, rc_label(rc));
                    std::process::exit(2);
                }
            };

            let mut status = 0;
            let wait_rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            println!("iter={} child_wait={} status=0x{:x}", i, wait_rc, status);
            if wait_rc < 0 || status != 0 {
                failures += 1;
            }
        }

        let (parent_vcpu_destroy, parent_vm_destroy, parent_destroy_elapsed) = parent_vm.destroy();
        println!(
            "parent_final_destroy_vcpu={} parent_final_destroy_vm={} parent_final_destroy_us={}",
            rc_label(parent_vcpu_destroy),
            rc_label(parent_vm_destroy),
            parent_destroy_elapsed.as_micros()
        );
        if failures != 0 || parent_vcpu_destroy != HV_SUCCESS || parent_vm_destroy != HV_SUCCESS {
            std::process::exit(1);
        }
    }

    fn signal_flood(run_us: u64, block_internal: bool) {
        println!("case=signal-flood run_us={run_us} block_internal={block_internal}");
        SIGNAL_HITS.store(0, Ordering::Relaxed);
        install_probe_signal_handlers();
        if block_internal {
            set_probe_signal_mask(libc::SIG_BLOCK);
        }
        let (vm, create_elapsed) = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!("create={}", rc_label(rc));
                std::process::exit(1);
            }
        };
        println!("create=ok create_us={}", create_elapsed.as_micros());
        if block_internal {
            set_probe_signal_mask(libc::SIG_UNBLOCK);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let sender_stop = Arc::clone(&stop);
        let pid = unsafe { libc::getpid() };
        let sender = std::thread::spawn(move || {
            let mut sent = 0u64;
            while !sender_stop.load(Ordering::Relaxed) {
                for &signum in PROBE_SIGNALS {
                    unsafe {
                        libc::kill(pid, signum);
                    }
                    sent += 1;
                }
                std::thread::yield_now();
            }
            sent
        });

        match vm.run_spin_for(run_us) {
            Ok(run) => println!(
                "run={} kick={} exec={} exec_ns={} elapsed_us={} exit={}",
                rc_label(run.run_rc),
                rc_label(run.kick_rc),
                rc_label(run.exec_rc),
                run.exec_ns,
                run.elapsed.as_micros(),
                run.exit_reason
            ),
            Err(rc) => {
                stop.store(true, Ordering::Relaxed);
                let _ = sender.join();
                println!("run_setup={}", rc_label(rc));
                let _ = vm.destroy();
                std::process::exit(2);
            }
        }
        stop.store(true, Ordering::Relaxed);
        let sent = sender.join().unwrap_or(0);
        let hits = SIGNAL_HITS.load(Ordering::Relaxed);
        println!("signals_sent={sent} signals_handled={hits}");
        let (vcpu_rc, vm_rc, destroy_elapsed) = vm.destroy();
        println!(
            "destroy_vcpu={} destroy_vm={} destroy_us={}",
            rc_label(vcpu_rc),
            rc_label(vm_rc),
            destroy_elapsed.as_micros()
        );
        if vcpu_rc != HV_SUCCESS || vm_rc != HV_SUCCESS {
            std::process::exit(3);
        }
    }

    fn fork_churn(iters: u64, child_hold_us: u64) {
        println!("case=fork-churn iters={iters} child_hold_us={child_hold_us}");
        let (mut parent_vm, first_create) = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!("parent_initial_create={}", rc_label(rc));
                std::process::exit(1);
            }
        };
        println!(
            "parent_initial_create=ok create_us={}",
            first_create.as_micros()
        );

        let mut failures = 0u64;
        for i in 0..iters {
            let (parent_vcpu_destroy, parent_vm_destroy, parent_destroy_elapsed) =
                parent_vm.destroy();
            println!(
                "iter={} parent_prefork_destroy_vcpu={} parent_prefork_destroy_vm={} parent_prefork_destroy_us={}",
                i,
                rc_label(parent_vcpu_destroy),
                rc_label(parent_vm_destroy),
                parent_destroy_elapsed.as_micros()
            );
            if parent_vcpu_destroy != HV_SUCCESS || parent_vm_destroy != HV_SUCCESS {
                std::process::exit(3);
            }

            let pid = unsafe { libc::fork() };
            if pid < 0 {
                println!("iter={} fork=errno({})", i, errno());
                std::process::exit(1);
            }
            if pid == 0 {
                match Vm::create() {
                    Ok((child_vm, child_create_elapsed)) => {
                        sleep_micros(child_hold_us);
                        let (child_vcpu_destroy, child_vm_destroy, child_destroy_elapsed) =
                            child_vm.destroy();
                        println!(
                            "iter={} child_create=ok child_create_us={} child_destroy_vcpu={} child_destroy_vm={} child_destroy_us={}",
                            i,
                            child_create_elapsed.as_micros(),
                            rc_label(child_vcpu_destroy),
                            rc_label(child_vm_destroy),
                            child_destroy_elapsed.as_micros()
                        );
                        unsafe {
                            libc::_exit(
                                if child_vcpu_destroy == HV_SUCCESS
                                    && child_vm_destroy == HV_SUCCESS
                                {
                                    0
                                } else {
                                    3
                                },
                            )
                        };
                    }
                    Err(rc) => {
                        println!("iter={} child_create={}", i, rc_label(rc));
                        unsafe { libc::_exit(2) };
                    }
                }
            }

            parent_vm = match Vm::create() {
                Ok((vm, parent_create_elapsed)) => {
                    println!(
                        "iter={} parent_postfork_create=ok parent_postfork_create_us={}",
                        i,
                        parent_create_elapsed.as_micros()
                    );
                    vm
                }
                Err(rc) => {
                    println!("iter={} parent_postfork_create={}", i, rc_label(rc));
                    std::process::exit(2);
                }
            };

            let mut status = 0;
            let wait_rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            println!("iter={} child_wait={} status=0x{:x}", i, wait_rc, status);
            if wait_rc < 0 || status != 0 {
                failures += 1;
            }
        }

        let (parent_vcpu_destroy, parent_vm_destroy, parent_destroy_elapsed) = parent_vm.destroy();
        println!(
            "parent_final_destroy_vcpu={} parent_final_destroy_vm={} parent_final_destroy_us={}",
            rc_label(parent_vcpu_destroy),
            rc_label(parent_vm_destroy),
            parent_destroy_elapsed.as_micros()
        );
        if failures != 0 || parent_vcpu_destroy != HV_SUCCESS || parent_vm_destroy != HV_SUCCESS {
            std::process::exit(1);
        }
    }

    fn parallel_recreate(workers: u64) {
        println!("case=parallel-recreate workers={workers}");
        for worker in 0..workers {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                println!("spawn worker={} errno={}", worker, errno());
                continue;
            }
            if pid == 0 {
                match Vm::create() {
                    Ok((vm, create_elapsed)) => {
                        let (vcpu_rc, vm_rc, destroy_elapsed) = vm.destroy();
                        println!(
                            "worker={} create=ok create_us={} destroy_vcpu={} destroy_vm={} destroy_us={}",
                            worker,
                            create_elapsed.as_micros(),
                            rc_label(vcpu_rc),
                            rc_label(vm_rc),
                            destroy_elapsed.as_micros()
                        );
                        unsafe {
                            libc::_exit(if vcpu_rc == HV_SUCCESS && vm_rc == HV_SUCCESS {
                                0
                            } else {
                                3
                            })
                        };
                    }
                    Err(rc) => {
                        println!("worker={} create={}", worker, rc_label(rc));
                        unsafe { libc::_exit(2) };
                    }
                }
            }
        }
        let mut failed = 0;
        for _ in 0..workers {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(-1, &mut status, 0) };
            println!("wait={} status=0x{:x}", rc, status);
            if rc < 0 || status != 0 {
                failed += 1;
            }
        }
        if failed != 0 {
            std::process::exit(1);
        }
    }

    fn sleep_micros(micros: u64) {
        if micros == 0 {
            return;
        }
        std::thread::sleep(Duration::from_micros(micros));
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn rc_label(rc: hv_return_t) -> String {
        match rc {
            HV_SUCCESS => "HV_SUCCESS".to_owned(),
            HV_ERROR => "HV_ERROR(0xfae94001)".to_owned(),
            HV_BUSY => "HV_BUSY(0xfae94002)".to_owned(),
            HV_NO_RESOURCES => "HV_NO_RESOURCES(0xfae94005)".to_owned(),
            HV_NO_DEVICE => "HV_NO_DEVICE(0xfae94006)".to_owned(),
            HV_DENIED => "HV_DENIED(0xfae94007)".to_owned(),
            HV_FAULT => "HV_FAULT(0xfae94008)".to_owned(),
            HV_UNSUPPORTED => "HV_UNSUPPORTED(0xfae9400f)".to_owned(),
            other => format!("HV_UNKNOWN(0x{other:08x})"),
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod imp {
    pub fn main() {
        eprintln!("hvf_fork_probe requires macOS arm64");
        std::process::exit(1);
    }
}

fn main() {
    imp::main();
}
