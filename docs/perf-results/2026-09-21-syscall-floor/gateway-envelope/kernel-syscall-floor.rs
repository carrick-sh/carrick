//! Non-product dispatch-cost probe. No guest execution, signal bridge, or DSR claim.
use carrick_abi::syscall::nr;
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge};
use carrick_kernel::{
    compat::{CompatEvent, CompatReporter, SyscallArgs},
    dispatch::{CarrierBridges, DispatchOutcome, SyscallDispatcher, SyscallRequest, ThreadCtx},
    kernel::CarrierProcess,
    thread::{FutexTable, ThreadId, ThreadRegistry},
};
use carrick_kernel_example::{
    driver::seed_initial_task_state,
    memory::TaskMemory,
    process::{AddressSpace, AsidAllocator, ExampleProcess},
};
use carrick_vfs::fs_backend::HostFsBackend;
use std::{hint::black_box, sync::Arc, time::Instant};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "kernel-syscall-floor/gateway.rs"]
mod gateway;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if std::env::args().any(|arg| arg == "--verify-gateway") {
        gateway::GatewayStack::new().verify()?;
        println!("gateway register and stack checks passed");
        return Ok(());
    }
    let scratch = tempfile::tempdir()?;
    let bridges = CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(NullGuestTimerBridge::default()),
    };
    let asids = AsidAllocator::new();
    let pid = carrick_abi::LINUX_BOOTSTRAP_PID as i32;
    let (process, context) = ExampleProcess::boot_root(
        pid,
        "dispatch-cost",
        Arc::clone(&bridges.host_signal),
        AddressSpace::allocate(&asids)?,
    )?;
    let process = Arc::new(process);
    let mut dispatcher = SyscallDispatcher::with_bridges(bridges);
    dispatcher.set_fs_backend(Box::new(HostFsBackend::new_in(scratch.path())?));
    dispatcher.bind_hvpatch_process(Arc::clone(&process) as Arc<dyn CarrierProcess>);
    if let Some(error) = process.take_bind_failure() {
        return Err(error.into());
    }
    dispatcher.activate_file_authority(context.resources().files())?;
    seed_initial_task_state(&context, process.asid_generation())?;
    let tid = ThreadId::from_guest_supplied_tid(pid);
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    let mut memory = TaskMemory::new();
    let path = memory.put(b"/data\0")?;
    let stat = memory.alloc_zeroed(128)?;
    let data = memory.put(&[42_u8; 64])?;
    // Hold admission across the synchronous batch, as a resident executor can.
    let mut executor = dispatcher.enter_mm_executor()?;
    let mut calls = 0_u64;
    let mut call = |number: u64, args: [u64; 6]| -> Result<i64, Box<dyn std::error::Error>> {
        calls += 1;
        match dispatcher.dispatch_threaded_with_mm_executor(
            &mut executor,
            &context,
            SyscallRequest::new(number, SyscallArgs::from(args)),
            &mut memory.linear,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )? {
            DispatchOutcome::Returned { value } => {
                let meta =
                    carrick_abi::syscall::lookup_aarch64(number).ok_or("unknown probe syscall")?;
                reporter.record(CompatEvent::SyscallReturn {
                    number,
                    name: meta.name.into(),
                    retval: value,
                    errno: None,
                });
                Ok(value)
            }
            other => Err(format!("unexpected synchronous result: {other:?}").into()),
        }
    };
    let fd = call(
        nr::OPENAT.raw(),
        [
            (-100_i64) as u64,
            path,
            carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            0o600,
            0,
            0,
        ],
    )?;
    if fd < 0 {
        return Err("open failed".into());
    }
    if call(nr::WRITE.raw(), [fd as u64, data, 64, 0, 0, 0])? != 64 {
        return Err("fixture write failed".into());
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let paired = std::env::args().any(|arg| arg == "--gateway-paired");
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let paired = false;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if paired {
        measure_paired(&mut call, fd, pid, stat)?;
    }
    if !paired {
        let iterations = 100_000_u64;
        // Reverse operation order on alternate blocks. Warmup is excluded.
        for block in 0..4 {
            let mut operations = [
                ("getpid", nr::GETPID.raw(), [0; 6], i64::from(pid)),
                ("fstat", nr::FSTAT.raw(), [fd as u64, stat, 0, 0, 0, 0], 0),
            ];
            if block % 2 == 1 {
                operations.reverse();
            }
            for (name, number, args, expected) in operations {
                for _ in 0..10_000 {
                    if call(number, args)? != expected {
                        return Err("warmup result mismatch".into());
                    }
                }
                for sample in 0..9 {
                    let start = Instant::now();
                    let mut sum = 0_i64;
                    for _ in 0..iterations {
                        sum += black_box(call(black_box(number), black_box(args))?);
                    }
                    let elapsed = start.elapsed();
                    if sum != expected * iterations as i64 {
                        return Err("timed result mismatch".into());
                    }
                    println!(
                        "{}",
                        serde_json::json!({"operation":name,"block":block,"sample":sample,
                    "iterations":iterations,"ns_per_call":elapsed.as_nanos() as f64 / iterations as f64})
                    );
                }
            }
        }
    }
    if call(nr::CLOSE.raw(), [fd as u64, 0, 0, 0, 0, 0])? != 0 {
        return Err("close failed".into());
    }
    drop(call);
    let bytes = memory.read(stat, 128)?;
    let offset = std::mem::offset_of!(carrick_abi::LinuxStat, st_size);
    let size = i64::from_ne_bytes(bytes[offset..offset + 8].try_into()?);
    if size != 64 {
        return Err("stat size mismatch".into());
    }
    let report = reporter.snapshot();
    if report.summary.syscall_invocations != calls || report.summary.syscall_returns_ok != calls {
        return Err(format!("reporter mismatch: expected {calls}, {:?}", report.summary).into());
    }
    println!(
        "{}",
        serde_json::json!({"verified_calls":calls,"stat_size":size,
        "scope":"resident current-kernel dispatcher, linear memory, null asynchronous bridges"})
    );
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn measure_paired<F>(
    call: &mut F,
    fd: i64,
    pid: i32,
    stat: u64,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(u64, [u64; 6]) -> Result<i64, Box<dyn std::error::Error>>,
{
    let mut stack = gateway::GatewayStack::new();
    stack.verify()?;
    println!(
        "{}",
        serde_json::json!({"gateway_register_and_stack_verification":true})
    );
    let iterations = 100_000_u64;
    for block in 0..2 {
        for (name, number, args, expected) in [
            ("getpid", nr::GETPID.raw(), [0; 6], i64::from(pid)),
            ("fstat", nr::FSTAT.raw(), [fd as u64, stat, 0, 0, 0, 0], 0),
        ] {
            for (arm_index, gateway) in [false, true, true, false].into_iter().enumerate() {
                let mut failure = None;
                let mut callback = || match call(black_box(number), black_box(args)) {
                    Ok(value) => value,
                    Err(error) => {
                        failure = Some(error);
                        i64::MIN
                    }
                };
                for _ in 0..10_000 {
                    if stack.invoke(gateway, &mut callback) != expected {
                        return Err("gateway warmup failed".into());
                    }
                }
                for sample in 0..9 {
                    let start = Instant::now();
                    let mut correct = true;
                    for _ in 0..iterations {
                        correct &= black_box(stack.invoke(gateway, &mut callback)) == expected;
                    }
                    let elapsed = start.elapsed();
                    if !correct {
                        return Err("gateway return mismatch".into());
                    }
                    println!(
                        "{}",
                        serde_json::json!({"operation":name,"block":block,"arm_index":arm_index,
                        "arm":if gateway {"gateway"} else {"direct_callback"},"sample":sample,"iterations":iterations,
                        "ns_per_call":elapsed.as_nanos() as f64 / iterations as f64})
                    );
                }
                if let Some(error) = failure {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}
