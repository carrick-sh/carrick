//! Non-product namespace-operation cost probe for the `--fs host` backend.
//!
//! Dispatches guest `openat`/`unlinkat`/`renameat`/`newfstatat` straight into
//! a resident kernel dispatcher over a real `HostFsBackend` (no guest, no HVF,
//! no signal bridge) and prints wall time per operation next to a native
//! control that performs the same host operation through `std::fs` in a
//! sibling directory of the same volume. It is the timing half of the
//! structural budget in
//! `dispatch::fs::tests::serial_host::namespace_ops_host_syscall_budget`: that
//! test counts host syscalls exactly; this measures what they cost. Numbers
//! exclude the HVF trap and guest-memory transport, so they are a floor for
//! the in-guest cost, not a substitute for it.
//!
//! Every phase is bracketed by one `getppid(2)` on each side, so a syscall
//! tracer can attribute host calls to phases (count `getppid` entries).
//!
//! Usage: `fs-namespace-census [OPS_PER_PHASE]` (default 1000).
use carrick_abi::syscall::nr;
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge};
use carrick_kernel::{
    compat::{CompatReporter, SyscallArgs},
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
use std::{sync::Arc, time::Instant};

type Error = Box<dyn std::error::Error>;
type Op<'a> = &'a mut dyn FnMut(&mut TaskMemory, usize) -> Result<(), Error>;
type NativeOp<'a> = &'a mut dyn FnMut(usize) -> std::io::Result<()>;

fn check(ok: bool, what: &str) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(what.into()) }
}

fn phase_marker() {
    std::hint::black_box(std::os::unix::process::parent_id());
}

fn report(name: &str, ops: usize, start: Instant) {
    let us = start.elapsed().as_nanos() as f64 / ops as f64 / 1000.0;
    println!(
        "{}",
        serde_json::json!({"operation": name, "ops": ops, "us_per_op": us})
    );
}

fn main() -> Result<(), Error> {
    let ops: usize = match std::env::args().nth(1) {
        Some(arg) => arg.parse()?,
        None => 1000,
    };
    let scratch = tempfile::tempdir()?;
    let bridges = CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(NullGuestTimerBridge::default()),
    };
    let asids = AsidAllocator::new();
    let pid = carrick_abi::LINUX_BOOTSTRAP_PID as i32;
    let (process, context) = ExampleProcess::boot_root(
        pid,
        "fs-namespace-census",
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
    let first = memory.alloc_zeroed(256)?;
    let second = memory.alloc_zeroed(256)?;
    let stat = memory.alloc_zeroed(256)?;
    let mut executor = dispatcher.enter_mm_executor()?;
    let mut call = |memory: &mut TaskMemory, number: u64, args: [u64; 6]| -> Result<i64, Error> {
        match dispatcher.dispatch_threaded_with_mm_executor(
            &mut executor,
            &context,
            SyscallRequest::new(number, SyscallArgs::from(args)),
            &mut memory.linear,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )? {
            DispatchOutcome::Returned { value } => Ok(value),
            DispatchOutcome::Errno { errno } => Ok(errno.guest_retval()),
            other => Err(format!("unexpected synchronous result: {other:?}").into()),
        }
    };
    let put = |memory: &mut TaskMemory, at: u64, path: &str| -> Result<(), Error> {
        memory.write(at, format!("{path}\0").as_bytes())?;
        Ok(())
    };
    let cwd = (-100_i64) as u64;
    let create = carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_WRONLY;
    for dir in ["/a", "/a/b", "/a/b/c", "/a/b/d"] {
        put(&mut memory, first, dir)?;
        let made = call(&mut memory, nr::MKDIRAT.raw(), [cwd, first, 0o755, 0, 0, 0])?;
        check(made == 0, "mkdirat")?;
    }
    for i in 0..ops {
        put(&mut memory, first, &format!("/a/b/c/f{i}"))?;
        let fd = call(
            &mut memory,
            nr::OPENAT.raw(),
            [cwd, first, create, 0o644, 0, 0],
        )?;
        check(fd >= 0, "fixture create")?;
        call(&mut memory, nr::CLOSE.raw(), [fd as u64, 0, 0, 0, 0, 0])?;
    }

    let phase = |name: &str, memory: &mut TaskMemory, op: Op<'_>| -> Result<(), Error> {
        phase_marker();
        let start = Instant::now();
        for i in 0..ops {
            op(memory, i)?;
        }
        report(name, ops, start);
        phase_marker();
        Ok(())
    };
    // One guest operation: `path_a` (and `path_b` for a rename) in guest
    // memory, then the syscall; an open is paired with its close.
    let mut guest = |m: &mut TaskMemory,
                     number: u64,
                     flags: u64,
                     path_a: &str,
                     path_b: Option<&str>|
     -> Result<(), Error> {
        put(m, first, path_a)?;
        let args = match path_b {
            Some(path_b) => {
                put(m, second, path_b)?;
                [cwd, first, cwd, second, 0, 0]
            }
            None if number == nr::NEWFSTATAT.raw() => [cwd, first, stat, 0, 0, 0],
            None => [cwd, first, flags, 0o644, 0, 0],
        };
        let result = call(m, number, args)?;
        if number == nr::OPENAT.raw() {
            check(result >= 0, "openat")?;
            call(m, nr::CLOSE.raw(), [result as u64, 0, 0, 0, 0, 0])?;
            return Ok(());
        }
        check(result == 0, "namespace operation")
    };
    let open = nr::OPENAT.raw();
    phase("openat_rdonly+close", &mut memory, &mut |m, i| {
        guest(m, open, 0, &format!("/a/b/c/f{i}"), None)
    })?;
    phase("openat_creat+close", &mut memory, &mut |m, i| {
        guest(m, open, create, &format!("/a/b/c/n{i}"), None)
    })?;
    phase("unlinkat", &mut memory, &mut |m, i| {
        guest(m, nr::UNLINKAT.raw(), 0, &format!("/a/b/c/n{i}"), None)
    })?;
    phase("renameat_same_dir", &mut memory, &mut |m, i| {
        let to = format!("/a/b/c/r{i}");
        guest(m, nr::RENAMEAT.raw(), 0, &format!("/a/b/c/f{i}"), Some(&to))
    })?;
    phase("renameat_cross_dir", &mut memory, &mut |m, i| {
        let to = format!("/a/b/d/r{i}");
        guest(m, nr::RENAMEAT.raw(), 0, &format!("/a/b/c/r{i}"), Some(&to))
    })?;
    phase("newfstatat", &mut memory, &mut |m, i| {
        guest(m, nr::NEWFSTATAT.raw(), 0, &format!("/a/b/d/r{i}"), None)
    })?;
    phase("unlinkat_renamed", &mut memory, &mut |m, i| {
        guest(m, nr::UNLINKAT.raw(), 0, &format!("/a/b/d/r{i}"), None)
    })?;

    // Native control: the same host operations through std::fs, same volume.
    let native = tempfile::tempdir()?;
    let dir = native.path().join("a/b/c");
    std::fs::create_dir_all(&dir)?;
    for i in 0..ops {
        std::fs::File::create(dir.join(format!("f{i}")))?;
    }
    let native_phase = |name: &str, op: NativeOp<'_>| -> Result<(), Error> {
        phase_marker();
        let start = Instant::now();
        for i in 0..ops {
            op(i)?;
        }
        report(name, ops, start);
        phase_marker();
        Ok(())
    };
    native_phase("native_open_rdonly+close", &mut |i| {
        std::fs::File::open(dir.join(format!("f{i}"))).map(drop)
    })?;
    native_phase("native_open_creat+close", &mut |i| {
        std::fs::File::create(dir.join(format!("n{i}"))).map(drop)
    })?;
    native_phase("native_unlink", &mut |i| {
        std::fs::remove_file(dir.join(format!("n{i}")))
    })?;
    native_phase("native_rename", &mut |i| {
        std::fs::rename(dir.join(format!("f{i}")), dir.join(format!("r{i}")))
    })?;
    native_phase("native_lstat", &mut |i| {
        std::fs::symlink_metadata(dir.join(format!("r{i}"))).map(drop)
    })?;
    Ok(())
}
