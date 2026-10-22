//! sched_setaffinity and sched_getaffinity mask reflection and inheritance
//! across the main thread and a spawned pthread.
use conformance_probes::report;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

type Mask = [u8; 128];

fn getaffinity(pid: i32) -> (i32, i32, Mask) {
    let mut mask: Mask = [0; 128];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_getaffinity,
            pid,
            mask.len(),
            mask.as_mut_ptr(),
        )
    };
    let errno = if rc < 0 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    (rc as i32, errno, mask)
}

fn setaffinity(pid: i32, cpu_id: usize) -> (i32, i32) {
    let mut mask: Mask = [0; 128];
    if cpu_id < 1024 {
        mask[cpu_id / 8] = 1 << (cpu_id % 8);
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_setaffinity,
            pid,
            mask.len(),
            mask.as_ptr(),
        )
    };
    let errno = if rc < 0 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    (rc as i32, errno)
}

fn get_set_cpus(mask: &Mask) -> Vec<usize> {
    let mut cpus = Vec::new();
    for (byte_idx, &byte) in mask.iter().enumerate() {
        if byte != 0 {
            for bit_idx in 0..8 {
                if byte & (1 << bit_idx) != 0 {
                    cpus.push(byte_idx * 8 + bit_idx);
                }
            }
        }
    }
    cpus
}

fn is_single_cpu_set(mask: &Mask, cpu_id: usize) -> bool {
    let expected_byte = cpu_id / 8;
    let expected_bit = 1u8 << (cpu_id % 8);
    for (i, &b) in mask.iter().enumerate() {
        if i == expected_byte {
            if b != expected_bit {
                return false;
            }
        } else if b != 0 {
            return false;
        }
    }
    true
}

fn main() {
    let mut reference = vec![0u8; 4096];
    let reference_res = unsafe {
        libc::syscall(
            libc::SYS_sched_getaffinity,
            0i32,
            reference.len(),
            reference.as_mut_ptr(),
        )
    };
    let reference_err = if reference_res < 0 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    assert!(
        reference_res > 0 && reference_err == 0,
        "reference sched_getaffinity failed: res={reference_res}, errno={reference_err}"
    );
    let expected_get_res = std::cmp::min(128, reference_res as usize);

    let (init_rc, init_err, init_mask) = getaffinity(0);
    assert!(
        init_rc > 0 && init_err == 0,
        "initial sched_getaffinity failed: res={init_rc}, errno={init_err}"
    );
    let cpus = get_set_cpus(&init_mask);
    assert!(!cpus.is_empty(), "initial affinity mask is empty");
    let main_cpu = cpus[0];
    let worker_cpu = if cpus.len() > 1 { cpus[1] } else { main_cpu };

    let (main_set_res, main_set_err) = setaffinity(0, main_cpu);
    let (main_get_res, main_get_err, main_mask) = getaffinity(0);
    let main_reflected = is_single_cpu_set(&main_mask, main_cpu);

    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let main_mask_for_worker = main_mask;
    let worker = thread::spawn(move || {
        let (inherited_res, inherited_err, inherited_mask) = getaffinity(0);
        let inherited = inherited_res > 0
            && inherited_err == 0
            && inherited_mask == main_mask_for_worker;

        let (t_set_res, t_set_err) = setaffinity(0, worker_cpu);
        let (t_get_res, t_get_err, t_mask) = getaffinity(0);
        let reflected = is_single_cpu_set(&t_mask, worker_cpu);

        let _ = ready_tx.send((inherited, t_set_res, t_set_err, t_get_res, t_get_err, reflected));
        assert!(
            release_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "main thread did not release worker"
        );
    });

    let (
        clone_mask_inherited,
        thread_set_res,
        thread_set_err,
        thread_get_res,
        thread_get_err,
        thread_mask_reflected,
    ) = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker did not publish affinity");

    // Both threads are alive when the caller checks its independent mask.
    let (main_post_res, main_post_err, main_post_mask) = getaffinity(0);
    let threads_independent = main_post_res > 0
        && main_post_err == 0
        && main_post_mask == main_mask;

    let _ = release_tx.send(());
    assert!(worker.join().is_ok(), "worker thread panicked");

    report!(
        main_setaffinity_res = main_set_res,
        main_setaffinity_errno = main_set_err,
        main_getaffinity_size_rule = (main_get_res as usize) == expected_get_res,
        main_getaffinity_errno = main_get_err,
        main_mask_reflected = main_reflected,
        thread_setaffinity_res = thread_set_res,
        thread_setaffinity_errno = thread_set_err,
        thread_getaffinity_size_rule = (thread_get_res as usize) == expected_get_res,
        thread_getaffinity_errno = thread_get_err,
        thread_mask_reflected = thread_mask_reflected,
        threads_independent = threads_independent,
        clone_mask_inherited = clone_mask_inherited,
    );

    eprintln!("main_getaffinity_raw={main_get_res}");
    eprintln!("thread_getaffinity_raw={thread_get_res}");
}
