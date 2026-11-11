//! Population witness for the write-then-exec ETXTBSY race (#1814, #2012).
//!
//! Writer threads create a script and run it while spawner threads fork and
//! exec continuously. A forked child holds a copy of every descriptor open at
//! the fork until it execs, so a writer whose descriptor is open at that
//! moment gets "Text file busy" when it runs the file it just wrote.
#![cfg(unix)]

use carrick_test_support::executable::write_executable;
use std::io::ErrorKind;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn write_then_exec_never_sees_text_file_busy_under_spawn_load() {
    let dir = tempfile::tempdir().unwrap();
    let stop = AtomicBool::new(false);
    let busy = std::sync::atomic::AtomicUsize::new(0);
    let runs = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    Command::new("/usr/bin/true").status().unwrap();
                }
            });
        }
        let writers: Vec<_> = (0..4)
            .map(|n| {
                let dir = dir.path();
                let busy = &busy;
                let runs = &runs;
                scope.spawn(move || {
                    for i in 0..300 {
                        let path = dir.join(format!("script-{n}-{i}"));
                        write_executable(&path, "#!/bin/sh\nexit 0\n");
                        match Command::new(&path).status() {
                            Ok(status) => assert!(status.success()),
                            Err(e) if e.kind() == ErrorKind::ExecutableFileBusy => {
                                busy.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => panic!("exec {}: {e}", path.display()),
                        }
                        runs.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
    });
    std::thread::sleep(Duration::from_millis(1));
    let (busy, runs) = (busy.into_inner(), runs.into_inner());
    assert_eq!(busy, 0, "ETXTBSY in {busy} of {runs} write-then-exec runs");
}
