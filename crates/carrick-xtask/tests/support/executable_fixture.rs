//! Recreate a sibling fork inheriting a fixture's writer before it execs.
#![cfg(target_os = "linux")]
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

fn publish(path: &std::path::Path) {
    fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
    carrick_test_support::publish_executable(path, 0o700).unwrap();
}

#[test]
fn executable_fixture_survives_parallel_fork_inheriting_writer() {
    let root = tempfile::tempdir().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while !stop.load(Ordering::Acquire) {
                    assert!(Command::new("/bin/true").status().unwrap().success());
                }
            });
        }
        let result = std::panic::catch_unwind(|| {
            for iteration in 0..16 {
                let path = root.path().join(format!("curl-{iteration}"));
                fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
                let writer = OpenOptions::new().write(true).open(&path).unwrap();
                let (mut parent, child) = UnixStream::pair().unwrap();
                parent
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let fd = child.as_raw_fd();
                let mut command = Command::new("/bin/true");
                // Only async-signal-safe syscalls between fork and exec. The
                // handshake forces the otherwise rare inherited-writer window.
                unsafe {
                    command.pre_exec(move || {
                        let byte = [1u8];
                        if libc::write(fd, byte.as_ptr().cast(), 1) != 1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        let mut release = [0u8];
                        let mut poll = libc::pollfd {
                            fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        if libc::poll(&mut poll, 1, 5000) != 1
                            || libc::read(fd, release.as_mut_ptr().cast(), 1) != 1
                        {
                            return Err(std::io::Error::other("fixture fork handshake timed out"));
                        }
                        Ok(())
                    });
                }
                std::thread::scope(|scope| {
                    let spawning = scope.spawn(move || command.status().unwrap());
                    parent.read_exact(&mut [0u8]).unwrap();
                    drop(writer);
                    publish(&path);
                    let executed = Command::new(&path).status();
                    parent.write_all(&[1u8]).unwrap();
                    assert!(spawning.join().unwrap().success());
                    assert!(executed.unwrap().success(), "iteration {iteration}");
                });
            }
        });
        stop.store(true, Ordering::Release);
        result.unwrap();
    });
}
