// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Scoped structural workload: positive dirfds distinguish measured operations
//! from loader/setup operations in carrick trace. Both forked tasks remain live
//! through the independent mutation phase; pipes synchronize lifetime only.
use std::ffi::CString;

fn checked(value: i32) -> i32 {
    assert!(
        value >= 0,
        "host operation failed: {}",
        std::io::Error::last_os_error()
    );
    value
}

fn actor(dir: i32, id: usize, n: usize) {
    let src = CString::new(format!("{id}_src")).unwrap();
    let moved = CString::new(format!("{id}_moved")).unwrap();
    let alias = CString::new(format!("{id}_alias")).unwrap();
    for i in 0..n {
        unsafe {
            let (from, to) = if i % 2 == 0 {
                (&src, &moved)
            } else {
                (&moved, &src)
            };
            checked(libc::renameat(dir, from.as_ptr(), dir, to.as_ptr()));
            checked(libc::linkat(dir, to.as_ptr(), dir, alias.as_ptr(), 0));
            checked(libc::unlinkat(dir, alias.as_ptr(), 0));
            let fd = checked(libc::openat(dir, to.as_ptr(), libc::O_RDONLY));
            let mut byte = 0;
            assert_eq!(libc::read(fd, (&mut byte as *mut u8).cast(), 1), 1);
            assert_eq!(byte, b'x');
            checked(libc::close(fd));
        }
    }
}

fn transfer(fd: i32, write: bool) {
    let mut byte = b'!';
    unsafe {
        let mut poll = libc::pollfd {
            fd,
            events: if write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        assert_eq!(libc::poll(&mut poll, 1, 5000), 1);
        let ptr = (&mut byte as *mut u8).cast();
        assert_eq!(
            if write {
                libc::write(fd, ptr, 1)
            } else {
                libc::read(fd, ptr, 1)
            },
            1
        );
    }
}

fn main() {
    unsafe {
        conformance_probes::arm_alarm_ms(5000);
    }
    let args = std::env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 4);
    let n: usize = args[1].parse().unwrap();
    let population: usize = args[2].parse().unwrap();
    let same = args[3] == "same";
    assert!([1, 8, 32, 128].contains(&n));
    assert!([0, 128].contains(&population));
    let root = format!("/tmp/namespace-scale-{}", std::process::id());
    std::fs::create_dir_all(format!("{root}/shared")).unwrap();
    std::fs::create_dir_all(format!("{root}/unrelated")).unwrap();
    for i in 0..population {
        std::fs::create_dir(format!("{root}/population_{i}")).unwrap();
    }
    let parents = ["shared", if same { "shared" } else { "unrelated" }];
    let mut dirs = [0; 2];
    for (id, parent) in parents.iter().enumerate() {
        let path = format!("{root}/{parent}");
        std::fs::write(format!("{path}/{id}_src"), b"x").unwrap();
        let path = CString::new(path).unwrap();
        dirs[id] = unsafe {
            checked(libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            ))
        };
    }
    let mut start = [0; 2];
    let mut done = [0; 2];
    unsafe {
        checked(libc::pipe(start.as_mut_ptr()));
        checked(libc::pipe(done.as_mut_ptr()));
        let pid = checked(libc::fork());
        if pid == 0 {
            conformance_probes::arm_alarm_ms(5000);
            transfer(start[0], false);
            actor(dirs[1], 1, n);
            transfer(done[1], true);
            transfer(start[0], false);
            libc::_exit(0);
        }
        transfer(start[1], true);
        actor(dirs[0], 0, n);
        transfer(done[0], false);
        transfer(start[1], true);
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        assert_eq!(status, 0);
    }
    unsafe {
        conformance_probes::disarm_alarm();
    }
    println!("namespace_scale={n}");
    println!("namespace_population={population}");
    println!("namespace_actors=2");
    println!("namespace_complete=1");
}
