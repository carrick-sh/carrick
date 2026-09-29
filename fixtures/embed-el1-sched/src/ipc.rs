//! Real pipe/eventfd request-response workloads. Output reports completed
//! operations only; EL1 execution and parks are measured by the embed runner.
use std::sync::{Arc, Barrier};

struct Channel {
    read: i32,
    write: i32,
}
impl Channel {
    fn new(eventfd: bool) -> Self {
        if eventfd {
            let fd = unsafe { libc::eventfd(0, 0) };
            assert!(fd >= 0, "eventfd: {}", std::io::Error::last_os_error());
            Self {
                read: fd,
                write: fd,
            }
        } else {
            let (read, write) = super::pipe_pair();
            Self { read, write }
        }
    }
    fn send(&self, value: u64) {
        let bytes = value.to_ne_bytes();
        assert_eq!(
            unsafe { libc::write(self.write, bytes.as_ptr().cast(), bytes.len()) },
            8,
            "send"
        );
    }
    fn receive(&self) -> u64 {
        let mut bytes = [0u8; 8];
        assert_eq!(
            unsafe { libc::read(self.read, bytes.as_mut_ptr().cast(), bytes.len()) },
            8,
            "receive"
        );
        u64::from_ne_bytes(bytes)
    }
    fn send_vector(&self, value: u64) {
        let mut bytes = value.to_ne_bytes();
        let iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: 8,
        };
        assert_eq!(unsafe { libc::writev(self.write, &iov, 1) }, 8, "writev");
    }
    fn receive_vector(&self) -> u64 {
        let mut bytes = [0u8; 8];
        let iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: 8,
        };
        assert_eq!(unsafe { libc::readv(self.read, &iov, 1) }, 8, "readv");
        u64::from_ne_bytes(bytes)
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        if self.read >= 0 {
            assert_eq!(unsafe { libc::close(self.read) }, 0, "close reader");
        }
        if self.write >= 0 && self.write != self.read {
            assert_eq!(unsafe { libc::close(self.write) }, 0, "close writer");
        }
    }
}

pub fn pairs(kind: &str, pairs: usize, rounds: usize) -> i32 {
    assert!(matches!(kind, "pipe" | "eventfd"));
    assert!(matches!(pairs, 1 | 8 | 64));
    assert!(rounds > 0);
    let start = Arc::new(Barrier::new(2 * pairs + 1));
    let mut workers = Vec::with_capacity(2 * pairs);
    for pair in 0..pairs {
        let request = Arc::new(Channel::new(kind == "eventfd"));
        let response = Arc::new(Channel::new(kind == "eventfd"));
        let peer_request = Arc::clone(&request);
        let peer_response = Arc::clone(&response);
        let peer_start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            peer_start.wait();
            for round in 0..rounds {
                let expected = ((pair as u64 + 1) << 32) | (round as u64 + 1);
                assert_eq!(peer_request.receive(), expected, "request identity");
                peer_response.send(expected ^ 0x1000_0000);
            }
            0
        }));
        let client_start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            client_start.wait();
            let mut completed = 0usize;
            for round in 0..rounds {
                let value = ((pair as u64 + 1) << 32) | (round as u64 + 1);
                request.send(value);
                assert_eq!(response.receive(), value ^ 0x1000_0000, "response identity");
                completed += 1;
            }
            completed
        }));
    }
    start.wait();
    let completed: usize = workers
        .into_iter()
        .map(|worker| worker.join().expect("IPC worker"))
        .sum();
    println!("ipc-pairs kind={kind} pairs={pairs} rounds={rounds} completed={completed}");
    i32::from(completed != pairs * rounds)
}

/// Fork before creating threads: both processes inherit the same OFDs but
/// independently publish their descriptor namespaces to EL1.
pub fn processes(kind: &str, pairs: usize, rounds: usize) -> i32 {
    assert!(matches!(kind, "pipe" | "eventfd"));
    assert!(matches!(pairs, 1 | 8 | 64));
    assert!(rounds > 0);
    let channels: Vec<_> = (0..pairs)
        .map(|_| {
            (
                Channel::new(kind == "eventfd"),
                Channel::new(kind == "eventfd"),
            )
        })
        .collect();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    let child = pid == 0;
    let workers: Vec<_> = channels
        .into_iter()
        .enumerate()
        .map(|(pair, (request, response))| {
            std::thread::spawn(move || {
                for round in 0..rounds {
                    let value = ((pair as u64 + 1) << 32) | (round as u64 + 1);
                    if child {
                        assert_eq!(request.receive(), value, "inherited request identity");
                        response.send(value ^ 0x1000_0000);
                    } else {
                        request.send(value);
                        assert_eq!(
                            response.receive(),
                            value ^ 0x1000_0000,
                            "inherited response identity"
                        );
                    }
                }
                rounds
            })
        })
        .collect();
    let completed: usize = workers
        .into_iter()
        .map(|worker| worker.join().expect("cross-process IPC worker"))
        .sum();
    assert_eq!(completed, pairs * rounds);
    if child {
        unsafe { libc::_exit(0) }
    }
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, 0) },
        pid,
        "wait child"
    );
    assert!(libc::WIFEXITED(status), "child status {status}");
    assert_eq!(libc::WEXITSTATUS(status), 0, "child status {status}");
    println!("ipc-processes kind={kind} pairs={pairs} rounds={rounds} completed={completed}");
    0
}

/// Separate fork tables share descriptions. Replacing a parent slot must not
/// redirect the child's inherited endpoint; final writer close must yield EOF.
pub fn lifetime() -> i32 {
    const ROUNDS: u64 = 128;
    let mut request = Channel::new(false);
    let mut response = Channel::new(false);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        assert_eq!(unsafe { libc::close(request.write) }, 0);
        request.write = -1;
        assert_eq!(unsafe { libc::close(response.read) }, 0);
        response.read = -1;
        for round in 1..=ROUNDS {
            assert_eq!(request.receive(), round);
            response.send(round ^ 0x1000);
        }
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::read(request.read, (&mut byte as *mut u8).cast(), 1) },
            0,
            "final writer close must produce EOF"
        );
        response.send(0xeeee);
        drop(request);
        drop(response);
        unsafe { libc::_exit(0) }
    }
    assert_eq!(unsafe { libc::close(response.write) }, 0);
    response.write = -1;
    let replacement = unsafe { libc::eventfd(42, libc::EFD_NONBLOCK) };
    assert!(replacement >= 0 && replacement != request.read);
    assert_eq!(
        unsafe { libc::dup2(replacement, request.read) },
        request.read
    );
    assert_eq!(unsafe { libc::close(replacement) }, 0);
    assert_eq!(request.receive(), 42, "parent replacement identity");
    for round in 1..=ROUNDS {
        request.send(round);
        assert_eq!(
            response.receive(),
            round ^ 0x1000,
            "child retained original endpoint"
        );
    }
    assert_eq!(unsafe { libc::close(request.write) }, 0);
    request.write = -1;
    assert_eq!(response.receive(), 0xeeee, "child observed EOF");
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    println!("ipc-lifetime completed=128 reused=1 eof=1 child_exit=0");
    0
}

/// Vector I/O crosses the host dispatcher; scalar I/O uses the EL1 adapter.
/// Alternate both venues on each shared object, checking every transferred value.
pub fn mixed(kind: &str) -> i32 {
    assert!(matches!(kind, "pipe" | "eventfd"));
    let request = Arc::new(Channel::new(kind == "eventfd"));
    let response = Arc::new(Channel::new(kind == "eventfd"));
    let peer_request = Arc::clone(&request);
    let peer_response = Arc::clone(&response);
    let peer = std::thread::spawn(move || {
        for round in 1u64..=128 {
            let value = if round % 2 == 0 {
                peer_request.receive_vector()
            } else {
                peer_request.receive()
            };
            assert_eq!(value, round, "mixed request");
            if round % 2 == 0 {
                peer_response.send(value ^ 0x1000);
            } else {
                peer_response.send_vector(value ^ 0x1000);
            }
        }
    });
    for round in 1u64..=128 {
        if round % 2 == 0 {
            request.send(round);
        } else {
            request.send_vector(round);
        }
        let value = if round % 2 == 0 {
            response.receive_vector()
        } else {
            response.receive()
        };
        assert_eq!(value, round ^ 0x1000, "mixed response");
    }
    peer.join().expect("mixed IPC peer");
    println!("ipc-mixed kind={kind} completed=128");
    0
}
