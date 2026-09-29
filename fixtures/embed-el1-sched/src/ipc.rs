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
}
impl Drop for Channel {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::close(self.read) }, 0, "close reader");
        if self.write != self.read {
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
