//! Several live multi-threaded guest processes reading regular files that
//! enter the EL1 file zone, each verifying every byte it reads.
//!
//! The shape is `go build`'s: parallel processes, each with more threads than
//! the carrier has vCPUs, opening, reading and closing files, and writing new
//! files that a fresh open reads back. Every file's content names the file and
//! the record offset (16-byte records `NNNNNNN:OOOOOOO\n`), so a wrong byte
//! says which file and offset it really came from.
//!
//! The contract (`kernel.el1.files.cross-process-readers`): EL1 serves a
//! thread's fds only through that thread's own file table. When a vCPU's
//! current-task record named another thread's table, EL1 served one process's
//! reads with another process's files (wrong bytes, early EOF, EBADF writes).
//!
//! `zone-readers [rounds [procs [threads [iters]]]]` (parent): create the
//! files, run `rounds` rounds of `procs` children, print `zone_readers_ok` or
//! `zone_readers_failed ...` and exit 1.
//! `zone-readers child <round> <threads> <iters>`: one reader process.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const DIR: &str = "/tmp/zone-readers";
const STATIC_FILES: u64 = 100;
/// Defaults for `rounds procs threads iters`.
const SHAPE: [u64; 4] = [2, 4, 8, 40];

static MISMATCHES: AtomicU64 = AtomicU64::new(0);

fn content(id: u64, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 16);
    let mut record = 0u64;
    while out.len() < size {
        out.extend_from_slice(format!("{id:07}:{record:07x}\n").as_bytes());
        record += 1;
    }
    out.truncate(size);
    out
}

fn size_for(id: u64) -> usize {
    512 + ((id * 7919) % (120 * 1024)) as usize
}

/// A tiny xorshift so the fixture needs no crates.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

fn check(how: &str, path: &str, got: &[u8], want: &[u8]) {
    if got == want {
        return;
    }
    MISMATCHES.fetch_add(1, Ordering::Relaxed);
    let first = got.iter().zip(want).take_while(|(a, b)| a == b).count();
    let at = first & !15;
    let got_record = got.get(at..(at + 16).min(got.len())).unwrap_or(&[]);
    eprintln!(
        "MISMATCH pid={} {how} {path} len={} want={} first_diff={first} got_record={:?}",
        std::process::id(),
        got.len(),
        want.len(),
        String::from_utf8_lossy(got_record)
    );
}

/// read(2) in 4 KiB steps, or pread(2) in 8 KiB steps, to EOF.
fn read_all(path: &str, positional: bool) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len() as usize;
    let mut buf = vec![0u8; size + 512];
    let mut n = 0;
    loop {
        let step = if positional { 8192 } else { 4096 };
        let end = (n + step).min(buf.len());
        let got = if positional {
            file.read_at(&mut buf[n..end], n as u64)?
        } else {
            file.read(&mut buf[n..end])?
        };
        if got == 0 {
            break;
        }
        n += got;
    }
    buf.truncate(n);
    Ok(buf)
}

fn write_and_read_back(id: u64) {
    let path = format!("{DIR}/w-{id}.tmp");
    let data = content(id, size_for(id));
    let written = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| {
            for chunk in data.chunks(3000) {
                file.write_all(chunk)?;
            }
            Ok(())
        });
    if let Err(error) = written {
        MISMATCHES.fetch_add(1, Ordering::Relaxed);
        eprintln!("MISMATCH pid={} write {path}: {error}", std::process::id());
        return;
    }
    match read_all(&path, false) {
        Ok(got) => check("readback", &path, &got, &data),
        Err(error) => {
            MISMATCHES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "MISMATCH pid={} readback {path}: {error}",
                std::process::id()
            );
        }
    }
    let _ = std::fs::rename(&path, format!("{DIR}/w-{id}"));
}

fn child(round: u64, threads: u64, iters: u64) {
    let pid = u64::from(std::process::id());
    std::thread::scope(|scope| {
        for thread in 0..threads {
            scope.spawn(move || {
                let mut rng = Rng(pid * 1_000_003 + thread * 7_919 + round + 1);
                for iter in 0..iters {
                    match rng.below(10) {
                        0..=7 => {
                            let id = rng.below(STATIC_FILES);
                            let path = format!("{DIR}/s-{id}");
                            match read_all(&path, rng.below(2) == 1) {
                                Ok(got) => check("static", &path, &got, &content(id, size_for(id))),
                                Err(error) => {
                                    MISMATCHES.fetch_add(1, Ordering::Relaxed);
                                    eprintln!("MISMATCH pid={pid} read {path}: {error}");
                                }
                            }
                        }
                        _ => write_and_read_back(1_000_000 + pid * 1000 + thread * 100 + iter),
                    }
                    if iter % 8 == 7 {
                        // A blocking wait: the vCPU may be reclaimed and the
                        // thread resumed on another mailbox slot.
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            });
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let number = |index: usize, default: u64| {
        args.get(index)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    if args.get(1).map(String::as_str) == Some("child") {
        child(number(2, 0), number(3, SHAPE[2]), number(4, SHAPE[3]));
        std::process::exit(if MISMATCHES.load(Ordering::Relaxed) == 0 {
            0
        } else {
            3
        });
    }
    let [rounds, procs, threads, iters] = [0, 1, 2, 3].map(|i| number(i + 1, SHAPE[i]));
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).expect("create the file directory");
    for id in 0..STATIC_FILES {
        std::fs::write(format!("{DIR}/s-{id}"), content(id, size_for(id))).expect("create a file");
    }
    let mut failed_children = 0;
    for round in 0..rounds {
        let children: Vec<_> = (0..procs)
            .map(|_| {
                Command::new(&args[0])
                    .args(["child", &round.to_string()])
                    .args([threads.to_string(), iters.to_string()])
                    .stdin(Stdio::null())
                    .spawn()
                    .expect("spawn a reader process")
            })
            .collect();
        for mut child in children {
            if !child.wait().map(|status| status.success()).unwrap_or(false) {
                failed_children += 1;
            }
        }
    }
    if failed_children == 0 {
        println!("zone_readers_ok");
    } else {
        println!("zone_readers_failed children={failed_children}");
        std::process::exit(1);
    }
}
