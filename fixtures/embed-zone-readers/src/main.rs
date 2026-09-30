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
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const DIR: &str = "/tmp/zone-readers";
const STATIC_FILES: u64 = 100;
/// Defaults for `rounds procs threads iters`.
const SHAPE: [u64; 4] = [2, 4, 8, 40];

static MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// Forensics for a mismatch, recorded on every read and consulted only when
/// one fails: the destination buffer of each recent read in this process,
/// so a wrong record can be traced to the buffer that legitimately held it.
/// The difference between the two virtual addresses separates the
/// mechanisms: a multiple of 2 MiB is one page table linked under two
/// entries; anything else is one frame mapped (or cached in a TLB) at two
/// addresses. Lock-free and racy by design: a torn entry misattributes a
/// diagnostic, never a verdict.
const RING: usize = 4096;
static RING_NEXT: AtomicUsize = AtomicUsize::new(0);
static SEQ: AtomicU64 = AtomicU64::new(1);
static RING_VA: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];
/// `file id << 32 | buffer length`.
static RING_META: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];
/// `start sequence << 32 | end sequence` (0 while the read runs).
static RING_SEQ: [AtomicU64; RING] = [const { AtomicU64::new(0) }; RING];

fn tid() -> u64 {
    // SAFETY: gettid(2) takes no arguments and cannot fail.
    unsafe { raw_syscall0(178) }
}

/// aarch64 Linux `svc #0` with no arguments (the fixture needs no crates).
unsafe fn raw_syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        std::arch::asm!("svc #0", in("x8") nr, lateout("x0") ret, options(nostack));
    }
    ret
}

/// Record a read's destination; returns the ring index to close.
fn ring_open(id: u64, va: usize, len: usize) -> (usize, u64) {
    let index = RING_NEXT.fetch_add(1, Ordering::Relaxed) % RING;
    let start = SEQ.fetch_add(1, Ordering::Relaxed);
    RING_VA[index].store(va as u64, Ordering::Relaxed);
    RING_META[index].store((id << 32) | (len as u64 & 0xffff_ffff), Ordering::Relaxed);
    RING_SEQ[index].store(start << 32, Ordering::Release);
    (index, start)
}

fn ring_close(index: usize, start: u64) {
    let end = SEQ.fetch_add(1, Ordering::Relaxed);
    let _ = RING_SEQ[index].compare_exchange(
        start << 32,
        (start << 32) | (end & 0xffff_ffff),
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
}

/// Parse a `NNNNNNN:OOOOOOO\n` record into (file id, record index).
fn parse_record(record: &[u8]) -> Option<(u64, u64)> {
    if record.len() != 16 || record[7] != b':' || record[15] != b'\n' {
        return None;
    }
    let id = std::str::from_utf8(&record[..7]).ok()?.parse().ok()?;
    let index = u64::from_str_radix(std::str::from_utf8(&record[8..15]).ok()?, 16).ok()?;
    Some((id, index))
}

/// Describe every run of wrong 16-byte records in `got` (at `got_va`): its
/// buffer range, the file and offset its bytes really came from, and every
/// recent read of that file in this process whose buffer held those bytes.
fn forensics(got: &[u8], got_va: usize, want: &[u8], read_seq: u64) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "tid={} buf_va=0x{got_va:x} read_seq={read_seq} now_seq={}",
        tid(),
        SEQ.load(Ordering::Relaxed)
    );
    let records = got.len().min(want.len()) / 16;
    let mut runs = 0;
    let mut record = 0;
    while record < records && runs < 8 {
        let at = record * 16;
        if got[at..at + 16] == want[at..at + 16] {
            record += 1;
            continue;
        }
        while record < records
            && got[record * 16..record * 16 + 16] != want[record * 16..record * 16 + 16]
        {
            record += 1;
        }
        runs += 1;
        let first = &got[at..at + 16];
        let _ = write!(
            out,
            " | run [0x{:x},0x{:x}) page_off=0x{:x}",
            at,
            record * 16,
            (got_va + at) & 0xfff
        );
        let Some((source_id, source_record)) = parse_record(first) else {
            let _ = write!(out, " got={:02x?}", &first[..8]);
            continue;
        };
        let source_off = source_record as usize * 16;
        let _ = write!(
            out,
            " from id={source_id} off=0x{source_off:x} shift={}",
            at as i64 - source_off as i64
        );
        let mut matches = 0;
        for index in 0..RING {
            let meta = RING_META[index].load(Ordering::Acquire);
            if meta >> 32 != source_id || matches >= 4 {
                continue;
            }
            let va = RING_VA[index].load(Ordering::Relaxed) as usize;
            let seqs = RING_SEQ[index].load(Ordering::Acquire);
            let source_va = va + source_off;
            let ours = got_va + at;
            let delta = ours as i64 - source_va as i64;
            let _ = write!(
                out,
                " [holder va=0x{va:x} len={} seq={}..{} delta={}0x{:x} delta%2M=0x{:x}]",
                meta & 0xffff_ffff,
                seqs >> 32,
                seqs & 0xffff_ffff,
                if delta < 0 { "-" } else { "" },
                delta.unsigned_abs(),
                delta.unsigned_abs() % (2 << 20),
            );
            matches += 1;
        }
        if matches == 0 {
            out.push_str(" [no holder in this process]");
        }
    }
    out
}

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

fn check(how: &str, path: &str, got: &[u8], want: &[u8], read_seq: u64) {
    if got == want {
        return;
    }
    // Snapshot at once, then compare the snapshot: a mismatch whose bytes
    // change while this report is built is a store that reached the buffer
    // after read(2) returned, and must be named as such rather than
    // described from bytes that have since become correct.
    let snapshot: Vec<u8> = got
        .iter()
        // SAFETY: `byte` is a valid reference into `got`.
        .map(|byte| unsafe { std::ptr::read_volatile(byte) })
        .collect();
    MISMATCHES.fetch_add(1, Ordering::Relaxed);
    let first = snapshot
        .iter()
        .zip(want)
        .take_while(|(a, b)| a == b)
        .count();
    let at = first & !15;
    let got_record = snapshot
        .get(at..(at + 16).min(snapshot.len()))
        .unwrap_or(&[]);
    let want_record = want.get(at..(at + 16).min(want.len())).unwrap_or(&[]);
    eprintln!(
        "MISMATCH pid={} {how} {path} len={} want={} first_diff={first} got_record={:02x?} want_record={:02x?} snapshot_matches={}",
        std::process::id(),
        snapshot.len(),
        want.len(),
        got_record,
        want_record,
        snapshot == want
    );
    eprintln!(
        "FORENSICS pid={} {how} {path} {}",
        std::process::id(),
        forensics(&snapshot, got.as_ptr() as usize, want, read_seq)
    );
    // Were the wrong bytes still wrong after the report? Late arrival names
    // an asynchronous or unordered writer; persistent names a wrong copy.
    let later: Vec<u8> = got
        .iter()
        // SAFETY: as above.
        .map(|byte| unsafe { std::ptr::read_volatile(byte) })
        .collect();
    let first_later = later.iter().zip(want).take_while(|(a, b)| a == b).count();
    eprintln!(
        "LATE pid={} {how} {path} changed_since_snapshot={} later_matches={} later_first_diff={first_later}",
        std::process::id(),
        later != snapshot,
        later == want
    );
}

/// read(2) in 4 KiB steps, or pread(2) in 8 KiB steps, to EOF. Returns the
/// bytes and the read's forensic sequence number.
fn read_all(id: u64, path: &str, positional: bool) -> std::io::Result<(Vec<u8>, u64)> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len() as usize;
    let mut buf = vec![0u8; size + 512];
    let (ring, seq) = ring_open(id, buf.as_ptr() as usize, buf.len());
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
    ring_close(ring, seq);
    buf.truncate(n);
    Ok((buf, seq))
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
    match read_all(id, &path, false) {
        Ok((got, seq)) => {
            check("readback", &path, &got, &data, seq);
            if got != data {
                // Where the wrong bytes live: the file, the written source,
                // or only the destination of that one read.
                let reread = read_all(id, &path, false).map(|(again, _)| again == data);
                let source_intact = data == content(id, size_for(id));
                eprintln!(
                    "READBACK_SPLIT pid={} {path} reread_matches={reread:?} source_intact={source_intact} source_va=0x{:x}",
                    std::process::id(),
                    data.as_ptr() as usize
                );
            }
        }
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
                            match read_all(id, &path, rng.below(2) == 1) {
                                Ok((got, seq)) => {
                                    check("static", &path, &got, &content(id, size_for(id)), seq)
                                }
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
    let mut failures: Vec<String> = Vec::new();
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
            let pid = child.id();
            match child.wait() {
                Ok(status) if status.success() => {}
                // Every failure names its reason here, on both streams, so a
                // child that died by a signal, or whose own report was lost,
                // is never a silent failure.
                outcome => {
                    failed_children += 1;
                    let reason = match outcome {
                        Ok(status) => format!(
                            "code={:?} signal={:?} core={}",
                            status.code(),
                            status.signal(),
                            status.core_dumped()
                        ),
                        Err(error) => format!("wait failed: {error}"),
                    };
                    let line = format!("CHILD_FAILED round={round} pid={pid} {reason}");
                    eprintln!("{line}");
                    failures.push(line);
                }
            }
        }
    }
    if failed_children == 0 {
        println!("zone_readers_ok");
    } else {
        println!(
            "zone_readers_failed children={failed_children} [{}]",
            failures.join("; ")
        );
        std::process::exit(1);
    }
}
