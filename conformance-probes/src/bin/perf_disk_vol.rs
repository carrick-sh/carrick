//! Perf probe: bulk file IO over a directory (env `BENCH_DIR`, default `/mnt`),
//! for the volume-mount-vs-virtiofs disk test. Writes a SIZE-byte file (fsync),
//! then reads it back, reporting write & read throughput in MB/s (HIGHER is
//! better). Under `carrick run --fs host -v <host>:/mnt` and
//! `docker run -v <host>:/mnt` this measures the BIND-MOUNT path — carrick's
//! direct host FD vs Docker's virtiofs VM-boundary round-trip — the sharpest
//! test of the "no virtiofs abstraction" disk thesis. Natively (`BENCH_DIR` =
//! the host scratch dir) it is the host APFS ceiling.
//!
//! Output (key=value lines, parsed not diffed):
//!   disk_vol_write_mbps=<f>  disk_vol_read_mbps=<f>  bytes=<u>  nproc=<u>
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::thread;
use std::time::Instant;

const SIZE: usize = 64 * 1024 * 1024; // 64 MiB
const CHUNK: usize = 1024 * 1024; // 1 MiB

fn nproc() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
}

fn main() {
    let dir = std::env::var("BENCH_DIR").unwrap_or_else(|_| "/mnt".to_string());
    let path = format!("{dir}/carrick_bench_vol.dat");
    let chunk = vec![0xABu8; CHUNK];

    // WRITE: create + write SIZE bytes + fsync (force it through the fs path,
    // not just into the page cache).
    let t0 = Instant::now();
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("create");
        let mut written = 0usize;
        while written < SIZE {
            f.write_all(&chunk).expect("write");
            written += CHUNK;
        }
        f.sync_all().expect("fsync");
    }
    let wsecs = t0.elapsed().as_secs_f64();

    // READ: re-open and drain. (Just-written data may be cached; that cache
    // path is itself part of each engine's fs cost, measured identically.)
    let t1 = Instant::now();
    {
        let mut f = File::open(&path).expect("open read");
        let mut buf = vec![0u8; CHUNK];
        let mut total = 0usize;
        loop {
            let n = f.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            total += n;
        }
        assert!(total >= SIZE, "short read");
    }
    let rsecs = t1.elapsed().as_secs_f64();

    let _ = std::fs::remove_file(&path);

    println!("disk_vol_write_mbps={:.1}", (SIZE as f64) / 1.0e6 / wsecs);
    println!("disk_vol_read_mbps={:.1}", (SIZE as f64) / 1.0e6 / rsecs);
    println!("bytes={}", SIZE);
    println!("nproc={}", nproc());
}
