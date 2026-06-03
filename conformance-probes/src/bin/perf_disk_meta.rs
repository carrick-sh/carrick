//! Perf probe: deep-path stat() storm, self-timed in-guest. Creates a fixed
//! DEPTH-deep directory chain with a leaf file, then stat()s the full leaf
//! path ITERS times, timing each, and reports its own p50/p95/min in
//! microseconds. LOWER is better. Exercises path-resolution cost: carrick's
//! cap-std per-component openat re-walk (no openat2/RESOLVE_BENEATH on macOS,
//! plus redundant backend walks) amplifies with depth, vs docker's single
//! in-kernel VFS walk. This is the thesis's honest exception — carrick is
//! expected to LOSE here; the probe quantifies by how much.
//!
//! Output (key=value lines, parsed by the perf gate, NOT diffed):
//!   stat_p50_us=<f>  stat_p95_us=<f>  stat_min_us=<f>  depth=<u>  iters=<u>  nproc=<u>
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Instant;

const DEPTH: usize = 8;
const ITERS: usize = 2000;
const WARMUP: usize = 200;

fn nproc() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
}

fn main() {
    // Build /tmp/perfmeta/l0/l1/.../l{DEPTH-1}/leaf inside the guest's own fs
    // (carrick: --fs host scratch; docker: container overlayfs upper) — both
    // engines stat a self-created path of identical depth, so the work is the
    // same and only the path-resolution cost differs.
    let mut dir = PathBuf::from("/tmp/perfmeta");
    for i in 0..DEPTH {
        dir.push(format!("l{i}"));
    }
    fs::create_dir_all(&dir).expect("create chain");
    let leaf = dir.join("leaf");
    fs::write(&leaf, b"x").expect("write leaf");

    // Warmup (untimed): prime caches.
    for _ in 0..WARMUP {
        let _ = fs::metadata(&leaf).expect("warmup stat");
    }

    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let _ = fs::metadata(&leaf).expect("stat");
        samples_ns.push(t0.elapsed().as_nanos());
    }

    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };
    println!("stat_p50_us={:.3}", pct(0.50));
    println!("stat_p95_us={:.3}", pct(0.95));
    println!("stat_min_us={:.3}", samples_ns[0] as f64 / 1000.0);
    println!("depth={}", DEPTH);
    println!("iters={}", samples_ns.len());
    println!("nproc={}", nproc());
}
