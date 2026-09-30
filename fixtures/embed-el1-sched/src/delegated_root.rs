//! Two-process delegated-root witnesses (EL1 migration stage S3).
//!
//! - `delegated-root-vma <rounds>`: parent and forked child concurrently
//!   `mmap`/`munmap`/`mprotect` their own address spaces (and a pre-fork
//!   COW-shared region). Each process snapshots its own `/proc/self/maps`
//!   before and after every step and demands the exact row set the operation
//!   sequence implies. A row that belongs to the peer's mm, or a row the
//!   operations do not imply, is a mismatch.
//! - `delegated-root-fixed-cow <pages> <rounds>`: the child `MAP_FIXED`-replaces
//!   ranges still COW-shared with the parent (one untouched, one already
//!   COW-broken); the parent later replaces a range the child still shares.
//!   Neither side's bytes may change except in its own replaced ranges.
//! - `kick-first-read <rounds>`: fork, a parent stage-1 pause (a helper thread
//!   maps, touches and unmaps, kicking every vCPU), then the child's first pipe
//!   read. The read is bracketed by two intercepted `sched_yield` markers that
//!   the embed test uses to sample `host_work_publications`.
//!
//! Every wait is bounded; a lost wake is a failed line, never a hang.

use super::{poll_read_byte, poll_read_count, write_count, write_signal_byte};
use std::io::Write;

const PROT_RW: libc::c_int = libc::PROT_READ | libc::PROT_WRITE;

/// `sched_yield` marker arguments, recognised by the embed interceptor.
const MARKER_BEFORE_READ: u64 = 0x4b49_434b_0001;
const MARKER_AFTER_READ: u64 = 0x4b49_434b_0002;

fn page_size() -> usize {
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw > 0 { raw as usize } else { 16_384 }
}

fn anon(addr: usize, len: usize, prot: libc::c_int, fixed: bool) -> Option<usize> {
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | if fixed { libc::MAP_FIXED } else { 0 };
    let ptr = unsafe { libc::mmap(addr as *mut libc::c_void, len, prot, flags, -1, 0) };
    (ptr != libc::MAP_FAILED).then_some(ptr as usize)
}

fn perm_bits(prot: libc::c_int) -> [u8; 4] {
    [
        if prot & libc::PROT_READ != 0 {
            b'r'
        } else {
            b'-'
        },
        if prot & libc::PROT_WRITE != 0 {
            b'w'
        } else {
            b'-'
        },
        if prot & libc::PROT_EXEC != 0 {
            b'x'
        } else {
            b'-'
        },
        b'p',
    ]
}

// ---------------------------------------------------------------------------
// /proc/self/maps snapshots and the row model

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Row {
    start: usize,
    end: usize,
    perm: [u8; 4],
    /// 0 for an anonymous row, otherwise a hash of the path column.
    path: u64,
}

/// Capacity reserved up front so the snapshot/model loop never grows the
/// heap: a `brk` or `mmap` issued by the allocator would itself change the
/// maps being compared.
const ROW_CAPACITY: usize = 2048;
const MAPS_BUFFER: usize = 1 << 19;

struct Maps {
    buf: Vec<u8>,
    rows: Vec<Row>,
}

impl Maps {
    fn new() -> Self {
        Self {
            buf: vec![0u8; MAPS_BUFFER],
            rows: Vec::with_capacity(ROW_CAPACITY),
        }
    }

    /// Replace `self.rows` with the current process's rows (excluding the
    /// allocator-driven `[heap]` and `[stack]`), merged where Linux merges.
    fn snapshot(&mut self) -> bool {
        let fd = unsafe { libc::open(c"/proc/self/maps".as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            return false;
        }
        let mut have = 0usize;
        loop {
            if have == self.buf.len() {
                unsafe { libc::close(fd) };
                return false;
            }
            let n = unsafe {
                libc::read(
                    fd,
                    self.buf[have..].as_mut_ptr().cast(),
                    self.buf.len() - have,
                )
            };
            if n < 0 {
                unsafe { libc::close(fd) };
                return false;
            }
            if n == 0 {
                break;
            }
            have += n as usize;
        }
        unsafe { libc::close(fd) };
        self.rows.clear();
        let Ok(text) = std::str::from_utf8(&self.buf[..have]) else {
            return false;
        };
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
                return false;
            };
            let _offset = fields.next();
            let _device = fields.next();
            let _inode = fields.next();
            let path = fields.next().unwrap_or("");
            if path == "[heap]" || path == "[stack]" {
                continue;
            }
            let Some((start, end)) = range.split_once('-') else {
                return false;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                return false;
            };
            let pb = perms.as_bytes();
            if pb.len() < 4 || self.rows.len() == ROW_CAPACITY {
                return false;
            }
            let hash = path.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
            });
            self.rows.push(Row {
                start,
                end,
                perm: [pb[0], pb[1], pb[2], pb[3]],
                path: if path.is_empty() { 0 } else { hash | 1 },
            });
        }
        normalize(&mut self.rows);
        true
    }
}

fn normalize(rows: &mut Vec<Row>) {
    rows.sort_unstable_by_key(|row| row.start);
    let mut out = 0usize;
    for i in 0..rows.len() {
        let row = rows[i];
        if out > 0 {
            let prev = rows[out - 1];
            if prev.end == row.start && prev.path == 0 && row.path == 0 && prev.perm == row.perm {
                rows[out - 1].end = row.end;
                continue;
            }
        }
        rows[out] = row;
        out += 1;
    }
    rows.truncate(out);
}

fn model_unmap(rows: &mut Vec<Row>, start: usize, end: usize) {
    let mut i = 0;
    while i < rows.len() {
        let row = rows[i];
        if row.end <= start || row.start >= end {
            i += 1;
        } else if row.start < start && row.end > end {
            rows[i].end = start;
            rows.insert(i + 1, Row { start: end, ..row });
            i += 2;
        } else if row.start < start {
            rows[i].end = start;
            i += 1;
        } else if row.end > end {
            rows[i].start = end;
            i += 1;
        } else {
            rows.remove(i);
        }
    }
}

/// Model `mmap`/`MAP_FIXED` and `mprotect` of a range that is fully anonymous:
/// both leave exactly one new anonymous row with `perm` over `[start, end)`.
fn model_set(rows: &mut Vec<Row>, start: usize, end: usize, perm: [u8; 4]) {
    model_unmap(rows, start, end);
    rows.push(Row {
        start,
        end,
        perm,
        path: 0,
    });
    normalize(rows);
}

fn first_difference(expected: &[Row], actual: &[Row]) -> String {
    for i in 0..expected.len().max(actual.len()) {
        if expected.get(i) != actual.get(i) {
            return format!(
                "row {i}: expected {:x?} actual {:x?} (expected rows {} actual rows {})",
                expected.get(i),
                actual.get(i),
                expected.len(),
                actual.len()
            );
        }
    }
    "identical".to_owned()
}

/// Snapshot and compare against the modelled rows.
fn check(maps: &mut Maps, model: &[Row], step: &str, mismatches: &mut u64) {
    if !maps.snapshot() {
        *mismatches += 1;
        println!("delegated-root-vma maps unreadable at {step}");
        return;
    }
    if maps.rows.as_slice() != model {
        *mismatches += 1;
        println!(
            "delegated-root-vma MISMATCH at {step}: {}",
            first_difference(model, &maps.rows)
        );
    }
}

// ---------------------------------------------------------------------------
// delegated-root-vma

const SHARED_PAGES: usize = 16;
const SHARED_SEED: u64 = 0x5348_4152_0000_0000;

struct VmaOutcome {
    ops: u64,
    mismatches: u64,
    semantic_failures: u64,
}

impl VmaOutcome {
    fn ok(&self) -> bool {
        self.mismatches == 0 && self.semantic_failures == 0
    }
}

fn vma_worker(child: bool, rounds: usize, shared: usize) -> VmaOutcome {
    let ps = page_size();
    let mid_prot = if child {
        libc::PROT_NONE
    } else {
        libc::PROT_READ
    };
    let mid_perm = perm_bits(mid_prot);
    let rw = perm_bits(PROT_RW);
    let role_mark: u64 = if child {
        0x4348_494c_4d41_524b
    } else {
        0x5041_5245_4d41_524b
    };
    let mut maps = Maps::new();
    let mut model: Vec<Row> = Vec::with_capacity(ROW_CAPACITY);
    let mut outcome = VmaOutcome {
        ops: 0,
        mismatches: 0,
        semantic_failures: 0,
    };

    if !maps.snapshot() {
        outcome.mismatches += 1;
        return outcome;
    }
    let mut baseline: Vec<Row> = Vec::with_capacity(ROW_CAPACITY);
    baseline.extend_from_slice(&maps.rows);

    for round in 0..rounds {
        model.clear();
        model.extend_from_slice(&maps.rows);

        // A: 8 pages; touch first and last; protect the middle two.
        let Some(a) = anon(0, 8 * ps, PROT_RW, false) else {
            outcome.semantic_failures += 1;
            return outcome;
        };
        model_set(&mut model, a, a + 8 * ps, rw);
        unsafe {
            (a as *mut u64).write_volatile(role_mark ^ round as u64);
            ((a + 7 * ps) as *mut u64).write_volatile(!role_mark ^ round as u64);
        }
        outcome.ops += 1;
        check(&mut maps, &model, "map A", &mut outcome.mismatches);

        if unsafe { libc::mprotect((a + 3 * ps) as *mut libc::c_void, 2 * ps, mid_prot) } != 0 {
            outcome.semantic_failures += 1;
            return outcome;
        }
        model_set(&mut model, a + 3 * ps, a + 5 * ps, mid_perm);
        outcome.ops += 1;
        check(
            &mut maps,
            &model,
            "protect A middle",
            &mut outcome.mismatches,
        );

        // B: 4 pages with a hole punched in the middle.
        let Some(b) = anon(0, 4 * ps, PROT_RW, false) else {
            outcome.semantic_failures += 1;
            return outcome;
        };
        model_set(&mut model, b, b + 4 * ps, rw);
        outcome.ops += 1;
        if unsafe { libc::munmap((b + ps) as *mut libc::c_void, 2 * ps) } != 0 {
            outcome.semantic_failures += 1;
            return outcome;
        }
        model_unmap(&mut model, b + ps, b + 3 * ps);
        outcome.ops += 1;
        check(&mut maps, &model, "hole in B", &mut outcome.mismatches);

        // Tail of A.
        if unsafe { libc::munmap((a + 7 * ps) as *mut libc::c_void, ps) } != 0 {
            outcome.semantic_failures += 1;
            return outcome;
        }
        model_unmap(&mut model, a + 7 * ps, a + 8 * ps);
        outcome.ops += 1;
        check(&mut maps, &model, "unmap A tail", &mut outcome.mismatches);

        // The pre-fork region, COW-shared with the peer: protect one page.
        let k = 1 + round % (SHARED_PAGES - 4);
        let page_addr = shared + k * ps;
        if unsafe { libc::mprotect(page_addr as *mut libc::c_void, ps, mid_prot) } != 0 {
            outcome.semantic_failures += 1;
            return outcome;
        }
        model_set(&mut model, page_addr, page_addr + ps, mid_perm);
        outcome.ops += 1;
        check(
            &mut maps,
            &model,
            "protect shared page",
            &mut outcome.mismatches,
        );

        // Bytes the peer cannot have changed in this mm.
        for probe in [0, SHARED_PAGES - 3] {
            let seen = unsafe { ((shared + probe * ps) as *const u64).read_volatile() };
            if seen != (SHARED_SEED | probe as u64) {
                outcome.semantic_failures += 1;
                println!("delegated-root-vma shared page {probe} changed: {seen:#x}");
            }
        }
        // Both roles write their own mark into the same COW-shared page; the
        // peer's mark must never appear in this mm.
        let mark_page = (shared + (SHARED_PAGES - 1) * ps) as *mut u64;
        unsafe { mark_page.write_volatile(role_mark ^ round as u64) };
        let seen = unsafe { mark_page.read_volatile() };
        if seen != role_mark ^ round as u64 {
            outcome.semantic_failures += 1;
            println!("delegated-root-vma cross-mm write visible: {seen:#x}");
        }

        if unsafe { libc::mprotect(page_addr as *mut libc::c_void, ps, PROT_RW) } != 0 {
            outcome.semantic_failures += 1;
            return outcome;
        }
        model_set(&mut model, page_addr, page_addr + ps, rw);
        outcome.ops += 1;
        check(
            &mut maps,
            &model,
            "restore shared page",
            &mut outcome.mismatches,
        );

        // Unmap what is left and require the exact starting rows back.
        if unsafe { libc::munmap(a as *mut libc::c_void, 7 * ps) } != 0
            || unsafe { libc::munmap(b as *mut libc::c_void, ps) } != 0
            || unsafe { libc::munmap((b + 3 * ps) as *mut libc::c_void, ps) } != 0
        {
            outcome.semantic_failures += 1;
            return outcome;
        }
        model_unmap(&mut model, a, a + 7 * ps);
        model_unmap(&mut model, b, b + ps);
        model_unmap(&mut model, b + 3 * ps, b + 4 * ps);
        outcome.ops += 3;
        check(
            &mut maps,
            &model,
            "unmap remainder",
            &mut outcome.mismatches,
        );
        if maps.rows != baseline {
            outcome.mismatches += 1;
            println!(
                "delegated-root-vma round {round} did not return to baseline: {}",
                first_difference(&baseline, &maps.rows)
            );
        }
    }
    outcome
}

pub fn concurrent_vma(rounds: usize) -> i32 {
    if rounds == 0 {
        println!("delegated-root-vma invalid rounds 0");
        return 1;
    }
    unsafe { libc::alarm(120) };
    let ps = page_size();
    let Some(shared) = anon(0, SHARED_PAGES * ps, PROT_RW, false) else {
        println!("delegated-root-vma shared mmap failed");
        return 1;
    };
    for page in 0..SHARED_PAGES {
        let ptr = (shared + page * ps) as *mut u64;
        unsafe { ptr.write_volatile(SHARED_SEED | page as u64) };
    }
    let mut ready = [0 as libc::c_int; 2];
    let mut go = [0 as libc::c_int; 2];
    let mut result = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(ready.as_mut_ptr()) } != 0
        || unsafe { libc::pipe(go.as_mut_ptr()) } != 0
        || unsafe { libc::pipe(result.as_mut_ptr()) } != 0
    {
        println!("delegated-root-vma pipe failed");
        return 1;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("delegated-root-vma fork failed");
        return 1;
    }
    let child = pid == 0;
    let rendezvous = if child {
        write_signal_byte(ready[1], b'R') && poll_read_byte(go[0], 5_000)
    } else {
        poll_read_byte(ready[0], 5_000) && write_signal_byte(go[1], b'G')
    };
    if !rendezvous {
        println!("delegated-root-vma rendezvous failed child={child}");
        if child {
            unsafe { libc::_exit(2) };
        }
        return 1;
    }
    let outcome = vma_worker(child, rounds, shared);
    let role = if child { "child" } else { "parent" };
    println!(
        "delegated-root-vma role={role} rounds={rounds} ops={} map_mismatches={} semantic_failures={} ok={}",
        outcome.ops,
        outcome.mismatches,
        outcome.semantic_failures,
        outcome.ok()
    );
    if child {
        let _ = write_count(result[1], u64::from(outcome.ok()));
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(if outcome.ok() { 0 } else { 1 }) };
    }
    let child_reported = poll_read_count(result[0], 30_000);
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let child_ok = waited == pid
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0
        && child_reported == Some(1);
    println!(
        "delegated-root-vma summary rounds={rounds} parent_ok={} child_ok={child_ok}",
        outcome.ok()
    );
    if outcome.ok() && child_ok { 0 } else { 1 }
}

// ---------------------------------------------------------------------------
// delegated-root-fixed-cow

fn pattern(round: usize, page: usize, word: usize) -> u64 {
    0xC0DE_0000_0000_0000 ^ ((round as u64) << 32) ^ ((page as u64) << 8) ^ word as u64
}

fn fill_pages(base: usize, ps: usize, pages: std::ops::Range<usize>, round: usize) {
    for page in pages {
        let ptr = (base + page * ps) as *mut u64;
        for word in 0..ps / 8 {
            unsafe { ptr.add(word).write_volatile(pattern(round, page, word)) };
        }
    }
}

fn pages_match(base: usize, ps: usize, pages: std::ops::Range<usize>, round: usize) -> bool {
    for page in pages {
        let ptr = (base + page * ps) as *const u64;
        for word in 0..ps / 8 {
            if unsafe { ptr.add(word).read_volatile() } != pattern(round, page, word) {
                return false;
            }
        }
    }
    true
}

fn pages_hold(base: usize, ps: usize, pages: std::ops::Range<usize>, value: u64) -> bool {
    for page in pages {
        let ptr = (base + page * ps) as *const u64;
        for word in 0..ps / 8 {
            if unsafe { ptr.add(word).read_volatile() } != value {
                return false;
            }
        }
    }
    true
}

fn set_pages(base: usize, ps: usize, pages: std::ops::Range<usize>, value: u64) {
    for page in pages {
        let ptr = (base + page * ps) as *mut u64;
        for word in 0..ps / 8 {
            unsafe { ptr.add(word).write_volatile(value) };
        }
    }
}

fn replace_fixed(base: usize, ps: usize, pages: std::ops::Range<usize>) -> bool {
    let addr = base + pages.start * ps;
    anon(addr, pages.len() * ps, PROT_RW, true) == Some(addr)
}

const CHILD_MARK: u64 = 0x4348_494c_4449_4646;
const PARENT_MARK: u64 = 0x5041_5245_4449_4646;

/// Returns whether the child behaved. `r1` is replaced while still shared and
/// untouched; `r2` is first written (COW-broken) and then replaced; `r3` is
/// left for the parent to replace while the child still shares it.
fn fixed_cow_child(
    base: usize,
    ps: usize,
    pages: usize,
    round: usize,
    to_parent: libc::c_int,
    from_parent: libc::c_int,
) -> bool {
    let r1 = pages / 4..pages / 2;
    let r2 = pages / 2..pages / 2 + pages / 4;
    let r3 = 0..pages / 8;
    let untouched = pages / 2 + pages / 4..pages;

    set_pages(base, ps, r2.clone(), CHILD_MARK ^ 1);
    if !replace_fixed(base, ps, r1.clone()) || !pages_hold(base, ps, r1.clone(), 0) {
        return false;
    }
    set_pages(base, ps, r1.clone(), CHILD_MARK);
    if !replace_fixed(base, ps, r2.clone()) || !pages_hold(base, ps, r2.clone(), 0) {
        return false;
    }
    set_pages(base, ps, r2.clone(), CHILD_MARK);
    if !pages_match(base, ps, r3.clone(), round) || !pages_match(base, ps, untouched.clone(), round)
    {
        return false;
    }
    if !write_signal_byte(to_parent, b'F') || !poll_read_byte(from_parent, 5_000) {
        return false;
    }
    // The parent replaced r3 and wrote; the child's view must be unchanged.
    pages_hold(base, ps, r1, CHILD_MARK)
        && pages_hold(base, ps, r2, CHILD_MARK)
        && pages_match(base, ps, r3, round)
        && pages_match(base, ps, untouched, round)
        && write_signal_byte(to_parent, b'D')
}

pub fn fixed_over_cow(pages: usize, rounds: usize) -> i32 {
    let ps = page_size();
    if pages < 16 || pages > 1024 || rounds == 0 {
        println!("delegated-root-fixed-cow invalid parameters pages={pages} rounds={rounds}");
        return 1;
    }
    unsafe { libc::alarm(120) };
    let Some(base) = anon(0, pages * ps, PROT_RW, false) else {
        println!("delegated-root-fixed-cow mmap failed");
        return 1;
    };
    let r1 = pages / 4..pages / 2;
    let r2 = pages / 2..pages / 2 + pages / 4;
    let r3 = 0..pages / 8;
    let mut maps = Maps::new();
    let mut fixed_maps = 0u64;
    for round in 0..rounds {
        fill_pages(base, ps, 0..pages, round);
        let mut p2c = [0 as libc::c_int; 2];
        let mut c2p = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0
        {
            println!("delegated-root-fixed-cow pipe failed round={round}");
            return 1;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("delegated-root-fixed-cow fork failed round={round}");
            return 1;
        }
        if pid == 0 {
            unsafe {
                libc::close(p2c[1]);
                libc::close(c2p[0]);
                libc::alarm(60);
            }
            let ok = fixed_cow_child(base, ps, pages, round, c2p[1], p2c[0]);
            let _ = std::io::stdout().flush();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        unsafe {
            libc::close(p2c[0]);
            libc::close(c2p[1]);
        }
        let mut parent_ok = poll_read_byte(c2p[0], 5_000);
        // The child replaced r1 and r2 in its own mm only.
        parent_ok &= pages_match(base, ps, 0..pages, round);
        parent_ok &= maps.snapshot()
            && maps.rows.iter().any(|row| {
                row.start <= base && row.end >= base + pages * ps && row.perm == perm_bits(PROT_RW)
            });
        if parent_ok {
            parent_ok &= replace_fixed(base, ps, r3.clone()) && pages_hold(base, ps, r3.clone(), 0);
            set_pages(base, ps, r3.clone(), PARENT_MARK);
            parent_ok &= write_signal_byte(p2c[1], b'P') && poll_read_byte(c2p[0], 5_000);
            parent_ok &= pages_match(base, ps, r1.clone(), round);
            parent_ok &= pages_match(base, ps, r2.clone(), round);
            parent_ok &= pages_hold(base, ps, r3.clone(), PARENT_MARK);
        }
        unsafe {
            libc::close(p2c[1]);
            libc::close(c2p[0]);
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        let child_ok = waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        if !parent_ok || !child_ok {
            println!(
                "delegated-root-fixed-cow failed round={round} parent_ok={parent_ok} child_ok={child_ok}"
            );
            return 1;
        }
        fixed_maps += 3;
    }
    println!(
        "delegated-root-fixed-cow pages={pages} rounds={rounds} fixed_maps={fixed_maps} ok=true"
    );
    0
}

// ---------------------------------------------------------------------------
// kick-first-read

fn marker(value: u64) {
    // sched_yield ignores its arguments; the embed interceptor keys on them.
    unsafe { libc::syscall(libc::SYS_sched_yield, value) };
}

pub fn kick_first_read(rounds: usize) -> i32 {
    if rounds == 0 {
        println!("kick-first-read invalid rounds 0");
        return 1;
    }
    unsafe { libc::alarm(60) };
    let ps = page_size();
    for round in 0..rounds {
        let mut go = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
            println!("kick-first-read pipe failed");
            return 1;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("kick-first-read fork failed");
            return 1;
        }
        if pid == 0 {
            unsafe {
                libc::close(go[1]);
                libc::alarm(30);
            }
            // poll() is not a read: it only waits until the byte is queued, so
            // the read below is the child's first pipe read and finds data.
            let mut pfd = libc::pollfd {
                fd: go[0],
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut pfd, 1, 5_000) };
            let mut byte = 0u8;
            marker(MARKER_BEFORE_READ);
            let n = unsafe { libc::read(go[0], (&mut byte as *mut u8).cast(), 1) };
            marker(MARKER_AFTER_READ);
            let ok = polled == 1 && n == 1 && byte == b'K';
            println!("kick-first-read child round={round} polled={polled} read={n} ok={ok}");
            let _ = std::io::stdout().flush();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        unsafe { libc::close(go[0]) };
        // The kick: a sibling thread maps, touches and unmaps, which pauses
        // stage-1 publication and kicks every vCPU, including the child's.
        let kicker = std::thread::spawn(move || {
            let Some(addr) = anon(0, 4 * ps, PROT_RW, false) else {
                return false;
            };
            for page in 0..4 {
                unsafe { ((addr + page * ps) as *mut u64).write_volatile(page as u64) };
            }
            unsafe { libc::munmap(addr as *mut libc::c_void, 4 * ps) == 0 }
        });
        let kicked = kicker.join().unwrap_or(false);
        let wrote = write_signal_byte(go[1], b'K');
        unsafe { libc::close(go[1]) };
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        let child_ok = waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        if !kicked || !wrote || !child_ok {
            println!(
                "kick-first-read failed round={round} kicked={kicked} wrote={wrote} child_ok={child_ok}"
            );
            return 1;
        }
    }
    println!("kick-first-read rounds={rounds} ok=true");
    0
}
