//! Faithful replica of Go's `x/telemetry/internal/counter` mappedFile layout —
//! the precise sequence that crashes `go build` under carrick `--fs host`
//! (SIGSEGV at file.go:340 inside `mappedFile.lookup`).
//!
//! The earlier `mmapfile` / `mmapfileshare_mt` probes only ever read offset 0
//! (the header page) and passed. The telemetry counter additionally:
//!   * writes a SHORT header via the fd (`WriteAt(hdr,0)`), leaving the rest of
//!     page 0 (the hash table region, offsets ~36..2084) UNWRITTEN — relied on
//!     to read back as zero through the MAP_SHARED mapping,
//!   * sparse-extends to 16 KiB via a 4-byte `WriteAt` at offset 16380 (holes in
//!     between),
//!   * reads the hash table through the mapping (`load32` at hdrLen+hashOff+h*4),
//!   * writes counter RECORDS through the mapping (`writeEntryAt`: atomic stores
//!     into `mapping.Data[off..]`) and reads them back (`entryAt`).
//!
//! This probe performs exactly those steps and prints deterministic booleans.
//! It pre-spawns worker threads (like the Go runtime) so a sibling vCPU performs
//! the lookup, matching Go's goroutine scheduling. The first divergent `false`
//! pinpoints which mapped access carrick serves incoherently.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

const FILE_LEN: usize = 16 * 1024; // minFileLen
const HDR_LEN: u32 = 32; // round(len(hdrPrefix)=28,4)=28, +4, rounded to 32
const HASH_OFF: u32 = 4;
const NUM_HASH: u32 = 512;
const RECORD_UNIT: u32 = 32;
// hdrPrefix Go writes; HasPrefix is checked against it through the mapping.
const HDR_PREFIX: &[u8] = b"# telemetry/counter file v1\n";

// FNV-1a, exactly as telemetry's hash(), folded into numHash buckets.
fn hash(name: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &c in name {
        h = (h ^ c as u32).wrapping_mul(16777619);
    }
    (h ^ (h >> 16)) % NUM_HASH
}

fn place_first() -> u32 {
    // place(limit=0): first record offset = hdrLen + hashOff + 4*numHash, rounded
    // up to recordUnit.
    let limit = HDR_LEN + HASH_OFF + 4 * NUM_HASH;
    limit.div_ceil(RECORD_UNIT) * RECORD_UNIT
}

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
    }
    let fd = unsafe {
        libc::open(
            c"/tmp/telemetrymap_probe".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o666,
        )
    };
    if fd < 0 {
        println!("open FAIL");
        return;
    }

    // --- openMapped: short header via fd, sparse-extend to 16 KiB via fd ---
    let mut hdr = [0u8; HDR_LEN as usize];
    hdr[..HDR_PREFIX.len()].copy_from_slice(HDR_PREFIX);
    // telemetry stores the header length as a u32 at offset np=28.
    hdr[28..32].copy_from_slice(&(HDR_LEN).to_le_bytes());
    if unsafe { libc::pwrite(fd, hdr.as_ptr() as *const _, HDR_LEN as usize, 0) }
        != HDR_LEN as isize
    {
        println!("write_hdr FAIL");
        return;
    }
    let zero4 = [0u8; 4];
    if unsafe {
        libc::pwrite(
            fd,
            zero4.as_ptr() as *const _,
            4,
            (FILE_LEN - 4) as libc::off_t,
        )
    } != 4
    {
        println!("extend FAIL");
        return;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_size as usize != FILE_LEN {
        println!("fstat FAIL size={}", st.st_size);
        return;
    }
    println!("openmapped_fdwrite ok");

    // --- pre-spawn worker vCPUs BEFORE the mapping exists (like Go runtime) ---
    let release = Arc::new(AtomicU64::new(0));
    let ready = Arc::new(AtomicUsize::new(0));
    let map_addr = Arc::new(AtomicU64::new(0));
    // Results a sibling reports after doing the lookup on ITS vCPU:
    let sib_hdr_ok = Arc::new(AtomicU64::new(2)); // 2 = unset
    let sib_hash_zero = Arc::new(AtomicU64::new(2));
    let sib_record_val = Arc::new(AtomicU64::new(0));
    let sib_record_name_ok = Arc::new(AtomicU64::new(2));

    const K: usize = 4;
    let rec_off = place_first();
    let name: &[u8] = b"go/build";
    let head_off = HDR_LEN + HASH_OFF + hash(name) * 4;

    let mut handles = Vec::new();
    for w in 0..K {
        let release = Arc::clone(&release);
        let ready = Arc::clone(&ready);
        let map_addr = Arc::clone(&map_addr);
        let sib_hdr_ok = Arc::clone(&sib_hdr_ok);
        let sib_hash_zero = Arc::clone(&sib_hash_zero);
        let sib_record_val = Arc::clone(&sib_record_val);
        let sib_record_name_ok = Arc::clone(&sib_record_name_ok);
        handles.push(std::thread::spawn(move || {
            ready.fetch_add(1, Ordering::SeqCst);
            let mut spins: u64 = 0;
            while release.load(Ordering::SeqCst) == 0 {
                spins += 1;
                if spins > 2_000_000_000 {
                    return;
                }
                std::hint::spin_loop();
            }
            // Only worker 0 performs the read-side lookup; the rest just exist so
            // the scheduler has live sibling vCPUs (matching the Go runtime).
            if w != 0 {
                return;
            }
            let base = map_addr.load(Ordering::SeqCst);
            if base == 0 {
                return;
            }
            // HasPrefix(header) through the mapping, on a sibling vCPU.
            let mut hok = 1u64;
            for (i, &b) in HDR_PREFIX.iter().enumerate() {
                let got = unsafe { std::ptr::read_volatile((base as *const u8).add(i)) };
                if got != b {
                    hok = 0;
                    break;
                }
            }
            sib_hdr_ok.store(hok, Ordering::SeqCst);
            // load32 of the hash-table head slot (must read back the record off
            // the main vCPU wrote, OR zero if not yet linked).
            let hslot =
                unsafe { &*((base as *const u8).add(head_off as usize) as *const AtomicU32) };
            let head = hslot.load(Ordering::SeqCst);
            sib_hash_zero.store(if head == rec_off { 1 } else { 0 }, Ordering::SeqCst);
            // entryAt(rec_off): read the counter value (off+0) and name (off+16).
            let vptr = unsafe { &*((base as *const u8).add(rec_off as usize) as *const AtomicU64) };
            sib_record_val.store(vptr.load(Ordering::SeqCst), Ordering::SeqCst);
            let mut nok = 1u64;
            for (i, &b) in name.iter().enumerate() {
                let got = unsafe {
                    std::ptr::read_volatile((base as *const u8).add(rec_off as usize + 16 + i))
                };
                if got != b {
                    nok = 0;
                    break;
                }
            }
            sib_record_name_ok.store(nok, Ordering::SeqCst);
        }));
    }

    let mut spins: u64 = 0;
    while ready.load(Ordering::SeqCst) < K {
        spins += 1;
        if spins > 2_000_000_000 {
            println!("workers_park FAIL");
            return;
        }
        std::hint::spin_loop();
    }

    // --- memmap + HasPrefix on the main vCPU ---
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            FILE_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        println!("mmap FAIL");
        return;
    }
    let base = addr as *const u8;
    let mut main_hdr_ok = true;
    for (i, &b) in HDR_PREFIX.iter().enumerate() {
        if unsafe { std::ptr::read_volatile(base.add(i)) } != b {
            main_hdr_ok = false;
            break;
        }
    }
    println!("main_hasprefix {main_hdr_ok}");

    // --- lookup of an empty hash slot must read 0 through the mapping ---
    let head_before =
        unsafe { (*((base.add(head_off as usize)) as *const AtomicU32)).load(Ordering::SeqCst) };
    println!("hash_slot_empty {}", head_before == 0);

    // --- newCounter / writeEntryAt: write a record THROUGH the mapping ---
    // copy(Data[off+16:], name)
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (addr as *mut u8).add(rec_off as usize + 16),
            name.len(),
        );
    }
    // atomic store nameLen|0xff000000 at off+8
    unsafe {
        (*((base.add(rec_off as usize + 8)) as *const AtomicU32))
            .store(name.len() as u32 | 0xff00_0000, Ordering::SeqCst);
    }
    // counter value at off+0, bumped via atomic add (Counter.add does LDADD)
    let vptr = unsafe { &*((base.add(rec_off as usize)) as *const AtomicU64) };
    vptr.store(0, Ordering::SeqCst);
    let prev = vptr.fetch_add(1, Ordering::SeqCst);
    // link the record into the hash table head slot (atomic store of its offset)
    unsafe {
        (*((base.add(head_off as usize)) as *const AtomicU32)).store(rec_off, Ordering::SeqCst);
    }
    // read the record back on the MAIN vCPU (control)
    let main_val = vptr.load(Ordering::SeqCst);
    println!("main_record_add prev={prev} val={main_val}");

    // --- release siblings; a sibling re-does lookup on its own vCPU ---
    map_addr.store(addr as u64, Ordering::SeqCst);
    release.store(1, Ordering::SeqCst);
    for h in handles {
        let _ = h.join();
    }
    println!("sib_hasprefix {}", sib_hdr_ok.load(Ordering::SeqCst));
    println!("sib_hash_links {}", sib_hash_zero.load(Ordering::SeqCst));
    println!("sib_record_val {}", sib_record_val.load(Ordering::SeqCst));
    println!(
        "sib_record_name {}",
        sib_record_name_ok.load(Ordering::SeqCst)
    );

    // --- file coherence: pread the record value back off the fd ---
    let mut fbuf = [0u8; 8];
    let r = unsafe { libc::pread(fd, fbuf.as_mut_ptr() as *mut _, 8, rec_off as libc::off_t) };
    let file_val = u64::from_le_bytes(fbuf);
    println!("file_record_val rc={r} val={file_val}");
    println!("DONE");
}
