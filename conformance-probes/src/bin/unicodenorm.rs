//! Unicode-normalization filename IDENTITY probe (the byte-exact-name invariant).
//!
//! On Linux a filename is an opaque byte string: two byte sequences that are
//! Unicode-equivalent under NFC/NFD (or NFKC/NFKD) are nonetheless DIFFERENT
//! files. macOS APFS/HFS+ normalize at the VFS boundary, so a `stat`/`open` of
//! the NFD byte sequence resolves the NFC-named inode (and vice-versa) — which
//! would make a guest see the wrong file and break CPython's
//! test_unicode_file_functions::test_normalize (it expects FileNotFoundError
//! when stat/open the differently-normalized name). carrick's `--fs host`
//! backend re-checks the guest-supplied leaf against the parent directory's
//! readdir bytes (`name_matches_on_disk`) so the host's normalizing lookup
//! cannot alias one name onto the other.
//!
//! We use "å": NFC is the 2-byte UTF-8 `C3 A5` (U+00E5), NFD is the 3-byte
//! `61 CC 8A` ('a' + combining ring U+030A). They are canonically equivalent
//! but distinct byte strings.
//!
//! On real Linux every boolean below is `true`. Deterministic: fixed names
//! under /tmp, no inodes/pids/timestamps; cleanup first so it is re-runnable.

use std::ffi::CString;

// Directory holding the two differently-normalized siblings.
const DIR: &str = "/tmp/unicodenorm_probe";
// NFC: '<dir>/' + 'z_' + 0xC3 0xA5
const NFC_LEAF: &[u8] = &[b'z', b'_', 0xC3, 0xA5];
// NFD: '<dir>/' + 'z_' + 0x61 0xCC 0x8A
const NFD_LEAF: &[u8] = &[b'z', b'_', 0x61, 0xCC, 0x8A];

fn join(dir: &str, leaf: &[u8]) -> CString {
    let mut v = dir.as_bytes().to_vec();
    v.push(b'/');
    v.extend_from_slice(leaf);
    CString::new(v).unwrap()
}

fn main() {
    unsafe {
        libc::umask(0);
        let dc = CString::new(DIR).unwrap();
        // Clean any leftover from a prior run.
        let nfc = join(DIR, NFC_LEAF);
        let nfd = join(DIR, NFD_LEAF);
        libc::unlink(nfc.as_ptr());
        libc::unlink(nfd.as_ptr());
        libc::rmdir(dc.as_ptr());

        let made = libc::mkdir(dc.as_ptr(), 0o777) == 0;
        println!("setup_dir={}", made);

        // Create ONLY the NFC-named file.
        let fd = libc::open(
            nfc.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let created = fd >= 0;
        if created {
            libc::close(fd);
        }
        println!("setup_nfc_file={}", created);

        // stat(NFC) MUST succeed — the file exists under its real name.
        let mut st: libc::stat = std::mem::zeroed();
        let nfc_stat = libc::stat(nfc.as_ptr(), &mut st);
        println!("nfc_stat_ok={}", nfc_stat == 0);

        // stat(NFD) MUST fail with ENOENT — on Linux the NFD byte string is a
        // DIFFERENT, non-existent file. (On a normalizing host without the
        // guard it would alias the NFC inode and wrongly succeed.)
        let mut st2: libc::stat = std::mem::zeroed();
        let nfd_stat = libc::stat(nfd.as_ptr(), &mut st2);
        println!(
            "nfd_stat_enoent={}",
            nfd_stat == -1 && errno() == libc::ENOENT
        );

        // open(NFD) without O_CREAT MUST also fail with ENOENT.
        let ofd = libc::open(nfd.as_ptr(), libc::O_RDONLY);
        println!("nfd_open_enoent={}", ofd == -1 && errno() == libc::ENOENT);
        if ofd >= 0 {
            libc::close(ofd);
        }

        // lstat(NFD) MUST fail with ENOENT too (no-follow path).
        let mut st3: libc::stat = std::mem::zeroed();
        let nfd_lstat = libc::lstat(nfd.as_ptr(), &mut st3);
        println!(
            "nfd_lstat_enoent={}",
            nfd_lstat == -1 && errno() == libc::ENOENT
        );

        // readdir of the directory returns EXACTLY the NFC byte sequence we
        // wrote — the host did not decompose the stored name behind our back.
        let dirp = libc::opendir(dc.as_ptr());
        let mut saw_nfc = false;
        let mut saw_nfd = false;
        if !dirp.is_null() {
            loop {
                let ent = libc::readdir(dirp);
                if ent.is_null() {
                    break;
                }
                // Read the d_name C string bytes.
                let name_ptr = (*ent).d_name.as_ptr();
                let cs = std::ffi::CStr::from_ptr(name_ptr);
                let bytes = cs.to_bytes();
                if bytes == NFC_LEAF {
                    saw_nfc = true;
                }
                if bytes == NFD_LEAF {
                    saw_nfd = true;
                }
            }
            libc::closedir(dirp);
        }
        println!("readdir_has_nfc={}", saw_nfc);
        println!("readdir_has_nfd={}", saw_nfd);

        // Cleanup (best-effort).
        libc::unlink(nfc.as_ptr());
        libc::unlink(nfd.as_ptr());
        libc::rmdir(dc.as_ptr());
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
