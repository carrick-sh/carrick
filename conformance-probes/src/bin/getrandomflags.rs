//! getrandom(2) flag validation. Only GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE
//! are valid; any other bit → EINVAL (LTP getrandom05). carrick previously
//! ignored flags entirely and always succeeded. Deterministic booleans.

use conformance_probes::{errno, report};

const GRND_NONBLOCK: u32 = 0x0001;
const GRND_RANDOM: u32 = 0x0002;
const GRND_INSECURE: u32 = 0x0004;

unsafe fn getrandom(buf: *mut u8, len: usize, flags: u32) -> i64 {
    libc::syscall(libc::SYS_getrandom, buf, len, flags as i64)
}

fn main() {
    unsafe {
        let mut buf = [0u8; 16];
        // Valid flag combinations succeed and return the byte count.
        let ok_none = getrandom(buf.as_mut_ptr(), 16, 0);
        let ok_nb = getrandom(buf.as_mut_ptr(), 16, GRND_NONBLOCK);
        // GRND_RANDOM alone is valid. (GRND_RANDOM|GRND_INSECURE together is
        // NOT — they're mutually-exclusive sources — so that combo isn't
        // asserted here; the bare unknown-bit rejection below is the invariant
        // LTP getrandom05 checks.)
        let ok_rand = getrandom(buf.as_mut_ptr(), 16, GRND_RANDOM);
        report!(
            valid_no_flags_ok = ok_none == 16,
            valid_nonblock_ok = ok_nb == 16,
            valid_random_ok = ok_rand == 16,
        );
        let _ = GRND_INSECURE;

        // An unsupported flag bit → -1/EINVAL.
        let bad = getrandom(buf.as_mut_ptr(), 16, 0x8000);
        let bad_e = if bad < 0 { errno() } else { 0 };
        let neg1 = getrandom(buf.as_mut_ptr(), 16, u32::MAX); // all bits, incl. invalid
        let neg1_e = if neg1 < 0 { errno() } else { 0 };
        report!(
            invalid_flag_einval = bad == -1 && bad_e == libc::EINVAL,
            all_bits_einval = neg1 == -1 && neg1_e == libc::EINVAL,
        );
    }
}
