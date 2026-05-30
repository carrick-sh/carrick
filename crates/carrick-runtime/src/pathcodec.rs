//! Reversible byte<->String path codec for undecodable (non-UTF-8) guest paths.
//!
//! Linux treats pathnames as opaque NUL-terminated byte strings: any byte
//! except `/` (0x2F) and NUL (0x00) is legal in a filename. CPython (and any
//! program that fopens a "mojibake" filename) round-trips undecodable bytes
//! through `str` with PEP 383 *surrogateescape*: each undecodable byte `0xNN`
//! becomes the lone surrogate `U+DC00+NN`, and is decoded back to `0xNN` on the
//! way out to the kernel. So `open(b"/tmp/\xff")` MUST create exactly that byte
//! on disk, and `os.listdir(b"/tmp")` MUST hand back `b"\xff"` verbatim.
//!
//! Carrick's VFS / fs-backend layer is `&str`-based (paths are Rust `String`s).
//! A Rust `String` is well-formed UTF-8 and so *cannot* hold lone surrogates,
//! which is why the old `read_guest_c_string` rejected undecodable paths with
//! EINVAL — `open()` of such a path errored where Linux succeeds.
//!
//! Rather than refactor every `&str` path boundary to bytes/`OsStr` (a very
//! large change), we keep the layer String-based and carry undecodable bytes
//! through it with a *reversible* escape that IS expressible in a `String`:
//! each undecodable byte `0xNN` (0x80..=0xFF) is mapped to the Private-Use-Area
//! scalar `U+EE00 + NN`. Valid UTF-8 in the path is left byte-for-byte
//! unchanged, exactly like surrogateescape only escapes the *undecodable*
//! bytes.
//!
//! Crucially, macOS APFS (carrick's `--fs host` backend) REJECTS a raw
//! non-UTF-8 filename with `EILSEQ` (errno 92) — a guest's opaque `b"\xff"`
//! cannot be stored on disk byte-for-byte. The PUA escape is valid UTF-8 (so
//! APFS accepts it) AND reversible, so it doubles as carrick's *durable host
//! representation* of an undecodable name: the encoded form is what lives on
//! disk and what the `&str` VFS layer carries. The escape is decoded back to
//! the raw guest bytes only at the GUEST-facing read-back boundaries — getdents
//! (`dirent64_record`), readlink (`readlinkat`), and getcwd — so the guest sees
//! `b"\xff"` and a re-open / listdir / readlink by those bytes round-trips.
//!
//! The PUA window `U+EE00..=U+EEFF` is in the BMP Private Use Area
//! (`U+E000..=U+F8FF`); we re-escape any *genuine* occurrence of that window in
//! a guest path so the mapping is total and reversible (see `encode_bytes`).

/// Base of the 256-wide Private-Use-Area window used to escape raw bytes.
const PUA_BASE: u32 = 0xEE00;
const PUA_END: u32 = PUA_BASE + 0xFF; // 0xEEFF, inclusive

/// True if `c` is one of the scalars we use as a byte-escape.
#[inline]
fn is_escape_scalar(c: char) -> bool {
    let u = c as u32;
    (PUA_BASE..=PUA_END).contains(&u)
}

/// Encode opaque path bytes into a reversible `String`.
///
/// - A maximal run of valid UTF-8 is copied through unchanged, *except* any
///   scalar that already falls in our escape window `U+EE00..=U+EEFF`, which is
///   itself escaped (its UTF-8 bytes are escaped one-by-one) so decoding is
///   unambiguous and total.
/// - Any byte that is not part of a valid UTF-8 sequence is escaped as the
///   single scalar `U+EE00 + byte`.
///
/// Round-trips: `decode_to_bytes(&encode_bytes(b)) == b` for every `&[u8]`.
pub fn encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        // Try to decode the next char as valid UTF-8.
        match std::str::from_utf8(&bytes[i..]) {
            Ok(s) => {
                // Whole remainder is valid UTF-8: copy chars, escaping any that
                // land in our reserved window.
                for c in s.chars() {
                    push_char_escaping_window(&mut out, c);
                }
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    // SAFETY: validated by from_utf8 above.
                    let s = unsafe { std::str::from_utf8_unchecked(&bytes[i..i + valid]) };
                    for c in s.chars() {
                        push_char_escaping_window(&mut out, c);
                    }
                    i += valid;
                }
                // The byte at `i` is undecodable: escape it.
                out.push(escape_byte(bytes[i]));
                i += 1;
            }
        }
    }
    out
}

#[inline]
fn push_char_escaping_window(out: &mut String, c: char) {
    if is_escape_scalar(c) {
        // A genuine U+EE00..U+EEFF in the guest path: escape each of its UTF-8
        // bytes so it cannot be confused with an escaped raw byte on decode.
        let mut buf = [0u8; 4];
        for &b in c.encode_utf8(&mut buf).as_bytes() {
            out.push(escape_byte(b));
        }
    } else {
        out.push(c);
    }
}

#[inline]
fn escape_byte(b: u8) -> char {
    // PUA_BASE + b is always a valid scalar (well within the BMP PUA).
    char::from_u32(PUA_BASE + b as u32).expect("PUA escape scalar is valid")
}

/// Decode an encoded path `String` back to the original opaque bytes.
///
/// Inverse of [`encode_bytes`]: each escape scalar `U+EE00 + NN` becomes the
/// raw byte `0xNN`; every other scalar is emitted as its normal UTF-8 bytes.
pub fn decode_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut buf = [0u8; 4];
    for c in s.chars() {
        let u = c as u32;
        if (PUA_BASE..=PUA_END).contains(&u) {
            out.push((u - PUA_BASE) as u8);
        } else {
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

/// True if the encoded path contains at least one escaped (undecodable) byte —
/// i.e. it would NOT survive a naive `String`-as-UTF-8 round-trip. Lets callers
/// keep the common all-ASCII/valid-UTF-8 fast path allocation-free.
pub fn has_escaped_bytes(s: &str) -> bool {
    s.chars().any(is_escape_scalar)
}

/// Decode an encoded path to an owned `OsString` carrying the raw bytes — the
/// form cap-std / libc want at the host-syscall boundary on a unix host.
#[cfg(unix)]
pub fn decode_to_osstring(s: &str) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(decode_to_bytes(s))
}

/// Encode raw host name bytes (e.g. a `readdir`/`readlink` result) into the
/// reversible `String` form the VFS layer carries.
#[cfg(unix)]
pub fn encode_osstr(s: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    encode_bytes(s.as_bytes())
}

/// Encode a raw host `Path` (e.g. a symlink target from `read_link_contents`)
/// into the reversible `String` form the VFS layer carries.
#[cfg(unix)]
pub fn encode_path(p: &std::path::Path) -> String {
    encode_osstr(p.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrips(b: &[u8]) {
        let enc = encode_bytes(b);
        assert_eq!(
            decode_to_bytes(&enc),
            b,
            "roundtrip failed for {b:?} (enc={enc:?})"
        );
    }

    #[test]
    fn ascii_is_identity() {
        let s = encode_bytes(b"/tmp/hello.txt");
        assert_eq!(s, "/tmp/hello.txt");
        assert!(!has_escaped_bytes(&s));
        roundtrips(b"/tmp/hello.txt");
    }

    #[test]
    fn valid_utf8_unicode_preserved() {
        let s = "/tmp/café/日本語".as_bytes();
        let enc = encode_bytes(s);
        assert_eq!(enc, "/tmp/café/日本語");
        assert!(!has_escaped_bytes(&enc));
        roundtrips(s);
    }

    #[test]
    fn undecodable_bytes_roundtrip() {
        roundtrips(b"/tmp/cr_\xff\xfe_x");
        roundtrips(&[0xff]);
        roundtrips(&[0x80, 0x81, 0xfe, 0xff]);
        // A lone continuation byte after valid ASCII.
        roundtrips(b"abc\x80def");
        // Truncated multi-byte sequence at the end.
        roundtrips(b"x\xe2\x82"); // first two bytes of U+20AC, truncated
    }

    #[test]
    fn has_escaped_flags_only_when_escaped() {
        assert!(!has_escaped_bytes(&encode_bytes(b"plain")));
        assert!(has_escaped_bytes(&encode_bytes(b"\xff")));
    }

    #[test]
    fn genuine_pua_window_char_is_reescaped_and_roundtrips() {
        // A guest path that legitimately contains U+EE10 (in our escape window):
        // its UTF-8 bytes must survive the round-trip without aliasing a raw
        // byte escape.
        let original = "/tmp/\u{EE10}name".as_bytes();
        let enc = encode_bytes(original);
        // The decoded bytes must equal the original UTF-8 bytes exactly.
        assert_eq!(decode_to_bytes(&enc), original);
    }

    #[cfg(unix)]
    #[test]
    fn osstring_roundtrip() {
        let enc = encode_bytes(b"/tmp/\xff\xfe");
        let os = decode_to_osstring(&enc);
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(os.as_os_str().as_bytes(), b"/tmp/\xff\xfe");
        assert_eq!(encode_osstr(os.as_os_str()), enc);
    }
}
