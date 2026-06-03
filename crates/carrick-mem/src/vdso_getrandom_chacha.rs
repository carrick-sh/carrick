//! ChaCha20 block function (RFC 8439), the cryptographic core of the userspace
//! vDSO getrandom fast path (P2). `no_std`-compatible and allocation-free so the
//! exact same source compiles into the position-independent vDSO blob (via
//! tools/build-vdso-getrandom.sh) AND into carrick-mem for host known-answer
//! testing — the ONLY way to catch a subtly-wrong keystream (a differential
//! can't: both sides return random-looking bytes regardless of correctness).
//!
//! Security-critical. Keep this minimal and auditable; do not "optimise" without
//! re-running the RFC 8439 vectors.
#![allow(dead_code)]

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One ChaCha20 block: 20 rounds over (constants ‖ key ‖ counter ‖ nonce),
/// returned as 16 little-endian-serialised state words (the 64-byte keystream).
pub fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    let init: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        nonce[0],
        nonce[1],
        nonce[2],
    ];
    let mut s = init;
    for _ in 0..10 {
        // column rounds
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        // diagonal rounds
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = s[i].wrapping_add(init[i]);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// vgetrandom state machine (the security-critical part). The per-thread opaque
// state (carrick's own 144-byte layout) holds a ChaCha key + the generation it
// was seeded under. `getrandom_fill` reseeds when the published generation
// changes — which carrick bumps on fork, so a forked child NEVER reuses its
// parent's keystream — and ratchets the key after every call so the stored
// state cannot reproduce bytes already handed out (forward secrecy). It never
// reuses a (key, block-counter) pair.
// ---------------------------------------------------------------------------

/// Offsets within the opaque state: a 32-byte `key` at 0, the gen-snapshot `u64`
/// at 32, the `init` flag (`u8`) at 40.
const ST_KEY: usize = 0;
const ST_GEN: usize = 32;
const ST_INIT: usize = 40;

fn block_to_bytes(block: &[u32; 16]) -> [u8; 64] {
    let mut ks = [0u8; 64];
    let mut i = 0;
    while i < 16 {
        ks[i * 4..i * 4 + 4].copy_from_slice(&block[i].to_le_bytes());
        i += 1;
    }
    ks
}

fn load_key(state: &[u8]) -> [u32; 8] {
    let mut key = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        key[i] = u32::from_le_bytes([
            state[ST_KEY + i * 4],
            state[ST_KEY + i * 4 + 1],
            state[ST_KEY + i * 4 + 2],
            state[ST_KEY + i * 4 + 3],
        ]);
        i += 1;
    }
    key
}

/// Fill `buf` with ChaCha20 keystream from the per-thread `state`, reseeding the
/// 32-byte key via `reseed` when the published generation `gen` differs from the
/// state's snapshot (or the state is uninitialised). Returns false iff `reseed`
/// failed — the caller must then fall back to the getrandom(2) syscall.
///
/// Invariants enforced (verified by the tests below):
/// - reseed exactly when `!initialised || snapshot != gen` (fork safety: carrick
///   bumps `gen` on fork → child's copied snapshot mismatches → child reseeds);
/// - within a call, block counters 0,1,2,… never repeat under one key;
/// - after a call the key is RATCHETED to a fresh block, so the persisted state
///   cannot reproduce the bytes just returned (forward secrecy) and successive
///   calls never collide.
pub fn getrandom_fill(
    state: &mut [u8; 144],
    buf: &mut [u8],
    generation: u64,
    mut reseed: impl FnMut(&mut [u8; 32]) -> bool,
) -> bool {
    let snapshot = u64::from_le_bytes([
        state[ST_GEN],
        state[ST_GEN + 1],
        state[ST_GEN + 2],
        state[ST_GEN + 3],
        state[ST_GEN + 4],
        state[ST_GEN + 5],
        state[ST_GEN + 6],
        state[ST_GEN + 7],
    ]);
    if state[ST_INIT] == 0 || snapshot != generation {
        let mut key = [0u8; 32];
        if !reseed(&mut key) {
            return false;
        }
        state[ST_KEY..ST_KEY + 32].copy_from_slice(&key);
        state[ST_GEN..ST_GEN + 8].copy_from_slice(&generation.to_le_bytes());
        state[ST_INIT] = 1;
        for b in key.iter_mut() {
            *b = 0;
        }
    }

    let mut key = load_key(state);
    let nonce = [0u32; 3];
    let mut counter: u32 = 0;
    // Panic-free fill: the blob is freestanding, so NO runtime slice range (which
    // would emit a slice_index_fail call into core). Emit byte-by-byte over
    // `buf.iter_mut()`; `pos & 63` keeps the keystream index provably < 64.
    let mut ks = [0u8; 64];
    let mut pos = 64usize;
    for slot in buf.iter_mut() {
        if pos >= 64 {
            ks = block_to_bytes(&chacha20_block(&key, counter, &nonce));
            counter += 1;
            pos = 0;
        }
        *slot = ks[pos & 63];
        pos += 1;
    }
    for b in ks.iter_mut() {
        *b = 0; // zeroize the last keystream block
    }

    // Ratchet: re-key from a block BEYOND those served (counters 0..counter were
    // consumed, so `counter` is fresh), then wipe the working key.
    let next = block_to_bytes(&chacha20_block(&key, counter, &nonce));
    state[ST_KEY..ST_KEY + 32].copy_from_slice(&next[..32]);
    for w in key.iter_mut() {
        *w = 0;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.3.2 ChaCha20 block-function test vector.
    #[test]
    fn rfc8439_block_function() {
        let key: [u32; 8] = [
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x1312_1110,
            0x1716_1514,
            0x1b1a_1918,
            0x1f1e_1d1c,
        ];
        let counter: u32 = 1;
        let nonce: [u32; 3] = [0x0900_0000, 0x4a00_0000, 0x0000_0000];
        let block = chacha20_block(&key, counter, &nonce);
        // Serialise to little-endian bytes and compare to the authoritative
        // RFC 8439 §2.3.2 keystream byte dump (transcribed in display order to
        // avoid u32-word transcription errors).
        let mut got = [0u8; 64];
        for (i, w) in block.iter().enumerate() {
            got[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let want: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(got, want, "ChaCha20 block keystream mismatch vs RFC 8439");
    }

    /// Distinct counters must give distinct blocks (sanity for the counter wiring).
    #[test]
    fn distinct_counters_distinct_blocks() {
        let key = [0u32; 8];
        let nonce = [0u32; 3];
        assert_ne!(
            chacha20_block(&key, 0, &nonce),
            chacha20_block(&key, 1, &nonce)
        );
    }

    use std::cell::Cell;

    /// Reseed happens EXACTLY on first use and on a generation change — the
    /// mechanism that makes a forked child (which carrick gives a bumped
    /// generation) reseed instead of reusing its parent's keystream.
    #[test]
    fn reseeds_only_on_generation_change() {
        let mut st = [0u8; 144];
        let calls = Cell::new(0u32);
        let mut reseed = |k: &mut [u8; 32]| {
            calls.set(calls.get() + 1);
            k.fill(calls.get() as u8);
            true
        };
        let mut buf = [0u8; 16];
        getrandom_fill(&mut st, &mut buf, 5, &mut reseed); // uninit -> reseed #1
        getrandom_fill(&mut st, &mut buf, 5, &mut reseed); // same gen -> no reseed
        getrandom_fill(&mut st, &mut buf, 5, &mut reseed); // same gen -> no reseed
        getrandom_fill(&mut st, &mut buf, 6, &mut reseed); // gen bumped -> reseed #2
        assert_eq!(calls.get(), 2);
    }

    /// Successive calls under the SAME generation never return the same bytes
    /// (the per-call key ratchet), and the persisted key is never one that
    /// reproduces bytes already handed out (forward secrecy).
    #[test]
    fn successive_calls_never_repeat() {
        let mut st = [0u8; 144];
        let mut reseed = |k: &mut [u8; 32]| {
            k.fill(0xab);
            true
        };
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        getrandom_fill(&mut st, &mut a, 1, &mut reseed);
        let key_after_a = st[..32].to_vec();
        getrandom_fill(&mut st, &mut b, 1, &mut reseed);
        assert_ne!(a, b, "ratchet must give distinct output across calls");
        assert_ne!(&st[..32], &key_after_a[..], "key must ratchet each call");
        // Forward secrecy: the key stored after call A must NOT reproduce A.
        let key = load_key(&{
            let mut s = [0u8; 144];
            s[..32].copy_from_slice(&key_after_a);
            s
        });
        let replay = block_to_bytes(&chacha20_block(&key, 0, &[0u32; 3]));
        assert_ne!(
            &replay[..40],
            &a[..],
            "stored key must not reproduce prior output"
        );
    }

    /// THE fork-safety property. A forked child is a byte-copy of the parent's
    /// state; carrick bumps the generation for the child. With the bump, the
    /// child reseeds and its output differs from the parent's. The control case
    /// (no bump) shows WHY the bump is essential: identical state + identical
    /// generation reproduces identical bytes (the reuse the bump prevents).
    #[test]
    fn forked_child_does_not_reuse_parent_keystream() {
        let mut parent = [0u8; 144];
        let mut reseed_p = |k: &mut [u8; 32]| {
            k.fill(0x11);
            true
        };
        let mut warm = [0u8; 16];
        getrandom_fill(&mut parent, &mut warm, 7, &mut reseed_p); // parent seeded @gen 7

        // fork: child is a byte-for-byte copy of the parent's opaque state.
        let mut child = parent;

        // child reseeds with DIFFERENT entropy because carrick bumped its gen.
        let mut child_out = [0u8; 32];
        let mut reseed_c = |k: &mut [u8; 32]| {
            k.fill(0x22);
            true
        };
        getrandom_fill(&mut child, &mut child_out, 8, &mut reseed_c); // gen 8 != 7 -> reseed

        let mut parent_out = [0u8; 32];
        getrandom_fill(&mut parent, &mut parent_out, 7, &mut reseed_p); // gen unchanged
        assert_ne!(
            child_out, parent_out,
            "forked child reused parent keystream!"
        );

        // Control: WITHOUT the generation bump, a copy reproduces parent output.
        let mut twin = parent; // copy parent's CURRENT state
        let mut twin_out = [0u8; 32];
        getrandom_fill(&mut twin, &mut twin_out, 7, &mut reseed_p); // same gen, same state
        let mut parent_next = [0u8; 32];
        getrandom_fill(&mut parent, &mut parent_next, 7, &mut reseed_p);
        assert_eq!(
            twin_out, parent_next,
            "control: identical state+gen must reproduce (proves the bump matters)"
        );
    }
}
