//! The host artifact behind Apple Rosetta 2 for Linux: the interpreter's fixed
//! path and the two cached reads of its bytes.
//!
//! This lives under `dispatch` because the only in-zone consumer is the Rosetta
//! startup handshake (`dispatch::rosetta_handshake_ioctl`, reached from
//! `dispatch::fs::ioctl`): the guest asks a licensing ioctl and the kernel must
//! answer with bytes Rosetta itself will `memcmp`. The carrier's x86 ELF-load
//! redirect and its `binfmt_misc` registration name the same const and the same
//! read, which is the allowed carrier-to-kernel direction.

/// Apple's FIXED macOS location for the Rosetta 2 Linux ELF interpreter — an
/// AArch64 binary that JIT-translates an x86_64 Linux guest in user space. This
/// is the literal path: the `binfmt_misc` registration carrick publishes names
/// it, and the cached reads below source their bytes from it. Probing a host
/// that may have put it elsewhere goes through the carrier's
/// `rosetta_interpreter_path`, which falls back to this const last.
pub const ROSETTA_INTERPRETER: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";

/// The installed Rosetta interpreter's bytes, read once and cached. `None` when
/// Rosetta isn't installed for Linux. Both the ELF-load redirect and the ioctl
/// handshake source data from this single read.
pub fn rosetta_binary_bytes() -> Option<&'static [u8]> {
    static CACHE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| std::fs::read(ROSETTA_INTERPRETER).ok())
        .as_deref()
}

/// The verification blob Apple's Rosetta `memcmp`s the licensing-ioctl result
/// against. Rosetta keeps its own copy embedded at a fixed offset and compares
/// the kernel's answer against it, so we echo back *exactly that* — sourced
/// live from the installed binary rather than embedded in carrick's source.
/// This keeps Apple's string out of our tree and stays correct if Apple
/// revises it. Returns the bytes through (and including) the NUL terminator.
pub fn rosetta_license_blob() -> Option<&'static [u8]> {
    static CACHE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let bytes = rosetta_binary_bytes()?;
            // Anchor on a short distinctive prefix; the full response is taken
            // from the binary, not encoded here.
            const ANCHOR: &[u8] = b"Our hard work";
            let start = bytes.windows(ANCHOR.len()).position(|w| w == ANCHOR)?;
            let nul = bytes[start..].iter().position(|&b| b == 0)?;
            Some(bytes[start..=start + nul].to_vec())
        })
        .as_deref()
}
