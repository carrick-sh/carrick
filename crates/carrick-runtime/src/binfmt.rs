//! Faithful `binfmt_misc`-style registry for foreign-architecture binaries.
//!
//! The Linux kernel's `binfmt_misc` matches a binary's leading bytes against a
//! registered `magic`/`mask` (at an `offset`) and, on a hit, re-executes it
//! through a registered `interpreter`, with `P`/`O`/`C`/`F` flags controlling the
//! invocation (see `docs/rosetta-binfmt.md` and the kernel admin-guide). carrick
//! mirrors that mechanism here: the redirect is driven by a general registry
//! rather than a hardcoded "is this x86_64?" check. The sole registration today
//! is Apple's Rosetta for x86_64 Linux ELFs (the same `POCF` magic/mask Docker
//! Desktop registers), but adding another foreign arch is just another table
//! entry.
//!
//! carrick invokes the interpreter *directly* (it is the guest's kernel), so it
//! follows the interpreter's own launch contract rather than re-implementing the
//! kernel's exec rewrite; the flags are retained because they document the
//! canonical registration and gate faithful behaviors (e.g. `preserve_argv0`).

use crate::runtime::ROSETTA_INTERPRETER;

/// `binfmt_misc` invocation flags (the subset carrick models).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinfmtFlags {
    /// `P`: preserve the program's original `argv[0]` (don't clobber it with the
    /// binary path). carrick honors this so multi-call binaries (busybox,
    /// coreutils) that dispatch on `argv[0]` work.
    pub preserve_argv0: bool,
    /// `O`: the kernel opens the target and passes an fd (vs the path).
    pub open_binary: bool,
    /// `C`: compute credentials from the target, not the interpreter (implies O).
    pub credentials: bool,
    /// `F`: open the interpreter at registration time (fix-binary).
    pub fix_binary: bool,
}

/// A `binfmt_misc` registration: a binary whose `file[offset..]` matches `magic`
/// under `mask` is run through `interpreter`.
pub struct BinfmtRegistration {
    /// Human-readable registration name (the `binfmt_misc` `:name:` field).
    pub name: &'static str,
    /// Byte offset in the file where `magic` is expected.
    pub offset: usize,
    /// Expected bytes (compared under `mask`).
    pub magic: &'static [u8],
    /// Per-byte mask applied before comparison (`magic.len() == mask.len()`).
    pub mask: &'static [u8],
    /// Host path to the interpreter that translates/runs the target.
    pub interpreter: &'static str,
    /// Canonical registration flags.
    pub flags: BinfmtFlags,
}

impl BinfmtRegistration {
    /// True if `file` matches this registration, the way the kernel compares:
    /// `(file[offset+i] & mask[i]) == (magic[i] & mask[i])` for every byte.
    pub fn matches(&self, file: &[u8]) -> bool {
        debug_assert_eq!(self.magic.len(), self.mask.len());
        let end = match self.offset.checked_add(self.magic.len()) {
            Some(end) => end,
            None => return false,
        };
        if file.len() < end {
            return false;
        }
        self.magic
            .iter()
            .zip(self.mask)
            .enumerate()
            .all(|(i, (&m, &k))| (file[self.offset + i] & k) == (m & k))
    }
}

/// x86_64 ELF magic Docker Desktop registers Rosetta with. Matches a little-
/// endian ELF64 whose `e_machine` is `EM_X86_64` (0x3e) and whose `e_type` is
/// `ET_EXEC` (2) or `ET_DYN` (3) — the latter via the masked low bit of byte 16.
const X86_64_ELF_MAGIC: &[u8] = &[
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00,
];
/// Mask paired with [`X86_64_ELF_MAGIC`]: `e_type` low bit (byte 16) is masked so
/// both `ET_EXEC` and `ET_DYN` match; `e_machine` (bytes 18-19) is pinned exact.
const X86_64_ELF_MASK: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfe, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff,
];

/// The registered binfmt handlers, consulted in order. Today: x86_64 → Rosetta.
static REGISTRATIONS: &[BinfmtRegistration] = &[BinfmtRegistration {
    name: "rosetta",
    offset: 0,
    magic: X86_64_ELF_MAGIC,
    mask: X86_64_ELF_MASK,
    interpreter: ROSETTA_INTERPRETER,
    // Docker Desktop registers Rosetta as POCF.
    flags: BinfmtFlags {
        preserve_argv0: true,
        open_binary: true,
        credentials: true,
        fix_binary: true,
    },
}];

/// Return the first registered handler whose magic matches `file`, or `None` if
/// the binary is native (no redirect needed).
pub fn match_registration(file: &[u8]) -> Option<&'static BinfmtRegistration> {
    REGISTRATIONS.iter().find(|reg| reg.matches(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header(class: u8, data: u8, e_type: u16, e_machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(b"\x7fELF");
        h[4] = class; // EI_CLASS (2 = ELF64)
        h[5] = data; // EI_DATA (1 = LSB)
        h[6] = 1; // EI_VERSION
        h[16..18].copy_from_slice(&e_type.to_le_bytes());
        h[18..20].copy_from_slice(&e_machine.to_le_bytes());
        h
    }

    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const EM_X86_64: u16 = 0x3e;
    const EM_AARCH64: u16 = 0xb7;

    #[test]
    fn x86_64_exec_and_dyn_elf_match_rosetta() {
        // Both a classic ET_EXEC and a PIE ET_DYN x86_64 ELF must match (the
        // masked e_type low bit covers both) — alpine busybox is ET_DYN.
        for e_type in [ET_EXEC, ET_DYN] {
            let elf = elf_header(2, 1, e_type, EM_X86_64);
            let reg = match_registration(&elf).expect("x86_64 ELF must match a binfmt handler");
            assert_eq!(reg.name, "rosetta");
            assert!(reg.flags.preserve_argv0, "Rosetta registration is POCF");
        }
    }

    #[test]
    fn aarch64_elf_does_not_match() {
        // A native aarch64 ELF must NOT be redirected.
        let elf = elf_header(2, 1, ET_DYN, EM_AARCH64);
        assert!(match_registration(&elf).is_none());
    }

    #[test]
    fn non_elf_and_truncated_do_not_match() {
        assert!(match_registration(b"#!/bin/sh\n").is_none());
        assert!(
            match_registration(b"\x7fEL").is_none(),
            "too short to match"
        );
        assert!(match_registration(&[]).is_none());
    }
}
