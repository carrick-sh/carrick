//! Live KVM x86_64 integration tests: M0/M1 (ring-3 SYSCALL doorbell) + M2
//! (static musl ELF hello-world).
//!
//! These tests require `/dev/kvm` and are skipped silently when absent (e.g.
//! on the macOS dev machine or a lima aarch64 VM).  They are LIVE: they
//! actually create a KVM VM, run a vCPU, and observe the guest's stdout.
//!
//! Run on an x86_64 Linux host with /dev/kvm (e.g. Ubuntu 24.04):
//! ```
//! cargo test -p carrick-vmm-kvm --test live_vcpu_x86 -- --nocapture
//! ```

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
// Integration tests legitimately use expect() to fail fast on unexpected
// test-infrastructure errors (e.g. missing binary path components).
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn kvm_available() -> bool {
    Path::new("/dev/kvm").exists()
}

/// Locate the `carrick-vmm-kvm` binary relative to the test executable.
///
/// `cargo test` places the test binary at `target/{profile}/deps/<name>-<hash>`;
/// the carrick-vmm-kvm binary is at `target/{profile}/carrick-vmm-kvm` (one directory
/// up, sibling of `deps/`).  This avoids relying on a CWD that is not
/// guaranteed to be the workspace root.
fn carrick_linux_bin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // target/{profile}/deps/live_vcpu_x86-<hash>
    //   -> target/{profile}/carrick-vmm-kvm
    let profile_dir = exe
        .parent() // deps/
        .and_then(|p| p.parent()) // {profile}/
        .expect("unexpected test binary path structure");
    profile_dir.join("carrick-vmm-kvm")
}

/// Locate the workspace root relative to the test executable.
///
/// `target/{profile}/deps/` -> `target/{profile}/` -> `target/` -> workspace root.
fn workspace_root() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    exe.parent() // deps/
        .and_then(|p| p.parent()) // {profile}/
        .and_then(|p| p.parent()) // target/
        .and_then(|p| p.parent()) // workspace root
        .expect("unexpected test binary path structure")
        .to_path_buf()
}

// ─── Minimal x86_64 ELF builder ──────────────────────────────────────────────
//
// Builds a hand-crafted ET_EXEC ELF64 file with a single PT_LOAD segment
// containing `blob` bytes, placed at `load_va`.  The ELF entry point is set to
// `load_va` so `AddressSpace::load_elf_for` places the code at the right VA.
//
// ELF64 format (OSDev "ELF" / System V ABI §4):
//   Ehdr (64 bytes) + Phdr (56 bytes) = 120 bytes header, then blob data.
// The file offset of the blob = 0x78 = 120 bytes (after Ehdr + 1 Phdr).

fn make_x86_elf(blob: &[u8], load_va: u64) -> Vec<u8> {
    let file_offset: u64 = 0x78; // 64 (Ehdr) + 56 (Phdr) = 120 = 0x78
    let filesz = blob.len() as u64;
    // memsz: round up to next page so the stack can follow without overlap.
    let memsz = (filesz + 0xFFF) & !0xFFF;
    let entry = load_va; // entry = first byte of the blob

    // ── ELF64 header (64 bytes, little-endian) ────────────────────────────
    // e_ident[0..4]   = magic 0x7F 'E' 'L' 'F'
    // e_ident[4]      = ELFCLASS64 = 2
    // e_ident[5]      = ELFDATA2LSB = 1  (little-endian)
    // e_ident[6]      = EV_CURRENT = 1
    // e_ident[7]      = ELFOSABI_NONE = 0
    // e_ident[8..16]  = padding
    // e_type          = ET_EXEC = 2
    // e_machine       = EM_X86_64 = 0x3E = 62
    // e_version       = 1
    // e_entry         = load_va
    // e_phoff         = 64 (immediately after Ehdr)
    // e_shoff         = 0 (no section headers)
    // e_flags         = 0
    // e_ehsize        = 64
    // e_phentsize     = 56
    // e_phnum         = 1
    // e_shentsize     = 64
    // e_shnum         = 0
    // e_shstrndx      = SHN_UNDEF = 0

    let mut buf = Vec::with_capacity(0x78 + blob.len());

    // e_ident[0..16]
    buf.extend_from_slice(b"\x7fELF"); // magic
    buf.push(2); // ELFCLASS64
    buf.push(1); // ELFDATA2LSB
    buf.push(1); // EV_CURRENT
    buf.push(0); // ELFOSABI_NONE
    buf.extend_from_slice(&[0u8; 8]); // padding (total ident = 16 bytes)

    // e_type (u16 LE) = ET_EXEC = 2
    buf.extend_from_slice(&2u16.to_le_bytes());
    // e_machine (u16 LE) = EM_X86_64 = 62
    buf.extend_from_slice(&62u16.to_le_bytes());
    // e_version (u32 LE) = 1
    buf.extend_from_slice(&1u32.to_le_bytes());
    // e_entry (u64 LE)
    buf.extend_from_slice(&entry.to_le_bytes());
    // e_phoff (u64 LE) = 64
    buf.extend_from_slice(&64u64.to_le_bytes());
    // e_shoff (u64 LE) = 0
    buf.extend_from_slice(&0u64.to_le_bytes());
    // e_flags (u32 LE) = 0
    buf.extend_from_slice(&0u32.to_le_bytes());
    // e_ehsize (u16 LE) = 64
    buf.extend_from_slice(&64u16.to_le_bytes());
    // e_phentsize (u16 LE) = 56
    buf.extend_from_slice(&56u16.to_le_bytes());
    // e_phnum (u16 LE) = 1
    buf.extend_from_slice(&1u16.to_le_bytes());
    // e_shentsize (u16 LE) = 64
    buf.extend_from_slice(&64u16.to_le_bytes());
    // e_shnum (u16 LE) = 0
    buf.extend_from_slice(&0u16.to_le_bytes());
    // e_shstrndx (u16 LE) = 0
    buf.extend_from_slice(&0u16.to_le_bytes());

    assert_eq!(buf.len(), 64, "Ehdr must be exactly 64 bytes");

    // ── PT_LOAD program header (56 bytes, little-endian) ──────────────────
    // p_type   (u32) = PT_LOAD = 1
    // p_flags  (u32) = PF_R|PF_W|PF_X = 7
    // p_offset (u64) = file_offset (0x78)
    // p_vaddr  (u64) = load_va
    // p_paddr  (u64) = load_va  (physical == virtual for static ELF)
    // p_filesz (u64) = blob.len()
    // p_memsz  (u64) = memsz (page-rounded)
    // p_align  (u64) = 0x1000  (4 KiB page)

    buf.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    buf.extend_from_slice(&7u32.to_le_bytes()); // p_flags = R|W|X
    buf.extend_from_slice(&file_offset.to_le_bytes()); // p_offset
    buf.extend_from_slice(&load_va.to_le_bytes()); // p_vaddr
    buf.extend_from_slice(&load_va.to_le_bytes()); // p_paddr
    buf.extend_from_slice(&filesz.to_le_bytes()); // p_filesz
    buf.extend_from_slice(&memsz.to_le_bytes()); // p_memsz
    buf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    assert_eq!(buf.len(), 120, "Ehdr + Phdr must be 120 bytes");

    // ── Blob data ─────────────────────────────────────────────────────────
    buf.extend_from_slice(blob);

    buf
}

// ─── T5: M0/M1 combined — ring-3 SYSCALL doorbell round-trip ────────────────

/// M0/M1 combined: a hand-encoded ring-3 flat binary wrapped in a minimal ELF.
/// Issues `write(1, "hello\n", 6)` then `exit_group(0)` via real `SYSCALL`
/// instructions.  Proves the complete trap vehicle end-to-end:
///
///   ring-3 SYSCALL → LSTAR stub (OUT 0xC5) → KVM_EXIT_IO →
///   VcpuExit::IoOut(0xC5) → KvmX86TrapEngine::next_syscall → handler →
///   complete_syscall (write RAX) → KVM resumes → exit_group → Ok(0)
///
/// Pass conditions: stdout == `b"hello\n"` AND exit code 0.
#[test]
fn test_m01_syscall_round_trip() {
    if !kvm_available() {
        eprintln!("SKIP: /dev/kvm not available");
        return;
    }

    use carrick_vmm_kvm::guest_setup_x86::{M01_BLOB_VA, m01_blob};

    // Build the blob and wrap it in a minimal x86_64 ELF.
    let blob = m01_blob();
    let elf_bytes = make_x86_elf(&blob, M01_BLOB_VA);

    // Write to a temp file.
    let tmp_path = "/tmp/carrick_m01_blob.elf";
    std::fs::write(tmp_path, &elf_bytes).expect("write m01 elf");

    // Run via the carrick-vmm-kvm binary (routes to run_elf_kvm_x86 on x86_64).
    // Derive the binary path from the test executable's location:
    //   test binary: target/{profile}/deps/live_vcpu_x86-<hash>
    //   carrick-vmm-kvm binary: target/{profile}/carrick-vmm-kvm
    let bin = carrick_linux_bin_path();

    eprintln!("[M0/M1] running blob ELF via {}", bin.display());
    let out = Command::new(&bin)
        .args(["run-elf", tmp_path])
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "carrick-vmm-kvm binary must exist at {}: {e}",
                bin.display()
            )
        });

    eprintln!(
        "[M0/M1] stdout={:?} stderr={:?} status={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        out.status,
    );

    assert_eq!(
        out.stdout,
        b"hello\n",
        "M0/M1 stdout mismatch: got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(out.status.success(), "M0/M1 exit code: {:?}", out.status);

    std::fs::remove_file(tmp_path).ok();
}

// ─── T6: M2 — static musl ELF hello-world ────────────────────────────────────

/// M2: run the pre-built static x86_64 musl-linked `hello` fixture under KVM.
///
/// The fixture is `crates/carrick-vmm-bhyve/fixtures/hello-x86_64/target/
/// x86_64-unknown-linux-musl/release/hello` — the same binary the bhyve
/// plan builds.  Build it first if absent:
/// ```
/// cargo build --release \
///   --manifest-path crates/carrick-vmm-bhyve/fixtures/hello-x86_64/Cargo.toml \
///   --target x86_64-unknown-linux-musl
/// ```
///
/// Pass condition: stdout byte-identical to `oracle.expected` AND exit code 0.
#[test]
fn test_m2_musl_static_hello() {
    if !kvm_available() {
        eprintln!("SKIP: /dev/kvm not available");
        return;
    }

    let root = workspace_root();
    let fixture = root.join(
        "crates/carrick-vmm-bhyve/fixtures/hello-x86_64/\
         target/x86_64-unknown-linux-musl/release/carrick-hello-x86_64",
    );
    if !fixture.exists() {
        eprintln!(
            "SKIP: fixture not built — run: \
             cargo build --release \
             --manifest-path crates/carrick-vmm-bhyve/fixtures/hello-x86_64/Cargo.toml \
             --target x86_64-unknown-linux-musl"
        );
        return;
    }

    let bin = carrick_linux_bin_path();

    eprintln!("[M2] running fixture via {}", bin.display());
    let out = Command::new(&bin)
        .args(["run-elf", fixture.to_str().unwrap()])
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "carrick-vmm-kvm binary must exist at {}: {e}",
                bin.display()
            )
        });

    eprintln!(
        "[M2] stdout={:?} stderr={:?} status={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        out.status,
    );

    // oracle.expected is a plain text file (no trailing newline added by git).
    let expected = include_bytes!("../../carrick-vmm-bhyve/fixtures/hello-x86_64/oracle.expected");
    assert_eq!(
        out.stdout,
        expected,
        "M2 stdout mismatch: got {:?} want {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(expected),
    );
    assert!(out.status.success(), "M2 exit code: {:?}", out.status);
}
