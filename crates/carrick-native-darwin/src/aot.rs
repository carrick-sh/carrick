//! Stage 1 of the file-backed AOT translation cache
//! (`docs/superpowers/specs/2026-07-26-file-backed-aot-cache-design.md`):
//! emit translated code as a loadable, ad-hoc-signable Mach-O dylib instead of
//! writing it into `MAP_JIT` memory.
//!
//! # Why this exists
//!
//! `MAP_JIT` is the single largest remaining cost in a guest `fork(2)`.
//! `vm_map_enter` stamps every `entry_for_jit` mapping
//! `MEMORY_OBJECT_COPY_NONE` (`osfmk/vm/vm_map.c:3537`), which routes it to
//! `vm_map_fork`'s **slow** path — `vm_map_copyin_internal_for_entry` →
//! `vm_object_copy_strategically` — that eagerly copies and frees pages rather
//! than resolving copy-on-write lazily. MEASURED on this box, 64 MiB of
//! executable code, otherwise-identical process, fork p50 over 5 round-robin
//! rounds:
//!
//! | mapping                                | fork p50 | delta   |
//! |----------------------------------------|----------|---------|
//! | none                                   | 420 us   | --      |
//! | `dlopen` of an ad-hoc-signed dylib     | 414 us   | **-6**  |
//! | `mmap(MAP_JIT)`                        | 987 us   | **+567**|
//!
//! File-backed executable code is free; `MAP_JIT` is not, and its cost scales
//! with the mapping's VA *range* whether or not we use it.
//!
//! # Why a dylib and not a raw file
//!
//! MEASURED: `mmap(PROT_EXEC)` of an unsigned file fails `EPERM` — AMFI
//! requires a signature to map a file executable. Ad-hoc signing a Mach-O we
//! generated ourselves and loading it with `dlopen` DOES work (carrick is
//! ad-hoc signed without hardened runtime, the configuration that permits it),
//! and yields exactly the mapping we want: `r-x`, `SM=COW`, file-backed.
//!
//! # Scope of this module
//!
//! Emission only. It turns a caller-supplied blob of already-translated arm64
//! instructions into the bytes of a dylib exporting one symbol at a
//! caller-chosen offset. Signing, the on-disk store, cache keying and the
//! translator wiring are later stages and deliberately live elsewhere.

/// A symbol to export from an emitted unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AotExport<'a> {
    /// Exported symbol name, as `dlsym` will see it (no leading underscore —
    /// the emitter adds the Mach-O `_` prefix).
    pub name: &'a str,
    /// Byte offset of the entry point within `code`.
    pub offset: u32,
}

/// Why an emission attempt could not produce a loadable unit. Every variant is
/// a reason to fall back to `MAP_JIT`, never to fail the guest.
#[derive(Debug)]
pub enum AotEmitError {
    /// `code` was empty, or not a whole number of 4-byte arm64 instructions.
    CodeNotInstructionAligned(usize),
    /// An export pointed outside `code`, or was itself misaligned.
    ExportOutOfRange {
        name: String,
        offset: u32,
        code_len: usize,
    },
    /// A symbol name cannot be represented in a Mach-O string table.
    SymbolNameUnrepresentable(String),
    /// The Mach-O writer rejected the unit. Kept as a string because the
    /// upstream error is not part of our fallback contract - every variant here
    /// means "fall back to MAP_JIT", not "fail the guest".
    Writer(String),
}

impl std::fmt::Display for AotEmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeNotInstructionAligned(len) => write!(
                f,
                "translated code must be a nonzero multiple of 4 bytes, got {len}"
            ),
            Self::ExportOutOfRange {
                name,
                offset,
                code_len,
            } => write!(
                f,
                "export {name:?} at offset {offset} is outside the {code_len}-byte code blob \
                 (or is not 4-byte aligned)"
            ),
            Self::SymbolNameUnrepresentable(name) => {
                write!(f, "symbol name {name:?} cannot be encoded (embedded NUL)")
            }
            Self::Writer(msg) => write!(f, "Mach-O writer rejected the unit: {msg}"),
        }
    }
}

impl std::error::Error for AotEmitError {}

/// Validate an emission request. Split out from the writer so the preconditions
/// are testable without producing a file, and so every rejection is a typed
/// fallback reason rather than a panic inside the translator.
pub fn validate(code: &[u8], exports: &[AotExport<'_>]) -> Result<(), AotEmitError> {
    if code.is_empty() || !code.len().is_multiple_of(4) {
        return Err(AotEmitError::CodeNotInstructionAligned(code.len()));
    }
    for export in exports {
        if export.name.as_bytes().contains(&0) {
            return Err(AotEmitError::SymbolNameUnrepresentable(
                export.name.to_owned(),
            ));
        }
        let offset = export.offset as usize;
        if offset >= code.len() || !offset.is_multiple_of(4) {
            return Err(AotEmitError::ExportOutOfRange {
                name: export.name.to_owned(),
                offset: export.offset,
                code_len: code.len(),
            });
        }
    }
    Ok(())
}

/// Mach-O constants. These are published ABI numbers from `<mach-o/loader.h>`,
/// the same category as the Linux syscall numbers `carrick-abi` carries.
mod macho {
    pub const MH_MAGIC_64: u32 = 0xfeed_facf;
    pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
    pub const MH_DYLIB: u32 = 6;
    pub const MH_NOUNDEFS: u32 = 0x1;
    pub const MH_DYLDLINK: u32 = 0x4;
    pub const MH_TWOLEVEL: u32 = 0x80;

    pub const LC_SEGMENT_64: u32 = 0x19;
    pub const LC_SYMTAB: u32 = 0x2;
    pub const LC_DYSYMTAB: u32 = 0xb;
    pub const LC_ID_DYLIB: u32 = 0xd;
    pub const LC_BUILD_VERSION: u32 = 0x32;
    pub const LC_REQ_DYLD: u32 = 0x8000_0000;
    pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;

    pub const VM_PROT_READ: i32 = 0x1;
    pub const VM_PROT_EXECUTE: i32 = 0x4;
    pub const PLATFORM_MACOS: u32 = 1;

    /// `N_SECT | N_EXT`: defined in a section, externally visible.
    pub const N_SECT_EXT: u8 = 0x0f;
    /// `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`.
    pub const TEXT_SECTION_FLAGS: u32 = 0x8000_0400;

    /// arm64 macOS page size. `__LINKEDIT` must start on a page boundary.
    pub const PAGE: u64 = 16384;
    /// Slack between the load commands and the first section.
    ///
    /// Signing APPENDS an `LC_CODE_SIGNATURE` (16 bytes). With a tight header
    /// that grows `sizeofcmds`, the first section slides forward, and every
    /// symbol address we emitted then points 16 bytes short of the real code —
    /// which faults on the first call rather than failing to load. Real linkers
    /// leave slack for exactly this reason.
    pub const HEADER_SLACK: u64 = 256;
}

fn uleb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        out.push(if value != 0 { byte | 0x80 } else { byte });
        if value == 0 {
            return;
        }
    }
}

/// Build the dyld export trie: a root node with one edge per export, each edge
/// carrying the complete symbol name and pointing at a terminal node.
///
/// The child offsets are a fixed point — an offset's own ULEB length changes the
/// root's length, which changes the offsets. Solve by iterating to stability.
/// A spike that searched too narrow a range silently emitted offset 7 for a true
/// offset of 21, which sent dyld into the middle of a symbol name and trapped
/// inside `mach_o::ExportsTrie::valid`.
fn export_trie(exports: &[(String, u64)]) -> Vec<u8> {
    // Terminal node per export: terminal_size, flags(0 = regular), address,
    // then a zero child count.
    let terminals: Vec<Vec<u8>> = exports
        .iter()
        .map(|(_, addr)| {
            let mut payload = Vec::new();
            uleb128(0, &mut payload); // EXPORT_SYMBOL_FLAGS_KIND_REGULAR
            uleb128(*addr, &mut payload);
            let mut node = Vec::new();
            uleb128(payload.len() as u64, &mut node);
            node.extend_from_slice(&payload);
            node.push(0); // no children
            node
        })
        .collect();

    let mut offsets: Vec<u64> = vec![0; exports.len()];
    let mut root = Vec::new();
    for _ in 0..16 {
        root.clear();
        uleb128(0, &mut root); // root is not itself terminal
        root.push(exports.len() as u8);
        for (i, (name, _)) in exports.iter().enumerate() {
            // The trie stores the MACH-O name, i.e. with the leading
            // underscore; `dlsym("foo")` looks up `_foo`.
            root.push(b'_');
            root.extend_from_slice(name.as_bytes());
            root.push(0);
            uleb128(offsets[i], &mut root);
        }
        let mut cursor = root.len() as u64;
        let mut next = Vec::with_capacity(exports.len());
        for terminal in &terminals {
            next.push(cursor);
            cursor += terminal.len() as u64;
        }
        if next == offsets {
            let mut trie = root;
            for terminal in &terminals {
                trie.extend_from_slice(terminal);
            }
            while !trie.len().is_multiple_of(8) {
                trie.push(0);
            }
            return trie;
        }
        offsets = next;
    }
    unreachable!("export trie offsets converge in at most a couple of rounds")
}

/// Emit a complete, loadable arm64 `MH_DYLIB` whose `__TEXT,__text` is `code`
/// and which exports `exports`.
///
/// Written directly rather than emitted as a relocatable object and linked:
/// SPIKED AND PROVEN that dyld loads a hand-built dylib with **no
/// `LC_LOAD_DYLIB` at all**. `ld` refuses to produce one ("dylibs must link with
/// libSystem.dylib") but that is a linker policy, not a dyld requirement, and a
/// translated unit is genuinely self-contained. Emitting directly removes an
/// `ld` process spawn from the per-unit cost.
///
/// The result is NOT signed. AMFI refuses to map an unsigned file executable
/// (MEASURED: `mmap(PROT_EXEC)` -> `EPERM`), so a caller must sign before
/// `dlopen`.
pub fn emit_dylib(code: &[u8], exports: &[AotExport<'_>]) -> Result<Vec<u8>, AotEmitError> {
    use macho::*;
    validate(code, exports)?;

    const SEG_CMD: u64 = 72;
    const SECT: u64 = 80;
    const SYMTAB_CMD: u64 = 24;
    const DYSYMTAB_CMD: u64 = 80;
    const DYLD_INFO_CMD: u64 = 48;
    const BUILD_VERSION_CMD: u64 = 24; // 24 when ntools == 0; declaring 32 left
    // eight bytes of garbage in the command stream and dyld rejected the whole
    // image with a bare "not a mach-o".

    let install_name = b"@rpath/carrick_aot.dylib";
    let id_dylib_cmd = 24 + (install_name.len() as u64 + 1).next_multiple_of(8);

    let sizeofcmds = (SEG_CMD + SECT)
        + SEG_CMD
        + id_dylib_cmd
        + DYLD_INFO_CMD
        + SYMTAB_CMD
        + DYSYMTAB_CMD
        + BUILD_VERSION_CMD;
    let header_size = 32 + sizeofcmds + HEADER_SLACK;

    // `__TEXT` has vmaddr 0 and covers the header, so a section's vmaddr and its
    // file offset are the same number.
    let code_addr = header_size;
    let text_vmsize = (code_addr + code.len() as u64).next_multiple_of(PAGE);
    let linkedit_off = text_vmsize;

    let resolved: Vec<(String, u64)> = exports
        .iter()
        .map(|e| (e.name.to_owned(), code_addr + u64::from(e.offset)))
        .collect();
    let trie = export_trie(&resolved);

    // String table: a leading NUL, then each `_name`.
    let mut strtab = vec![0u8];
    let mut name_offsets = Vec::with_capacity(exports.len());
    for export in exports {
        name_offsets.push(strtab.len() as u32);
        strtab.push(b'_');
        strtab.extend_from_slice(export.name.as_bytes());
        strtab.push(0);
    }
    while !strtab.len().is_multiple_of(8) {
        strtab.push(0);
    }

    let mut nlists = Vec::new();
    for (i, (_, addr)) in resolved.iter().enumerate() {
        nlists.extend_from_slice(&name_offsets[i].to_le_bytes());
        nlists.push(N_SECT_EXT);
        nlists.push(1); // section 1 == __text
        nlists.extend_from_slice(&0u16.to_le_bytes());
        nlists.extend_from_slice(&addr.to_le_bytes());
    }

    let symoff = linkedit_off + trie.len() as u64;
    let stroff = symoff + nlists.len() as u64;
    let linkedit_size = trie.len() as u64 + nlists.len() as u64 + strtab.len() as u64;

    let mut cmds: Vec<u8> = Vec::with_capacity(sizeofcmds as usize);
    let seg = |name: &[u8],
               vmaddr: u64,
               vmsize: u64,
               off: u64,
               fsize: u64,
               prot: i32,
               nsects: i32,
               cmdsize: u64,
               out: &mut Vec<u8>| {
        out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        let mut padded = [0u8; 16];
        padded[..name.len()].copy_from_slice(name);
        out.extend_from_slice(&padded);
        for v in [vmaddr, vmsize, off, fsize] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [prot, prot, nsects, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };

    seg(
        b"__TEXT",
        0,
        text_vmsize,
        0,
        text_vmsize,
        VM_PROT_READ | VM_PROT_EXECUTE,
        1,
        SEG_CMD + SECT,
        &mut cmds,
    );
    // section_64 for __text
    let mut sect_name = [0u8; 16];
    sect_name[..6].copy_from_slice(b"__text");
    let mut seg_name = [0u8; 16];
    seg_name[..6].copy_from_slice(b"__TEXT");
    cmds.extend_from_slice(&sect_name);
    cmds.extend_from_slice(&seg_name);
    cmds.extend_from_slice(&code_addr.to_le_bytes());
    cmds.extend_from_slice(&(code.len() as u64).to_le_bytes());
    cmds.extend_from_slice(&(code_addr as u32).to_le_bytes());
    cmds.extend_from_slice(&2u32.to_le_bytes()); // align 2^2 = 4, the arm64 instruction size
    for v in [0u32, 0, TEXT_SECTION_FLAGS, 0, 0, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    seg(
        b"__LINKEDIT",
        linkedit_off,
        linkedit_size.next_multiple_of(PAGE),
        linkedit_off,
        linkedit_size,
        VM_PROT_READ,
        0,
        SEG_CMD,
        &mut cmds,
    );

    // LC_ID_DYLIB. The name is a NUL-TERMINATED string padded out to the
    // command's declared size; aligning `cmds` to 8 instead happened to land on
    // a shorter length than declared and desynchronised `sizeofcmds`.
    let id_start = cmds.len();
    cmds.extend_from_slice(&LC_ID_DYLIB.to_le_bytes());
    cmds.extend_from_slice(&(id_dylib_cmd as u32).to_le_bytes());
    for v in [24u32, 0, 0x1_0000, 0x1_0000] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }
    cmds.extend_from_slice(install_name);
    while (cmds.len() - id_start) < id_dylib_cmd as usize {
        cmds.push(0);
    }

    // LC_DYLD_INFO_ONLY: rebase/bind/weak/lazy all empty, export = the trie.
    // The trie MUST land in the export pair; a spike that put it in the
    // lazy-bind pair made dyld read trie bytes as bind opcodes.
    cmds.extend_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
    cmds.extend_from_slice(&(DYLD_INFO_CMD as u32).to_le_bytes());
    for v in [0u32, 0, 0, 0, 0, 0, 0, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }
    cmds.extend_from_slice(&(linkedit_off as u32).to_le_bytes());
    cmds.extend_from_slice(&(trie.len() as u32).to_le_bytes());

    // LC_SYMTAB
    cmds.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    cmds.extend_from_slice(&(SYMTAB_CMD as u32).to_le_bytes());
    for v in [
        symoff as u32,
        exports.len() as u32,
        stroff as u32,
        strtab.len() as u32,
    ] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    // LC_DYSYMTAB. dyld ENFORCES `iundefsym == iextdefsym + nextdefsym`;
    // violating it rejects the image with "indirect symbol table
    // iundefsym != iextdefsym+nextdefsym".
    let n = exports.len() as u32;
    cmds.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
    cmds.extend_from_slice(&(DYSYMTAB_CMD as u32).to_le_bytes());
    for v in [0u32, 0, 0, n, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    // LC_BUILD_VERSION, ntools = 0.
    cmds.extend_from_slice(&LC_BUILD_VERSION.to_le_bytes());
    cmds.extend_from_slice(&(BUILD_VERSION_CMD as u32).to_le_bytes());
    for v in [PLATFORM_MACOS, 11 << 16, 11 << 16, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    debug_assert_eq!(cmds.len() as u64, sizeofcmds);

    let mut out = Vec::with_capacity((linkedit_off + linkedit_size) as usize);
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    out.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    out.extend_from_slice(&MH_DYLIB.to_le_bytes());
    out.extend_from_slice(&7u32.to_le_bytes()); // ncmds
    out.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
    out.extend_from_slice(&(MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&cmds);
    out.resize(code_addr as usize, 0); // HEADER_SLACK
    out.extend_from_slice(code);
    out.resize(linkedit_off as usize, 0);
    out.extend_from_slice(&trie);
    out.extend_from_slice(&nlists);
    out.extend_from_slice(&strtab);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `mov w0, #42 ; ret` — the smallest blob whose execution proves the whole
    /// pipeline (emit -> sign -> dlopen -> dlsym -> call) actually works.
    const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

    #[test]
    fn rejects_code_that_is_not_whole_instructions() {
        // A truncated blob would emit a dylib that faults on entry rather than
        // failing here, so this must be caught before anything is written.
        assert!(matches!(
            validate(&MOV42_RET[..5], &[]),
            Err(AotEmitError::CodeNotInstructionAligned(5))
        ));
        assert!(matches!(
            validate(&[], &[]),
            Err(AotEmitError::CodeNotInstructionAligned(0))
        ));
    }

    #[test]
    fn rejects_exports_outside_the_code_blob() {
        let past_end = AotExport {
            name: "carrick_aot_entry",
            offset: 8,
        };
        assert!(matches!(
            validate(&MOV42_RET, &[past_end]),
            Err(AotEmitError::ExportOutOfRange { offset: 8, .. })
        ));
        let misaligned = AotExport {
            name: "carrick_aot_entry",
            offset: 2,
        };
        assert!(matches!(
            validate(&MOV42_RET, &[misaligned]),
            Err(AotEmitError::ExportOutOfRange { offset: 2, .. })
        ));
    }

    /// THE stage-1 proof: emit -> ad-hoc sign -> `dlopen` -> `dlsym` -> CALL.
    ///
    /// Nothing short of executing the code proves the emitted Mach-O is real.
    /// A structurally-plausible-but-wrong dylib fails at `dlopen` or faults on
    /// entry, and both are exactly the bugs this stage exists to catch.
    ///
    /// There is deliberately NO linker step: `emit_dylib` produces `MH_DYLIB`
    /// directly. Signing still shells out to `codesign` here because the test is
    /// proving the FORMAT; replacing it with an in-process signer is a separate
    /// decision (measured: `codesign` costs 0.03 s at 16 MiB — fine for a test,
    /// too slow for a hot path).
    #[test]
    fn emitted_dylib_is_signable_loadable_and_executable() {
        let entry = AotExport {
            name: "carrick_aot_entry",
            offset: 0,
        };
        let bytes = emit_dylib(&MOV42_RET, &[entry]).expect("emit a one-instruction unit");

        let dir = std::env::temp_dir().join(format!("carrick-aot-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("unit.dylib");
        std::fs::write(&path, &bytes).expect("write the emitted unit");

        // AMFI refuses to map an unsigned file executable, so an unsigned unit
        // would fail `dlopen` no matter how correct the Mach-O is.
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["-s", "-"])
            .arg(&path)
            .output()
            .expect("run codesign");
        assert!(
            signed.status.success(),
            "ad-hoc signing the emitted unit failed: {}",
            String::from_utf8_lossy(&signed.stderr)
        );

        let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring");
        // SAFETY: `c_path` is a live NUL-terminated path to a file this test
        // just wrote and signed.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
        assert!(
            !handle.is_null(),
            "dlopen of the emitted unit failed: {}",
            // SAFETY: dlerror returns a static NUL-terminated string or null.
            unsafe {
                let e = libc::dlerror();
                if e.is_null() {
                    "(no dlerror)".to_owned()
                } else {
                    std::ffi::CStr::from_ptr(e).to_string_lossy().into_owned()
                }
            }
        );

        let sym = std::ffi::CString::new(entry.name).expect("cstring");
        // SAFETY: `handle` is a live dlopen handle; the symbol was exported by
        // `emit_dylib` at offset 0 of the code blob.
        let addr = unsafe { libc::dlsym(handle, sym.as_ptr()) };
        assert!(!addr.is_null(), "dlsym({:?}) found nothing", entry.name);

        // SAFETY: the symbol addresses `mov w0,#42; ret` - a leaf function
        // taking no arguments and returning an int, matching this signature.
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(addr) };
        assert_eq!(f(), 42, "executed the emitted unit but got the wrong value");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn accepts_a_well_formed_unit() {
        let entry = AotExport {
            name: "carrick_aot_entry",
            offset: 0,
        };
        assert!(validate(&MOV42_RET, &[entry]).is_ok());
    }
}
