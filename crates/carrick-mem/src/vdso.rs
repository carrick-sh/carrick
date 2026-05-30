//! A minimal Linux aarch64 vDSO so the guest reads the clock in userspace
//! (reading `CNTVCT_EL0` directly, enabled by `CNTKCTL_EL1.EL0VCTEN`) instead of
//! issuing a `clock_gettime` syscall per read. Without it, timer/clock-heavy Go
//! code (the `time` package) drowns in HVF vmexits — ~4.27M `clock_gettime`
//! syscalls in 15s — and effectively hangs.
//!
//! We control BOTH the vDSO code and the vvar data page it reads, so the
//! internal data-page ABI is ours; only the EXTERNAL ELF contract (a versioned
//! `__kernel_clock_gettime@LINUX_2.6.39` dynamic symbol resolvable through a
//! SysV hash + verdef) must match what Go's `runtime/vdso_linux*.go` parser
//! looks up. The function bodies are assembled once with the host toolchain
//! (see `tools/vdso_fns.s`) and embedded here as `VDSO_CODE`; the ELF wrapper
//! (headers, .dynsym, .dynstr, .hash, .gnu.version, .gnu.version_d, .dynamic) is
//! hand-built below — no build-time toolchain dependency.

/// Guest VA of the vvar (timekeeping) data page. The embedded code loads this
/// with a single `movz x9, #0x2E, lsl #32`, so it MUST match the asm.
pub const LINUX_VVAR_BASE: u64 = 0x2E_0000_0000;
/// Guest VA of the vDSO code/ELF page (one 64 KiB slot above vvar). This is the
/// value published in `AT_SYSINFO_EHDR`.
pub const LINUX_VDSO_BASE: u64 = 0x2E_0001_0000;
/// Page sizes reserved for each region.
pub const LINUX_VVAR_SIZE: u64 = 0x1000;
pub const LINUX_VDSO_SIZE: u64 = 0x1000;

/// Byte offsets into the vvar data page (little-endian u64s). carrick fills
/// these; the vDSO code reads them.
pub const VVAR_OFF_SEQ: usize = 0; // seqlock (even = stable) — reserved
pub const VVAR_OFF_FREQ: usize = 8; // CNTFRQ_EL0 in Hz
pub const VVAR_OFF_REALTIME_OFF_NS: usize = 16; // wall_ns - monotonic_ns

/// The assembled clock functions (aarch64). Offsets within this blob:
/// `__kernel_clock_gettime` @ 0x00, `__kernel_gettimeofday` @ 0x84,
/// `__kernel_clock_getres` @ 0xdc, `__kernel_rt_sigreturn` @ 0x104,
/// `__kernel_getrandom` @ 0x10c.
/// See `tools/vdso_fns.s`.
const VDSO_CODE: &[u8] = &[
    0x1f, 0x1c, 0x00, 0x71, 0x28, 0x01, 0x00, 0x54, 0x1f, 0x10, 0x00, 0x71, 0x40, 0x01, 0x00, 0x54,
    0x1f, 0x04, 0x00, 0x71, 0x00, 0x01, 0x00, 0x54, 0x1f, 0x1c, 0x00, 0x71, 0xc0, 0x00, 0x00, 0x54,
    0x1f, 0x00, 0x00, 0x71, 0x80, 0x00, 0x00, 0x54, 0x28, 0x0e, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    0xc0, 0x03, 0x5f, 0xd6, 0xc9, 0x05, 0xc0, 0xd2, 0x42, 0xe0, 0x3b, 0xd5, 0x0a, 0xe0, 0x3b, 0xd5,
    0x43, 0x08, 0xca, 0x9a, 0x64, 0x88, 0x0a, 0x9b, 0x0b, 0x40, 0x99, 0xd2, 0x4b, 0x73, 0xa7, 0xf2,
    0x84, 0x7c, 0x0b, 0x9b, 0x84, 0x08, 0xca, 0x9a, 0x65, 0x10, 0x0b, 0x9b, 0x1f, 0x00, 0x00, 0x71,
    0x61, 0x00, 0x00, 0x54, 0x2c, 0x09, 0x40, 0xf9, 0xa5, 0x00, 0x0c, 0x8b, 0xa7, 0x08, 0xcb, 0x9a,
    0xe4, 0x94, 0x0b, 0x9b, 0x27, 0x00, 0x00, 0xf9, 0x24, 0x04, 0x00, 0xf9, 0x00, 0x00, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0x80, 0x02, 0x00, 0xb4, 0xed, 0x03, 0x00, 0xaa, 0xc9, 0x05, 0xc0, 0xd2,
    0x42, 0xe0, 0x3b, 0xd5, 0x0a, 0xe0, 0x3b, 0xd5, 0x43, 0x08, 0xca, 0x9a, 0x64, 0x88, 0x0a, 0x9b,
    0x0b, 0x40, 0x99, 0xd2, 0x4b, 0x73, 0xa7, 0xf2, 0x84, 0x7c, 0x0b, 0x9b, 0x84, 0x08, 0xca, 0x9a,
    0x65, 0x10, 0x0b, 0x9b, 0x2c, 0x09, 0x40, 0xf9, 0xa5, 0x00, 0x0c, 0x8b, 0xa7, 0x08, 0xcb, 0x9a,
    0xe4, 0x94, 0x0b, 0x9b, 0x0e, 0x7d, 0x80, 0xd2, 0x84, 0x08, 0xce, 0x9a, 0xa7, 0x01, 0x00, 0xf9,
    0xa4, 0x05, 0x00, 0xf9, 0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x1c, 0x00, 0x71,
    0xe8, 0x00, 0x00, 0x54, 0x81, 0x00, 0x00, 0xb4, 0x3f, 0x00, 0x00, 0xf9, 0x22, 0x00, 0x80, 0xd2,
    0x22, 0x04, 0x00, 0xf9, 0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x48, 0x0e, 0x80, 0xd2,
    0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6,
    // __kernel_rt_sigreturn (8 bytes): `mov x8, #139 (__NR_rt_sigreturn); svc #0`.
    // The canonical aarch64 sigreturn trampoline body — unwinders (libgcc, gdb,
    // Go traceback) recognise a signal frame by matching this exact instruction
    // pair at the PC. (See SYM_RT_SIGRETURN; it precedes getrandom below.)
    0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
    // __kernel_getrandom (72 bytes, assembled from tools/vdso_fns.s; P1). QUERY
    // mode (opaque_len == ~0UL) fills vgetrandom_opaque_params{size_of_opaque_
    // state=144, mmap_prot=3, mmap_flags=0x28 (MAP_ANON|MAP_DROPPABLE)} and
    // returns 0; otherwise falls back to the getrandom(2) syscall (x8=278). Fully
    // position-independent (movz immediates only, no literal pool).
    0x9f, 0x04, 0x00, 0xb1, 0xc1, 0x01, 0x00, 0x54, 0x09, 0x12, 0x80, 0x52, 0x69, 0x00, 0x00, 0xb9,
    0x69, 0x00, 0x80, 0x52, 0x69, 0x04, 0x00, 0xb9, 0x09, 0x05, 0x80, 0x52, 0x69, 0x08, 0x00, 0xb9,
    0x6a, 0x30, 0x00, 0x91, 0xab, 0x01, 0x80, 0x52, 0x5f, 0x45, 0x00, 0xb8, 0x6b, 0x05, 0x00, 0x71,
    0xc1, 0xff, 0xff, 0x54, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6, 0xc8, 0x22, 0x80, 0xd2,
    0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6,
];

// Symbol offsets within VDSO_CODE.
const SYM_CLOCK_GETTIME: u64 = 0x00;
const SYM_GETTIMEOFDAY: u64 = 0x84;
const SYM_CLOCK_GETRES: u64 = 0xdc;
// rt_sigreturn (8 B) then getrandom (72 B) are the trailing functions of
// VDSO_CODE; derive their offsets from the blob length so they stay correct
// regardless of the clock functions' size.
const GETRANDOM_LEN: u64 = 72;
const RT_SIGRETURN_LEN: u64 = 8;
const SYM_GETRANDOM: u64 = VDSO_CODE.len() as u64 - GETRANDOM_LEN;
const SYM_RT_SIGRETURN: u64 = SYM_GETRANDOM - RT_SIGRETURN_LEN;

const EM_AARCH64: u16 = 183;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const STB_GLOBAL_FUNC: u8 = 0x12; // (STB_GLOBAL<<4)|STT_FUNC
const STB_GLOBAL_NOTYPE: u8 = 0x10; // (STB_GLOBAL<<4)|STT_NOTYPE — Linux marks
// __kernel_rt_sigreturn this way; match it.
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
/// vd_hash of "LINUX_2.6.39" — Go's `vdsoLinuxVersion.verHash`.
const LINUX_2_6_39_HASH: u32 = 0x75f_cb89;

fn align_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

/// Build the complete vDSO ELF image (to be mapped at `LINUX_VDSO_BASE`). All
/// `d_val`/`st_value` are file offsets, valid because the single PT_LOAD has
/// `p_vaddr == p_offset == 0`, so Go's `loadOffset` is exactly the load base.
pub fn vdso_image_bytes() -> Vec<u8> {
    // ---- string table ----
    let mut dynstr = Vec::new();
    dynstr.push(0u8);
    let name_gettime = dynstr.len() as u32;
    dynstr.extend_from_slice(b"__kernel_clock_gettime\0");
    let name_gtod = dynstr.len() as u32;
    dynstr.extend_from_slice(b"__kernel_gettimeofday\0");
    let name_getres = dynstr.len() as u32;
    dynstr.extend_from_slice(b"__kernel_clock_getres\0");
    let name_rt_sigreturn = dynstr.len() as u32;
    dynstr.extend_from_slice(b"__kernel_rt_sigreturn\0");
    let name_getrandom = dynstr.len() as u32;
    dynstr.extend_from_slice(b"__kernel_getrandom\0");
    let name_version = dynstr.len() as u32;
    dynstr.extend_from_slice(b"LINUX_2.6.39\0");

    // ---- fixed-size sections; compute offsets ----
    const EHDR: usize = 64;
    const PHENT: usize = 56;
    const NPH: usize = 2;
    const SYMENT: usize = 24;
    const NSYM: usize = 6; // undef + 5 funcs (3 clock + rt_sigreturn + getrandom)

    let off_phdr = EHDR;
    let off_dynsym = off_phdr + NPH * PHENT;
    let off_dynstr = off_dynsym + NSYM * SYMENT;
    let off_hash = align_up(off_dynstr + dynstr.len(), 4);
    // SysV hash: nbucket=1, nchain=6; bucket=[1]; chain=[0,2,3,4,5,0]. nbucket=1
    // funnels every name to bucket 0, so lookup walks the chain 1->2->3->4->5->end.
    let hash: [u32; 9] = [1, 6, 1, 0, 2, 3, 4, 5, 0];
    let off_versym = off_hash + hash.len() * 4;
    // versym: one u16 per dynsym entry; funcs use version index 1.
    let versym: [u16; 6] = [0, 1, 1, 1, 1, 1];
    let off_verdef = align_up(off_versym + versym.len() * 2, 4);
    const VERDEF_SZ: usize = 20 + 8; // elfVerdef + elfVerdaux
    let off_dyn = align_up(off_verdef + VERDEF_SZ, 8);
    // dynamic entries (tag,val) — those Go reads, terminated by DT_NULL.
    let dyn_entries: &[(i64, u64)] = &[
        (DT_HASH, off_hash as u64),
        (DT_STRTAB, off_dynstr as u64),
        (DT_SYMTAB, off_dynsym as u64),
        (DT_SYMENT, SYMENT as u64),
        (DT_STRSZ, dynstr.len() as u64),
        (DT_VERSYM, off_versym as u64),
        (DT_VERDEF, off_verdef as u64),
        (DT_VERDEFNUM, 1),
        (DT_NULL, 0),
    ];
    let off_dyn_end = off_dyn + dyn_entries.len() * 16;
    let off_code = align_up(off_dyn_end, 16);
    let off_code_end = off_code + VDSO_CODE.len();

    // ---- section-header string table + section headers ----
    // glibc/Go resolve vDSO symbols from PT_DYNAMIC and never need sections, so
    // historically we emitted none. Stricter parsers (Apple Rosetta) iterate the
    // SECTION headers looking for SHT_DYNSYM, so emit a minimal table: NULL,
    // .dynsym, .dynstr, .shstrtab.
    const SHENT: usize = 64; // sizeof(Elf64_Shdr)
    const NSH: usize = 4;
    let mut shstr = Vec::new();
    shstr.push(0u8);
    let sh_name_dynsym = shstr.len() as u32;
    shstr.extend_from_slice(b".dynsym\0");
    let sh_name_dynstr = shstr.len() as u32;
    shstr.extend_from_slice(b".dynstr\0");
    let sh_name_shstrtab = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab\0");

    let off_shstrtab = align_up(off_code_end, 4);
    let off_shdr = align_up(off_shstrtab + shstr.len(), 8);
    let total = off_shdr + NSH * SHENT;

    let mut buf = vec![0u8; total];

    // ---- ELF header ----
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    w16(&mut buf, 16, ET_DYN); // e_type
    w16(&mut buf, 18, EM_AARCH64); // e_machine
    w32(&mut buf, 20, 1); // e_version
    w64(&mut buf, 24, 0); // e_entry
    w64(&mut buf, 32, off_phdr as u64); // e_phoff
    w64(&mut buf, 40, off_shdr as u64); // e_shoff
    w32(&mut buf, 48, 0); // e_flags
    w16(&mut buf, 52, EHDR as u16); // e_ehsize
    w16(&mut buf, 54, PHENT as u16); // e_phentsize
    w16(&mut buf, 56, NPH as u16); // e_phnum
    w16(&mut buf, 58, SHENT as u16); // e_shentsize
    w16(&mut buf, 60, NSH as u16); // e_shnum
    w16(&mut buf, 62, 3); // e_shstrndx (.shstrtab is section index 3)

    // ---- program headers ----
    // PT_LOAD: covers the whole blob, R+X, vaddr==offset==0.
    let p0 = off_phdr;
    w32(&mut buf, p0, PT_LOAD);
    w32(&mut buf, p0 + 4, 0x5); // p_flags R+X
    w64(&mut buf, p0 + 8, 0); // p_offset
    w64(&mut buf, p0 + 16, 0); // p_vaddr
    w64(&mut buf, p0 + 24, 0); // p_paddr
    w64(&mut buf, p0 + 32, total as u64); // p_filesz
    w64(&mut buf, p0 + 40, total as u64); // p_memsz
    w64(&mut buf, p0 + 48, 0x1000); // p_align
    // PT_DYNAMIC
    let p1 = off_phdr + PHENT;
    w32(&mut buf, p1, PT_DYNAMIC);
    w32(&mut buf, p1 + 4, 0x4); // R
    w64(&mut buf, p1 + 8, off_dyn as u64); // p_offset
    w64(&mut buf, p1 + 16, off_dyn as u64); // p_vaddr
    w64(&mut buf, p1 + 24, off_dyn as u64); // p_paddr
    w64(&mut buf, p1 + 32, (off_dyn_end - off_dyn) as u64); // p_filesz
    w64(&mut buf, p1 + 40, (off_dyn_end - off_dyn) as u64); // p_memsz
    w64(&mut buf, p1 + 48, 8); // p_align

    // ---- .dynsym ----
    // `info` is st_info (STB_GLOBAL_FUNC for the clock fns, STB_GLOBAL_NOTYPE
    // for rt_sigreturn to mirror Linux), `shndx` is st_shndx (0 = undefined,
    // nonzero = defined; carrick uses 1 for every defined symbol).
    let sym =
        |buf: &mut [u8], idx: usize, name: u32, value: u64, size: u64, info: u8, shndx: u16| {
            let o = off_dynsym + idx * SYMENT;
            w32(buf, o, name); // st_name
            buf[o + 4] = info; // st_info
            buf[o + 5] = 0; // st_other
            w16(buf, o + 6, shndx); // st_shndx
            w64(buf, o + 8, value); // st_value
            w64(buf, o + 16, size); // st_size
        };
    sym(&mut buf, 0, 0, 0, 0, 0, 0); // STN_UNDEF
    sym(
        &mut buf,
        1,
        name_gettime,
        off_code as u64 + SYM_CLOCK_GETTIME,
        SYM_GETTIMEOFDAY - SYM_CLOCK_GETTIME,
        STB_GLOBAL_FUNC,
        1,
    );
    sym(
        &mut buf,
        2,
        name_gtod,
        off_code as u64 + SYM_GETTIMEOFDAY,
        SYM_CLOCK_GETRES - SYM_GETTIMEOFDAY,
        STB_GLOBAL_FUNC,
        1,
    );
    sym(
        &mut buf,
        3,
        name_getres,
        off_code as u64 + SYM_CLOCK_GETRES,
        SYM_RT_SIGRETURN - SYM_CLOCK_GETRES,
        STB_GLOBAL_FUNC,
        1,
    );
    // Linux marks __kernel_rt_sigreturn STT_NOTYPE; match it exactly.
    sym(
        &mut buf,
        4,
        name_rt_sigreturn,
        off_code as u64 + SYM_RT_SIGRETURN,
        RT_SIGRETURN_LEN,
        STB_GLOBAL_NOTYPE,
        1,
    );
    // __kernel_getrandom — a real STT_FUNC like the clock symbols.
    sym(
        &mut buf,
        5,
        name_getrandom,
        off_code as u64 + SYM_GETRANDOM,
        GETRANDOM_LEN,
        STB_GLOBAL_FUNC,
        1,
    );

    // ---- .dynstr ----
    buf[off_dynstr..off_dynstr + dynstr.len()].copy_from_slice(&dynstr);

    // ---- .hash ----
    for (i, v) in hash.iter().enumerate() {
        w32(&mut buf, off_hash + i * 4, *v);
    }

    // ---- .gnu.version ----
    for (i, v) in versym.iter().enumerate() {
        w16(&mut buf, off_versym + i * 2, *v);
    }

    // ---- .gnu.version_d (one verdef: LINUX_2.6.39, ndx=1) ----
    let vd = off_verdef;
    w16(&mut buf, vd, 1); // vd_version
    w16(&mut buf, vd + 2, 0); // vd_flags (not BASE)
    w16(&mut buf, vd + 4, 1); // vd_ndx
    w16(&mut buf, vd + 6, 1); // vd_cnt
    w32(&mut buf, vd + 8, LINUX_2_6_39_HASH); // vd_hash
    w32(&mut buf, vd + 12, 20); // vd_aux (verdaux right after the 20-byte verdef)
    w32(&mut buf, vd + 16, 0); // vd_next (last)
    w32(&mut buf, vd + 20, name_version); // vda_name
    w32(&mut buf, vd + 24, 0); // vda_next

    // ---- .dynamic ----
    for (i, (tag, val)) in dyn_entries.iter().enumerate() {
        let o = off_dyn + i * 16;
        w64(&mut buf, o, *tag as u64);
        w64(&mut buf, o + 8, *val);
    }

    // ---- code ----
    buf[off_code..off_code + VDSO_CODE.len()].copy_from_slice(VDSO_CODE);

    // ---- .shstrtab ----
    buf[off_shstrtab..off_shstrtab + shstr.len()].copy_from_slice(&shstr);

    // ---- section headers ----
    // The vDSO loads with vaddr == file offset (PT_LOAD p_vaddr = 0), so each
    // ALLOC section's sh_addr equals its sh_offset.
    const SHT_STRTAB: u32 = 3;
    const SHT_DYNSYM: u32 = 11;
    const SHF_ALLOC: u64 = 0x2;
    let mut shdr = |idx: usize,
                    name: u32,
                    sh_type: u32,
                    flags: u64,
                    addr_off: u64,
                    size: u64,
                    link: u32,
                    info: u32,
                    align: u64,
                    entsize: u64| {
        let o = off_shdr + idx * SHENT;
        w32(&mut buf, o, name);
        w32(&mut buf, o + 4, sh_type);
        w64(&mut buf, o + 8, flags);
        w64(&mut buf, o + 16, addr_off); // sh_addr (== sh_offset; vaddr==offset)
        w64(&mut buf, o + 24, addr_off); // sh_offset
        w64(&mut buf, o + 32, size);
        w32(&mut buf, o + 40, link);
        w32(&mut buf, o + 44, info);
        w64(&mut buf, o + 48, align);
        w64(&mut buf, o + 56, entsize);
    };
    // [0] SHT_NULL (all zero).
    shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    // [1] .dynsym — sh_link → .dynstr (index 2), sh_info = first global symbol (1).
    shdr(
        1,
        sh_name_dynsym,
        SHT_DYNSYM,
        SHF_ALLOC,
        off_dynsym as u64,
        (NSYM * SYMENT) as u64,
        2,
        1,
        8,
        SYMENT as u64,
    );
    // [2] .dynstr
    shdr(
        2,
        sh_name_dynstr,
        SHT_STRTAB,
        SHF_ALLOC,
        off_dynstr as u64,
        dynstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    // [3] .shstrtab (not ALLOC; only present for section-table parsers).
    shdr(
        3,
        sh_name_shstrtab,
        SHT_STRTAB,
        0,
        off_shstrtab as u64,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );

    buf
}

fn w16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vdso_elf_parses_and_exports_clock_gettime() {
        let img = vdso_image_bytes();
        let elf = goblin::elf::Elf::parse(&img).expect("vDSO must be a valid ELF");
        assert_eq!(elf.header.e_machine, EM_AARCH64);
        // The versioned dynamic symbol Go looks up must be present and defined.
        let mut found = false;
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name == "__kernel_clock_gettime" {
                    assert!(sym.st_value >= 64, "func must point into the code");
                    assert!(sym.is_function());
                    found = true;
                }
            }
        }
        assert!(found, "__kernel_clock_gettime not exported");
    }

    /// The aarch64 vDSO symbol set carrick exports, matching the LinuxKit 6.x
    /// oracle: the 4 classic `LINUX_2.6.39` symbols plus `__kernel_getrandom`
    /// (6.11+). All must resolve so unwinders/debuggers find rt_sigreturn by
    /// name and glibc finds the clock + getrandom fast paths.
    #[test]
    fn vdso_exports_all_canonical_symbols() {
        let img = vdso_image_bytes();
        let elf = goblin::elf::Elf::parse(&img).expect("vDSO must be a valid ELF");
        let code_lo = 64u64; // every defined func must point past the ELF header
        let code_hi = img.len() as u64;
        // The clock fns + getrandom are STT_FUNC; rt_sigreturn is STT_NOTYPE on
        // real Linux, so we only require it be defined (not its type).
        for (want, must_be_func) in [
            ("__kernel_clock_gettime", true),
            ("__kernel_gettimeofday", true),
            ("__kernel_clock_getres", true),
            ("__kernel_rt_sigreturn", false),
            ("__kernel_getrandom", true),
        ] {
            let sym = elf
                .dynsyms
                .iter()
                .find(|s| elf.dynstrtab.get_at(s.st_name) == Some(want))
                .unwrap_or_else(|| panic!("{want} not exported from vDSO"));
            if must_be_func {
                assert!(sym.is_function(), "{want} must be STT_FUNC");
            }
            assert_ne!(sym.st_shndx, 0, "{want} must be defined (st_shndx != 0)");
            assert!(
                sym.st_value >= code_lo && sym.st_value < code_hi,
                "{want} st_value {:#x} must point into the code blob",
                sym.st_value
            );
        }
    }

    /// `__kernel_rt_sigreturn` must be the canonical trampoline body
    /// `mov x8, #139 ; svc #0` — every unwinder recognises a signal frame by
    /// matching this exact instruction pair at the PC, not by symbol name.
    #[test]
    fn vdso_rt_sigreturn_is_the_canonical_trampoline_sequence() {
        let img = vdso_image_bytes();
        let elf = goblin::elf::Elf::parse(&img).unwrap();
        let sym = elf
            .dynsyms
            .iter()
            .find(|s| elf.dynstrtab.get_at(s.st_name) == Some("__kernel_rt_sigreturn"))
            .expect("__kernel_rt_sigreturn must exist");
        // st_value is a file offset (PT_LOAD vaddr==offset==0).
        let off = sym.st_value as usize;
        let mov_x8_139 = u32::from_le_bytes(img[off..off + 4].try_into().unwrap());
        let svc_0 = u32::from_le_bytes(img[off + 4..off + 8].try_into().unwrap());
        assert_eq!(mov_x8_139, 0xd280_1168, "expected `mov x8, #139`");
        assert_eq!(svc_0, 0xd400_0001, "expected `svc #0`");
    }

    /// __kernel_getrandom (P1) must start with the query-mode discriminator
    /// (`cmn x4, #1` — is opaque_len == ~0UL?) and contain the getrandom(2)
    /// syscall fallback (`mov x8, #278 ; svc #0`).
    #[test]
    fn vdso_getrandom_has_query_check_and_syscall_fallback() {
        let img = vdso_image_bytes();
        let elf = goblin::elf::Elf::parse(&img).unwrap();
        let sym = elf
            .dynsyms
            .iter()
            .find(|s| elf.dynstrtab.get_at(s.st_name) == Some("__kernel_getrandom"))
            .expect("__kernel_getrandom must exist");
        assert!(sym.is_function(), "__kernel_getrandom must be STT_FUNC");
        let off = sym.st_value as usize;
        let first = u32::from_le_bytes(img[off..off + 4].try_into().unwrap());
        assert_eq!(first, 0xb100_049f, "expected `cmn x4, #1` (query check)");
        // The body must contain `mov x8, #278` (0xd28022c8) then `svc #0`.
        let words: Vec<u32> = img[off..off + super::GETRANDOM_LEN as usize]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let i = words
            .iter()
            .position(|&w| w == 0xd280_22c8)
            .expect("expected `mov x8, #278` (getrandom syscall fallback)");
        assert_eq!(words[i + 1], 0xd400_0001, "expected `svc #0` after x8=278");
    }
}

#[cfg(test)]
mod rosetta_vdso_size_test {
    #[test]
    fn vdso_image_fits_in_one_page_and_has_dynsym() {
        let img = super::vdso_image_bytes();
        assert!(
            img.len() <= super::LINUX_VDSO_SIZE as usize,
            "vDSO image {} exceeds page {}",
            img.len(),
            super::LINUX_VDSO_SIZE
        );
        let elf = goblin::elf::Elf::parse(&img).unwrap();
        assert!(
            elf.section_headers.iter().any(|s| s.sh_type == 11),
            "vDSO must expose a SHT_DYNSYM section header for strict parsers"
        );
    }
}
