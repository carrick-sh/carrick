//! The x86_64 guest register snapshot, the `repr(C)` gateway context, and the
//! safe wrapper over the assembled `gateway_x86_64.S` trampoline.
//!
//! Execution model (block-at-a-time, mirrors the AArch64 lane):
//! Rust fills a [`X86DsrContext`] with the guest register snapshot and the
//! `entry` cache VA of one translated block, then calls
//! [`enter_translated`]. The trampoline saves the host's callee-saved
//! registers into the context, loads the guest state, pins **`%r15` as the
//! context pointer**, and jumps to `entry`. The block runs to its terminator
//! and branches to an exit stub, which saves the guest state back into the
//! snapshot and `ret`s — returning, on the SAME host frame, straight to the
//! caller of [`enter_translated`] with the exit status. Guest `%r15` is
//! virtualized (kept in the snapshot, never loaded into the live r15) because
//! r15 holds the context pointer throughout translated execution.

/// Guest register file. GPR order is the x86 encoding order
/// (rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8..r15=8..15), so
/// the gateway asm indexes it as `[r15 + SNAP_GPR + reg*8]`. `xsave` is a
/// 64-aligned standard-format XSAVE area large enough for current x86_64
/// extended state (including AVX-512 and AMX when enabled in XCR0).
pub const XSAVE_AREA_LEN: usize = 16 * 1024;
/// User components whose standard-format payload is unconstrained data plus
/// the separately validated legacy MXCSR/header fields. Components such as
/// MPX control, CET, PASID, and AMX tile configuration need component-specific
/// validators before an untrusted sigreturn image may reach hardware XRSTOR.
pub const X86_SIGNAL_SAFE_XFEATURES: u64 =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 7);

#[repr(C, align(64))]
#[derive(Clone, Debug)]
pub struct X86UcontextSnapshot {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    /// Virtual Linux PKRU. It deliberately lives outside the hardware XSAVE
    /// payload: applying guest key-0 restrictions to this user-mode gateway
    /// would revoke access to the context/host stack that a real kernel can
    /// access as supervisor memory. WRPKRU/RDPKRU are sensitive-emulated.
    virtual_pkru: u32,
    /// Non-REX x87 instruction/data pointer selectors. The gateway's
    /// FXSAVE64 image has no selector slots, so keeping these in scalar state
    /// prevents FreeBSD host selectors from leaking into the Linux guest.
    virtual_x87_fcs: u16,
    virtual_x87_fds: u16,
    xsave_align_pad: [u8; 40],
    pub xsave: [u8; XSAVE_AREA_LEN],
}

/// Register-file index constants (into [`X86UcontextSnapshot::gpr`]).
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
}

impl X86UcontextSnapshot {
    /// A snapshot with Linux's initial register/FPU state. A caller sets `rip`,
    /// `gpr[RSP]`, and argument registers before entry.
    pub fn new() -> Self {
        // XRSTOR requires a valid standard-format image. Linux starts x87/SSE
        // in non-trapping defaults; AVX and newer components remain in their
        // architectural initial state because XSTATE_BV names only x87/SSE.
        // Standard XSAVE layout keeps the legacy FCW/MXCSR fields at 0/24 and
        // XSTATE_BV at byte 512.
        let mut xsave = [0u8; XSAVE_AREA_LEN];
        xsave[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        xsave[24..28].copy_from_slice(&0x0000_1F80u32.to_le_bytes());
        xsave[512..520].copy_from_slice(&0x3u64.to_le_bytes());
        Self {
            gpr: [0; 16],
            rip: 0,
            // EFLAGS bit 1 is always set; everything else clear (IF is not
            // meaningful at CPL 3 and the guest never observes it).
            rflags: 0x0000_0000_0000_0002,
            virtual_pkru: 0,
            virtual_x87_fcs: carrick_abi::LINUX_X8664_USER_CS,
            virtual_x87_fds: carrick_abi::LINUX_X8664_USER_DS,
            xsave_align_pad: [0; 40],
            xsave,
        }
    }
}

impl Default for X86UcontextSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// Virtual Linux protection-key rights kept outside the hardware XSAVE image.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86Pkru(u32);

impl X86Pkru {
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Keep nonzero virtual rights out of host-resident neutral chains. The
    /// hardware PKRU remains zero for gateway safety; this conservative barrier
    /// also preserves the ownership contract for future guest-pkey enforcement.
    pub const fn requires_guest_residency(self) -> bool {
        self.0 != 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86SnapshotXstateComponent {
    pub offset: u32,
    pub size: u32,
}

impl X86SnapshotXstateComponent {
    fn end(self) -> Option<usize> {
        usize::try_from(self.offset)
            .ok()?
            .checked_add(usize::try_from(self.size).ok()?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86SnapshotXstateCapabilities {
    pub supported_features: u64,
    pub standard_size: u32,
    pub mxcsr_mask: u32,
    pub components: [X86SnapshotXstateComponent; 64],
}

impl X86SnapshotXstateCapabilities {
    fn standard_size_for(self, features: u64) -> Option<usize> {
        if features & !self.supported_features != 0 || features & 0x3 != 0x3 {
            return None;
        }
        let mut end = 576usize;
        for number in 2..64usize {
            if features & (1u64 << number) == 0 {
                continue;
            }
            let component = self.components[number];
            if component.size == 0 {
                return None;
            }
            end = end.max(component.end()?);
        }
        (end <= XSAVE_AREA_LEN).then_some(end)
    }
}

/// Complete geometry needed to consume either standard or compacted XSAVE
/// images. The existing snapshot capability contract remains unchanged;
/// compacted-only CPUID alignment metadata lives in this additive wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86SnapshotXstateLayout {
    capabilities: X86SnapshotXstateCapabilities,
    compacted_align64_features: u64,
}

impl X86SnapshotXstateLayout {
    /// Construct and validate the complete standard/compacted XSAVE geometry.
    /// Invalid CPUID-derived geometry is a setup failure and must never be
    /// converted into a guest architectural fault.
    pub fn new(
        capabilities: X86SnapshotXstateCapabilities,
        compacted_align64_features: u64,
    ) -> Result<Self, X86SnapshotXstateError> {
        let layout = Self {
            capabilities,
            compacted_align64_features,
        };
        layout.validate()?;
        Ok(layout)
    }

    #[cfg(test)]
    pub(crate) const fn new_unchecked(
        capabilities: X86SnapshotXstateCapabilities,
        compacted_align64_features: u64,
    ) -> Self {
        Self {
            capabilities,
            compacted_align64_features,
        }
    }

    pub const fn capabilities(self) -> X86SnapshotXstateCapabilities {
        self.capabilities
    }

    pub const fn compacted_align64_features(self) -> u64 {
        self.compacted_align64_features
    }

    /// Return the compacted XSAVE extent for one enabled subset of the
    /// virtual feature set. Compacted images begin immediately after the
    /// 576-byte legacy/header prefix; CPUID leaf D component ECX bit 1 inserts
    /// the required 64-byte alignment before the named component.
    pub fn compacted_size_for(&self, features: u64) -> Result<u32, X86SnapshotXstateError> {
        self.validate()?;
        self.compacted_size_for_validated(features)
    }

    fn compacted_size_for_validated(&self, features: u64) -> Result<u32, X86SnapshotXstateError> {
        const EXTENDED_OFFSET: usize = 576;

        let invalid = |reason| X86SnapshotXstateError::InvalidLayout(reason);
        if features & !self.capabilities.supported_features != 0 {
            return Err(invalid("compacted extent names an unsupported feature"));
        }
        let mut cursor = EXTENDED_OFFSET;
        for component in 2..64usize {
            let bit = 1u64 << component;
            if features & bit == 0 {
                continue;
            }
            let size = usize::try_from(self.capabilities.components[component].size)
                .map_err(|_| invalid("compacted component size is not representable"))?;
            if size == 0 {
                return Err(invalid("compacted component has zero size"));
            }
            if self.compacted_align64_features & bit != 0 {
                cursor = cursor
                    .checked_add(63)
                    .map(|value| value & !63)
                    .ok_or_else(|| invalid("compacted component alignment overflows"))?;
            }
            cursor = cursor
                .checked_add(size)
                .ok_or_else(|| invalid("compacted component range overflows"))?;
            if cursor > XSAVE_AREA_LEN {
                return Err(invalid("compacted component range exceeds the snapshot"));
            }
        }
        u32::try_from(cursor).map_err(|_| invalid("compacted extent is not representable"))
    }

    pub(crate) fn validate(&self) -> Result<(), X86SnapshotXstateError> {
        const LEGACY_FEATURES: u64 = (1 << 0) | (1 << 1);
        const AVX_FEATURE: u64 = 1 << 2;
        const AVX512_FEATURES: u64 = (1 << 5) | (1 << 6) | (1 << 7);
        const EXTENDED_OFFSET: usize = 576;

        let capabilities = self.capabilities;
        let supported = capabilities.supported_features;
        let invalid = |reason| X86SnapshotXstateError::InvalidLayout(reason);
        let standard_size = usize::try_from(capabilities.standard_size)
            .map_err(|_| invalid("standard extent is not representable"))?;
        if supported & LEGACY_FEATURES != LEGACY_FEATURES {
            return Err(invalid("virtual XCR0 omits x87 or SSE"));
        }
        if supported & !X86_SIGNAL_SAFE_XFEATURES != 0 {
            return Err(invalid("virtual XCR0 contains an unsafe feature"));
        }
        let avx512 = supported & AVX512_FEATURES;
        if avx512 != 0 && (avx512 != AVX512_FEATURES || supported & AVX_FEATURE == 0) {
            return Err(invalid(
                "virtual XCR0 must expose AVX-512 components 5/6/7 together and with AVX",
            ));
        }
        if !(EXTENDED_OFFSET..=XSAVE_AREA_LEN).contains(&standard_size) {
            return Err(invalid("standard extent is outside the snapshot"));
        }
        if self.compacted_align64_features & !supported != 0
            || self.compacted_align64_features & LEGACY_FEATURES != 0
        {
            return Err(invalid("compacted alignment names an invalid feature"));
        }

        let mut ranges = [(0usize, 0usize); 64];
        let mut advertised_end = EXTENDED_OFFSET;
        for component in 2..64usize {
            let bit = 1u64 << component;
            if supported & bit == 0 {
                continue;
            }
            let metadata = capabilities.components[component];
            let start = usize::try_from(metadata.offset)
                .map_err(|_| invalid("component offset is not representable"))?;
            let size = usize::try_from(metadata.size)
                .map_err(|_| invalid("component size is not representable"))?;
            let end = start
                .checked_add(size)
                .ok_or_else(|| invalid("component range overflows"))?;
            if size == 0 || start < EXTENDED_OFFSET || end > standard_size || end > XSAVE_AREA_LEN {
                return Err(invalid("component range is outside the standard image"));
            }
            for prior in ranges.iter().take(component).skip(2) {
                if prior.0 != prior.1 && start < prior.1 && prior.0 < end {
                    return Err(invalid("standard component ranges overlap"));
                }
            }
            ranges[component] = (start, end);
            advertised_end = advertised_end.max(end);
        }
        if standard_size != advertised_end {
            return Err(invalid(
                "standard extent does not equal the maximum advertised component end",
            ));
        }
        self.compacted_size_for_validated(supported)?;
        Ok(())
    }
}

impl std::ops::Deref for X86SnapshotXstateLayout {
    type Target = X86SnapshotXstateCapabilities;

    fn deref(&self) -> &Self::Target {
        &self.capabilities
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum X86SnapshotXstateError {
    #[error("x86 XSAVE is unavailable: {0}")]
    Unavailable(&'static str),
    #[error("x86 XSAVE component {component} has invalid range {offset}+{size}")]
    InvalidComponent {
        component: u32,
        offset: u32,
        size: u32,
    },
    #[error("x86 standard XSAVE extent {0} exceeds Carrick's bound")]
    ExtentTooLarge(usize),
    #[error("invalid x86 XSAVE layout: {0}")]
    InvalidLayout(&'static str),
    #[error("malformed standard x86 XSAVE signal image: {0}")]
    Malformed(&'static str),
}

#[cfg(target_arch = "x86_64")]
fn detect_signal_xstate_layout() -> Result<X86SnapshotXstateLayout, X86SnapshotXstateError> {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};

    if __cpuid(0).eax < 0x0d {
        return Err(X86SnapshotXstateError::Unavailable("CPUID leaf 0xD"));
    }
    let leaf1 = __cpuid(1);
    if leaf1.ecx & (1 << 27) == 0 {
        return Err(X86SnapshotXstateError::Unavailable("OSXSAVE"));
    }
    let leaf0 = __cpuid_count(0x0d, 0);
    let cpuid_features = u64::from(leaf0.eax) | (u64::from(leaf0.edx) << 32);
    // SAFETY: OSXSAVE is set above, so XGETBV(0) is available in userspace.
    let xcr0 = unsafe { _xgetbv(0) };
    let enabled_guest_features = (cpuid_features & xcr0) & !(1u64 << 9);
    let supported_features = enabled_guest_features & X86_SIGNAL_SAFE_XFEATURES;
    if supported_features & 0x3 != 0x3 {
        return Err(X86SnapshotXstateError::Unavailable("x87/SSE XCR0 state"));
    }

    let mut components = [X86SnapshotXstateComponent::default(); 64];
    let mut compacted_align64_features = 0u64;
    let mut standard_size = 576usize;
    for component in 2..64u32 {
        if supported_features & (1u64 << component) == 0 {
            continue;
        }
        let leaf = __cpuid_count(0x0d, component);
        let range = X86SnapshotXstateComponent {
            offset: leaf.ebx,
            size: leaf.eax,
        };
        if leaf.ecx & (1 << 1) != 0 {
            compacted_align64_features |= 1u64 << component;
        }
        let Some(end) = range
            .end()
            .filter(|end| range.size != 0 && *end <= XSAVE_AREA_LEN)
        else {
            return Err(X86SnapshotXstateError::InvalidComponent {
                component,
                offset: range.offset,
                size: range.size,
            });
        };
        components[component as usize] = range;
        standard_size = standard_size.max(end);
    }
    if standard_size > XSAVE_AREA_LEN {
        return Err(X86SnapshotXstateError::ExtentTooLarge(standard_size));
    }

    #[repr(align(16))]
    struct AlignedFxsave([u8; 512]);
    let mut fxsave = AlignedFxsave([0; 512]);
    // SAFETY: `fxsave` is writable and 16-byte aligned; FXSAVE is
    // non-destructive and records only this thread's current host FP state.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{}]",
            in(reg) fxsave.0.as_mut_ptr(),
            options(nostack, preserves_flags)
        );
    }
    let mut mask_bytes = [0u8; 4];
    mask_bytes.copy_from_slice(&fxsave.0[28..32]);
    // Newer CPUs may define MXCSR controls above bit 15. FXSAVE's complete
    // MXCSR_MASK is the architectural authority; truncating it rejects legal
    // guest state (this host exposes bit 17).
    let discovered_mask = u32::from_le_bytes(mask_bytes);
    // Intel documents 0xFFBF as the software fallback when an old CPU reports
    // a zero MXCSR_MASK in FXSAVE.
    let mxcsr_mask = if discovered_mask == 0 {
        0x0000_ffbf
    } else {
        discovered_mask
    };

    X86SnapshotXstateLayout::new(
        X86SnapshotXstateCapabilities {
            supported_features,
            standard_size: u32::try_from(standard_size)
                .map_err(|_| X86SnapshotXstateError::ExtentTooLarge(standard_size))?,
            mxcsr_mask,
            components,
        },
        compacted_align64_features,
    )
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_signal_xstate_layout() -> Result<X86SnapshotXstateLayout, X86SnapshotXstateError> {
    Err(X86SnapshotXstateError::Unavailable("non-x86 host"))
}

pub fn signal_xstate_layout() -> Result<X86SnapshotXstateLayout, X86SnapshotXstateError> {
    static LAYOUT: std::sync::OnceLock<Result<X86SnapshotXstateLayout, X86SnapshotXstateError>> =
        std::sync::OnceLock::new();
    LAYOUT.get_or_init(detect_signal_xstate_layout).clone()
}

pub fn signal_xstate_capabilities() -> Result<X86SnapshotXstateCapabilities, X86SnapshotXstateError>
{
    signal_xstate_layout().map(X86SnapshotXstateLayout::capabilities)
}

/// Bounded architectural fingerprint of one standard-format XSAVE image.
///
/// This is diagnostics vocabulary, not a replacement for the image itself. It
/// lets targeted native-x86 edge traces identify the first transition where
/// guest state diverges without copying or printing the 16 KiB image on every
/// block. Hashes are deterministic FNV-1a over architectural payload bytes;
/// reserved XSAVE padding is deliberately excluded from component hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86XstateSummary {
    pub xstate_bv: u64,
    pub fcw: u16,
    pub mxcsr: u32,
    pub pkru: u32,
    pub legacy_hash: u64,
    pub ymm_hash: u64,
    pub opmask_zmm_hash: u64,
    pub extended_hash: u64,
}

const FNV1A_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fingerprint_bytes(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV1A_OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV1A_PRIME)
    })
}

#[cfg(target_arch = "x86_64")]
fn xsave_component_bounds(component: u32) -> Option<(usize, usize)> {
    const COMPONENT_SLOTS: usize = 64;
    static BOUNDS: [std::sync::OnceLock<Option<(usize, usize)>>; COMPONENT_SLOTS] =
        [const { std::sync::OnceLock::new() }; COMPONENT_SLOTS];

    let compute = || {
        if std::arch::x86_64::__cpuid(0).eax < 0x0d {
            return None;
        }
        let leaf = std::arch::x86_64::__cpuid_count(0x0d, component);
        let start = leaf.ebx as usize;
        let len = leaf.eax as usize;
        (len != 0 && start.checked_add(len)? <= XSAVE_AREA_LEN).then_some((start, len))
    };
    let Some(index) = usize::try_from(component)
        .ok()
        .filter(|&index| index < COMPONENT_SLOTS)
    else {
        return compute();
    };
    *BOUNDS[index].get_or_init(compute)
}

#[cfg(not(target_arch = "x86_64"))]
fn xsave_component_bounds(_component: u32) -> Option<(usize, usize)> {
    None
}

fn fingerprint_components(xsave: &[u8; XSAVE_AREA_LEN], components: &[u32]) -> u64 {
    let mut hash = FNV1A_OFFSET;
    let mut found = false;
    for &component in components {
        let Some((start, len)) = xsave_component_bounds(component) else {
            continue;
        };
        found = true;
        for byte in &xsave[start..start + len] {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV1A_PRIME);
        }
    }
    if found { hash } else { 0 }
}

impl X86UcontextSnapshot {
    /// Enabled components materialized in this standard-format XSAVE image.
    ///
    /// Hardware XSAVEOPT may report x87 as initial when all physical fields are
    /// initial even though Carrick's separately virtualized FCS/FDS are not.
    /// In that case x87 is still architecturally noninitial and must remain
    /// present for later XSAVE, XRSTOR masking, clone, and signal operations.
    pub fn xstate_bv(&self) -> u64 {
        let hardware_bv = u64::from_le_bytes([
            self.xsave[512],
            self.xsave[513],
            self.xsave[514],
            self.xsave[515],
            self.xsave[516],
            self.xsave[517],
            self.xsave[518],
            self.xsave[519],
        ]);
        if self.virtual_x87_fcs != carrick_abi::LINUX_X8664_USER_CS
            || self.virtual_x87_fds != carrick_abi::LINUX_X8664_USER_DS
        {
            hardware_bv | 1
        } else {
            hardware_bv
        }
    }

    /// Virtual Linux PKRU value. The hardware XSAVE payload intentionally
    /// retains a host-safe zero PKRU while translated guest code runs.
    pub const fn pkru(&self) -> X86Pkru {
        X86Pkru(self.virtual_pkru)
    }

    /// Architectural x87 instruction pointer in the authoritative snapshot.
    /// A native gateway must normalize a copied instruction's JIT coordinate
    /// before exposing this state to any guest service or signal frame.
    pub fn x87_instruction_pointer(&self) -> u64 {
        u64::from_le_bytes(self.xsave[8..16].try_into().unwrap_or([0; 8]))
    }

    /// Architectural x87 data pointer in the authoritative snapshot. Identity
    /// native execution already records guest virtual addresses here.
    pub fn x87_data_pointer(&self) -> u64 {
        u64::from_le_bytes(self.xsave[16..24].try_into().unwrap_or([0; 8]))
    }

    /// Replace a copied identity-native x87 instruction's host/JIT pointer
    /// and, for a memory form, its exact guest linear data address. A missing
    /// data witness denotes a register-only instruction and deliberately
    /// preserves the entry FDP. Executing a guest x87 instruction also
    /// replaces the virtual selector pair with Carrick's Linux user selectors
    /// rather than leaking the FreeBSD selectors omitted by FXSAVE64.
    pub fn normalize_identity_native_x87_execution(
        &mut self,
        guest_fip: u64,
        guest_fdp: Option<u64>,
    ) {
        self.xsave[8..16].copy_from_slice(&guest_fip.to_le_bytes());
        if let Some(guest_fdp) = guest_fdp {
            self.xsave[16..24].copy_from_slice(&guest_fdp.to_le_bytes());
        }
        self.virtual_x87_fcs = carrick_abi::LINUX_X8664_USER_CS;
        self.virtual_x87_fds = carrick_abi::LINUX_X8664_USER_DS;
        // A completed x87 stack instruction materializes the component even
        // if a host XSAVEOPT image omitted its initial-looking legacy bytes.
        let state_bv = u64::from_le_bytes(self.xsave[512..520].try_into().unwrap_or([0; 8])) | 1;
        self.xsave[512..520].copy_from_slice(&state_bv.to_le_bytes());
    }

    /// Virtual selector paired with the non-REX x87 instruction pointer.
    pub const fn x87_fcs(&self) -> u16 {
        self.virtual_x87_fcs
    }

    /// Virtual selector paired with the non-REX x87 data pointer.
    pub const fn x87_fds(&self) -> u16 {
        self.virtual_x87_fds
    }

    /// Commit the selector fields imported by a non-REX XRSTOR form.
    pub(crate) fn restore_x87_selectors(&mut self, fcs: u16, fds: u16) {
        self.virtual_x87_fcs = fcs;
        self.virtual_x87_fds = fds;
    }

    /// Apply the architectural value written by a sensitive-emulated WRPKRU.
    /// This does not alter the hardware XSAVE payload; Carrick currently
    /// virtualizes PKRU reads/writes but does not enforce pkeys on guest memory.
    pub fn apply_guest_pkru_write(&mut self, value: u32) {
        self.virtual_pkru = value;
    }

    /// Export the complete authoritative guest state in standard XSAVE layout.
    /// Component 9 is omitted even when host XCR0 enables it; virtual PKRU rides
    /// in the separate scalar returned with the image.
    pub fn export_signal_xstate(
        &self,
    ) -> Result<(Vec<u8>, u64, u32, u16, u16), X86SnapshotXstateError> {
        let capabilities = signal_xstate_capabilities()?;
        if self.xstate_bv() & !capabilities.supported_features != 0 {
            return Err(X86SnapshotXstateError::Unavailable(
                "guest used an XSAVE component without a safe signal-frame validator",
            ));
        }
        let size = usize::try_from(capabilities.standard_size)
            .map_err(|_| X86SnapshotXstateError::ExtentTooLarge(usize::MAX))?;
        if size > XSAVE_AREA_LEN {
            return Err(X86SnapshotXstateError::ExtentTooLarge(size));
        }
        let mut bytes = vec![0u8; size];
        bytes[..512].copy_from_slice(&self.xsave[..512]);
        let xstate_bv = self.xstate_bv() & capabilities.supported_features;
        bytes[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        // Standard signal frames never use compacted format; the remainder of
        // the 64-byte header stays zero from allocation.
        for component in 2..64usize {
            if capabilities.supported_features & (1u64 << component) == 0 {
                continue;
            }
            let range = capabilities.components[component];
            let Some(end) = range.end() else {
                return Err(X86SnapshotXstateError::InvalidComponent {
                    component: component as u32,
                    offset: range.offset,
                    size: range.size,
                });
            };
            let start = range.offset as usize;
            bytes[start..end].copy_from_slice(&self.xsave[start..end]);
        }
        bytes[28..32].copy_from_slice(&capabilities.mxcsr_mask.to_le_bytes());
        Ok((
            bytes,
            capabilities.supported_features,
            self.virtual_pkru,
            self.virtual_x87_fcs,
            self.virtual_x87_fds,
        ))
    }

    /// Validate an untrusted standard signal image completely, materialize it
    /// in temporary state, and only then commit both hardware-safe XSAVE bytes
    /// and the virtual PKRU scalar. No guest image ever reaches raw XRSTOR.
    pub fn restore_signal_xstate(
        &mut self,
        bytes: &[u8],
        xfeatures: u64,
        virtual_pkru: u32,
        virtual_x87_fcs: u16,
        virtual_x87_fds: u16,
    ) -> Result<(), X86SnapshotXstateError> {
        let capabilities = signal_xstate_capabilities()?;
        let Some(expected_size) = capabilities.standard_size_for(xfeatures) else {
            return Err(X86SnapshotXstateError::Malformed("unsupported feature set"));
        };
        if bytes.len() != expected_size || bytes.len() < 576 || bytes.len() > XSAVE_AREA_LEN {
            return Err(X86SnapshotXstateError::Malformed("invalid image size"));
        }
        let mut xstate_bytes = [0u8; 8];
        xstate_bytes.copy_from_slice(&bytes[512..520]);
        let xstate_bv = u64::from_le_bytes(xstate_bytes);
        if xstate_bv & !xfeatures != 0 || xstate_bv & (1u64 << 9) != 0 {
            return Err(X86SnapshotXstateError::Malformed(
                "xstate_bv exceeds advertised features",
            ));
        }
        let mut xcomp_bytes = [0u8; 8];
        xcomp_bytes.copy_from_slice(&bytes[520..528]);
        if u64::from_le_bytes(xcomp_bytes) != 0 {
            return Err(X86SnapshotXstateError::Malformed(
                "compacted xstate is forbidden",
            ));
        }
        if bytes[528..576].iter().any(|byte| *byte != 0) {
            return Err(X86SnapshotXstateError::Malformed(
                "reserved XSAVE header bytes are nonzero",
            ));
        }
        let mut mxcsr_bytes = [0u8; 4];
        mxcsr_bytes.copy_from_slice(&bytes[24..28]);
        if u32::from_le_bytes(mxcsr_bytes) & !capabilities.mxcsr_mask != 0 {
            return Err(X86SnapshotXstateError::Malformed(
                "MXCSR has unsupported bits",
            ));
        }

        let mut temporary = [0u8; XSAVE_AREA_LEN];
        // Only bytes 0..464 are architectural in the legacy area. Linux's
        // software magic lives in 464..512 and must not pollute the persistent
        // hardware image, because XSAVE is permitted to leave reserved bytes.
        temporary[..464].copy_from_slice(&bytes[..464]);
        temporary[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        for component in 2..64usize {
            if xfeatures & (1u64 << component) == 0 {
                continue;
            }
            let range = capabilities.components[component];
            let Some(end) = range.end().filter(|end| *end <= bytes.len()) else {
                return Err(X86SnapshotXstateError::Malformed("component exceeds image"));
            };
            let start = range.offset as usize;
            temporary[start..end].copy_from_slice(&bytes[start..end]);
        }

        self.xsave = temporary;
        self.virtual_pkru = virtual_pkru;
        self.virtual_x87_fcs = virtual_x87_fcs;
        self.virtual_x87_fds = virtual_x87_fds;
        Ok(())
    }

    /// Summarize the architectural xstate fields used by targeted edge traces.
    pub fn xstate_summary(&self) -> X86XstateSummary {
        let pkru = self.pkru();
        X86XstateSummary {
            xstate_bv: self.xstate_bv(),
            fcw: u16::from_le_bytes([self.xsave[0], self.xsave[1]]),
            mxcsr: u32::from_le_bytes([
                self.xsave[24],
                self.xsave[25],
                self.xsave[26],
                self.xsave[27],
            ]),
            pkru: pkru.raw(),
            legacy_hash: fingerprint_bytes(&self.xsave[..512]),
            ymm_hash: fingerprint_components(&self.xsave, &[2]),
            opmask_zmm_hash: fingerprint_components(&self.xsave, &[5, 6, 7]),
            extended_hash: fingerprint_bytes(&self.xsave[576..]),
        }
    }
}

/// The exit status the gateway returns (also the discriminant the caller
/// switches on). Distinct stubs write distinct values; `Signal` is written by
/// the fault shim (M2-runtime).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum X86ExitStatus {
    /// A `syscall`/`int 0x80` terminator: `snapshot.rip` is the resume VA.
    Syscall = 1,
    /// A control-flow/indirect terminator: `snapshot.rip` is the next VA.
    Indirect = 3,
    /// A sensitive (rdtsc/cpuid/fsgsbase/…) terminator.
    Sensitive = 6,
    /// A host signal (guest fault) captured by the trap shim.
    Signal = 4,
    /// An asynchronous host kick requesting a return to the run loop.
    Kicked = 7,
}

impl X86ExitStatus {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Syscall),
            3 => Some(Self::Indirect),
            6 => Some(Self::Sensitive),
            4 => Some(Self::Signal),
            7 => Some(Self::Kicked),
            _ => None,
        }
    }
}

/// Raw x86_64 syscall ordinals eligible for the immutable identity fast path.
/// These are native x86 UAPI numbers read from live `%rax`, not Carrick's
/// canonical asm-generic syscall numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum X86IdentitySyscall {
    GetPid = 39,
    GetTid = 186,
}

impl X86IdentitySyscall {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn from_static_x86_ordinal(raw: u32) -> Option<Self> {
        match raw {
            39 => Some(Self::GetPid),
            186 => Some(Self::GetTid),
            _ => None,
        }
    }
}

/// Per-thread identity values consumed directly by emitted code. This is a
/// JIT/assembly wire structure; construction remains typed on the Rust side.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86IdentityStamp {
    /// Host VA of an aligned `AtomicU32`: 1 enables, 0 forces dispatch.
    pub live_gate: u64,
    pub pid: u64,
    pub tid: u64,
}

impl X86IdentityStamp {
    pub const fn live(live_gate: u64, pid: u32, tid: u32) -> Self {
        Self {
            live_gate,
            pid: pid as u64,
            tid: tid as u64,
        }
    }
}

/// One monomorphic indirect-control-flow cache entry consumed by the gateway
/// while guest xstate is already resident. A zero `expected_target` is cold.
/// The runtime publishes `target_exec`/`rsp_adjust` first and the matching
/// guest target last, and disarms by clearing `expected_target` first.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86IndirectCacheEntry {
    pub expected_target: u64,
    pub target_exec: u64,
    pub rsp_adjust: u64,
    pub reserved: u64,
}

impl X86IndirectCacheEntry {
    pub const fn return_site(rsp_adjust: u64) -> Self {
        Self {
            expected_target: 0,
            target_exec: 0,
            rsp_adjust,
            reserved: 0,
        }
    }

    pub fn arm(&mut self, expected_target: u64, target_exec: u64) {
        self.expected_target = 0;
        self.target_exec = target_exec;
        self.expected_target = expected_target;
    }
}

/// The gateway context has a fixed, 64-byte-aligned field order; the
/// `gateway_x86_64.S` `.equ` offsets mirror the `offset_of!` asserts below.
///
/// This 33 KiB value is deliberately neither [`Copy`] nor [`Clone`]. Construct
/// one per host guest thread, keep its embedded [`X86UcontextSnapshot`] as the
/// authoritative register state, and reuse it across gateway entries. Moving or
/// reconstructing it in the block loop copies two 16 KiB XSAVE areas and turns
/// the gateway into a `memcpy` workload.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct X86DsrContext {
    pub snapshot: X86UcontextSnapshot,
    /// Complete host extended state saved before installing guest state. This
    /// includes process-affecting components such as PKRU, not just registers
    /// covered by the SysV calling convention. XSAVE initializes every byte
    /// XRSTOR may consume; `MaybeUninit` avoids pointlessly clearing 16 KiB on
    /// every short gateway round trip.
    pub host_xsave: [std::mem::MaybeUninit<u8>; XSAVE_AREA_LEN],
    /// Host `rsp` at trampoline entry (points at the return address into the
    /// Rust caller). The exit stub restores this and `ret`s through it.
    pub host_rsp: u64,
    /// Host callee-saved registers saved at entry: rbx, rbp, r12, r13, r14,
    /// r15 (SysV requires the callee preserve these across the call).
    pub host_callee: [u64; 6],
    /// Cache VA of the translated block to jump to on entry.
    pub entry: u64,
    /// Resume/next guest VA, pre-filled per block; the exit stub copies it to
    /// `snapshot.rip`.
    pub exit_resume: u64,
    pub exit_status: i32,
    pub exit_pad: u32,
    /// Absolute addresses of the exit stubs, filled by [`enter_translated`]
    /// from the assembled symbols. Emitted code branches to a terminator via
    /// `jmp *disp(%r15)` (see [`CTX_EXIT_SYSCALL_ADDR`] etc.): the JIT region
    /// and the gateway `.text` can be more than 2 GiB apart, so a `rel32`
    /// branch cannot reach — an indirect jump through the context does, and
    /// clobbers no guest register (r15 is the context pointer).
    pub exit_syscall_addr: u64,
    pub exit_indirect_addr: u64,
    pub exit_sensitive_addr: u64,
    /// Spill slot for the emitter's RIP-relative rewrite: emitted code saves
    /// one guest GPR here (`mov [r15+CTX_SCRATCH], reg`), materializes the
    /// absolute guest VA in it, runs the re-encoded instruction, and restores
    /// the GPR — all `mov`s, so guest rflags survive. Never read by Rust or
    /// the gateway asm; live only within one rewritten instruction sequence.
    pub scratch: u64,
    /// Second spill slot, used when one rewritten instruction needs two
    /// scratch GPRs (a RIP-relative operand AND a virtualized-r15 rename in
    /// the same instruction). Same lifetime rules as `scratch`.
    pub scratch2: u64,
    /// The guest's `%fs` segment base (its Linux thread pointer, set via
    /// `arch_prctl(ARCH_SET_FS)` / `wrfsbase` servicing). The gateway installs
    /// it on every full entry — including zero, which is valid guest state —
    /// so plain `fs:`-prefixed guest TLS accesses cannot observe host TLS.
    /// [`host_fsbase`](Self::host_fsbase) is restored on every full exit.
    pub guest_fsbase: u64,
    /// Where the gateway parks the host's `%fs` base across a translated run
    /// (written by the enter trampoline via `rdfsbase`, read back by every full
    /// exit stub). Return-cache guest-resident resumes do not swap either base.
    pub host_fsbase: u64,
    /// Where the host-OS seam's signal shim records a guest fault before
    /// redirecting to the signal exit stub (see `carrick_dsr::fault`). Only
    /// meaningful when the gateway returns [`X86ExitStatus::Signal`]; note
    /// `snapshot.rip` holds the per-block `exit_resume` then, NOT the fault
    /// point — [`FaultRecord::host_rip`](carrick_dsr::fault::FaultRecord)
    /// is authoritative.
    pub fault: carrick_dsr::fault::FaultRecord,
    /// Whether the enter/exit trampoline should save/restore the guest and
    /// host XSAVE areas around this block. Set per block from
    /// [`X86Block::uses_fpu`](crate::block::X86Block); integer-only blocks skip
    /// the extended-state work. Nonzero = save/restore.
    pub save_fpu: u32,
    /// Nonzero when the host supports XSAVEOPT for sparse, incremental guest
    /// state saves; zero selects baseline XSAVE.
    pub use_xsaveopt: u32,
    /// A CHAIN-MISS flag, set nonzero by a chainable branch's COLD stub (see
    /// `emit::emit_block_linked`). When nonzero after an `Indirect` exit the
    /// run loop is at a chain miss — `snapshot.rip` holds the already-resolved
    /// successor guest VA, so the loop just continues there (and its
    /// `pending`-edge registry patches the missed slot when that VA is
    /// translated). Zero on a genuine indirect branch (`jmp/call r/m`), which
    /// the loop resolves from the snapshot instead. The driver clears it before
    /// every enter. The stub records the patch-site ADDRESS here (not just a
    /// bare 1) so the value is also usable for diagnostics or a future
    /// direct-patch path; the run loop currently consults only its
    /// nonzero-ness.
    pub chain_patch_site: u64,
    /// Namespace identity stamped at each chainable Rust→JIT entry, plus a
    /// live gate that closes when seccomp must observe these syscalls.
    pub identity: X86IdentityStamp,
    /// Diagnostic-only gateway controls. Bit 0 clobbers physical host xmm0
    /// immediately before an entry that skips xstate transfer, making unsafe
    /// local-only ownership deterministic. Production entries keep this zero.
    pub diagnostic_flags: u32,
    /// Whether [`host_xsave`](Self::host_xsave) has received its mandatory
    /// baseline full XSAVE. Once initialized, supported hosts may use
    /// full-mask XSAVEOPT into the same persistent image. Unlike transient
    /// entry fields this survives [`Self::prepare_entry`].
    pub host_xsave_initialized: u32,
    /// Stable address and length of this thread's gateway-consumed monomorphic
    /// indirect cache. The runtime may reallocate the backing vector only at a
    /// gateway boundary, then republishes these fields before re-entry.
    pub indirect_cache_table: u64,
    pub indirect_cache_len: u32,
    /// One-based cache-site id written by emitted return code. Zero means a
    /// genuine uncached indirect exit.
    pub indirect_cache_site: u32,
    /// Live guest target captured by an emitted return probe.
    pub indirect_actual_target: u64,
    /// Nonzero only while emitted code has guest RCX spilled in `scratch2`.
    /// The FreeBSD asynchronous-kick shim restores RCX from the spill before
    /// redirecting to the gateway.
    pub kick_restore_rcx: u32,
    /// Absolute address of the kicked exit stub. Kept separate from the
    /// signal-installed kick address so emitted edge guards can leave through
    /// the gateway without borrowing a guest register or requiring `rel32`
    /// reachability.
    pub exit_kicked_addr: u64,
    /// Stable address of this run's shared [`std::sync::atomic::AtomicU32`]
    /// executable stop word. Zero disables polling. Hot edge guards and the
    /// return-cache candidate path use ordinary x86 loads, which have acquire
    /// semantics, and never modify guest RFLAGS.
    pub executable_stop_word: u64,
    /// Exact guest VA of the most recently completed copied x87 stack
    /// instruction in this gateway entry. Some hosts omit x87 FIP from an
    /// XSAVEOPT image even after executing the instruction; this sideband
    /// witness lets the FreeBSD native runtime normalize that host/JIT detail
    /// without guessing from a block boundary.
    pub last_copied_x87_guest_va: u64,
    /// Exact linear guest data address of that copied x87 memory instruction.
    /// Zero is architectural, so [`last_copied_x87_data_valid`](Self::last_copied_x87_data_valid)
    /// distinguishes it from an absent witness (a register-only x87 form).
    pub last_copied_x87_guest_data_va: u64,
    /// Nonzero only after the emitter has completely published
    /// `last_copied_x87_guest_data_va`. Written last so an asynchronous exit
    /// never consumes an incomplete address.
    pub last_copied_x87_data_valid: u32,
}

/// Byte offset of [`X86DsrContext::exit_resume`] — the guest VA the exit stub
/// copies to `snapshot.rip`. Emitted exits SELF-SET this (so a chained-into
/// block does not depend on the driver pre-setting it).
pub const CTX_EXIT_RESUME: i32 = 33_024;
/// Byte offset of [`X86DsrContext::exit_syscall_addr`] for `jmp *disp(%r15)`.
pub const CTX_EXIT_SYSCALL_ADDR: i32 = 33_040;
/// Byte offset of [`X86DsrContext::exit_indirect_addr`].
pub const CTX_EXIT_INDIRECT_ADDR: i32 = 33_048;
/// Byte offset of [`X86DsrContext::exit_sensitive_addr`].
pub const CTX_EXIT_SENSITIVE_ADDR: i32 = 33_056;
/// Byte offset of [`X86DsrContext::scratch`] for the emitter's RIP-relative
/// rewrite spill (`mov [r15+CTX_SCRATCH], reg` / restore).
pub const CTX_SCRATCH: i32 = 33_064;
/// Byte offset of [`X86DsrContext::scratch2`] (second rewrite spill).
pub const CTX_SCRATCH2: i32 = 33_072;
/// Byte offset of [`X86DsrContext::guest_fsbase`] (mirrored in the `.S`).
pub const CTX_GUEST_FSBASE: i32 = 33_080;
/// Byte offset of [`X86DsrContext::host_fsbase`] (mirrored in the `.S`).
pub const CTX_HOST_FSBASE: i32 = 33_088;
/// Byte offset of [`X86DsrContext::save_fpu`] (mirrored in the `.S`): the
/// per-block flag gating the FPU save/restore.
pub const CTX_SAVE_FPU: i32 = 33_120;
/// Byte offset of [`X86DsrContext::chain_patch_site`] — a chainable branch's
/// cold stub writes the patch-site address here.
pub const CTX_CHAIN_PATCH: i32 = 33_128;
/// Byte offsets of the x86 identity fast-path wire fields.
pub const CTX_IDENTITY_LIVE_GATE: i32 = 33_136;
pub const CTX_IDENTITY_PID: i32 = 33_144;
pub const CTX_IDENTITY_TID: i32 = 33_152;
/// Byte offset of [`X86DsrContext::diagnostic_flags`] (mirrored in assembly).
pub const CTX_DIAGNOSTIC_FLAGS: i32 = 33_160;
/// Byte offset of [`X86DsrContext::host_xsave_initialized`] (mirrored in assembly).
pub const CTX_HOST_XSAVE_INITIALIZED: i32 = 33_164;
/// Byte offsets of the monomorphic indirect-cache gateway contract.
pub const CTX_INDIRECT_CACHE_TABLE: i32 = 33_168;
pub const CTX_INDIRECT_CACHE_LEN: i32 = 33_176;
pub const CTX_INDIRECT_CACHE_SITE: i32 = 33_180;
pub const CTX_INDIRECT_ACTUAL_TARGET: i32 = 33_184;
pub const CTX_KICK_RESTORE_RCX: i32 = 33_192;
/// Byte offsets of the per-run executable stop contract. These fields append
/// into the context's pre-existing tail padding, so no hot offset moves.
pub const CTX_EXIT_KICKED_ADDR: i32 = 33_200;
pub const CTX_EXECUTABLE_STOP_WORD: i32 = 33_208;
/// Byte offset of the last successfully copied x87 stack instruction's guest VA.
pub const CTX_LAST_COPIED_X87_GUEST_VA: i32 = 33_216;
/// Byte offset of its exact guest linear data address.
pub const CTX_LAST_COPIED_X87_GUEST_DATA_VA: i32 = 33_224;
/// Byte offset of its validity witness; zero guest addresses are valid.
pub const CTX_LAST_COPIED_X87_DATA_VALID: i32 = 33_232;
/// Byte offset of the virtualized guest `%r15` slot inside the snapshot
/// (`gpr[15]`): the emitter's r15-rename loads/stores it directly.
pub const SNAP_GUEST_R15: i32 = 120;
/// Byte offset of [`X86DsrContext::fault`] — handed to the host-OS seam's
/// signal shim, which writes the record through `r15 + CTX_FAULT_RECORD`.
pub const CTX_FAULT_RECORD: u32 = 33_096;
/// Byte offset of [`X86DsrContext::entry`] (unused by emitted code — the
/// trampoline reads it — but asserted for parity with the `.S`).
pub const CTX_ENTRY: i32 = 33_016;

/// Versioned context-layout contract consumed by the safe live native-x86
/// profiler. Keeping this beside [`X86DsrContext`] prevents diagnostic scripts
/// from baking in an offset that silently changes when the gateway grows (the
/// XSAVE conversion moved `exit_resume` from 720 to 33,024 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86DsrProfilerLayout {
    pub version: u32,
    pub context_register: &'static str,
    pub context_size: u32,
    pub exit_resume_offset: u32,
}

pub const fn x86_dsr_profiler_layout() -> X86DsrProfilerLayout {
    X86DsrProfilerLayout {
        version: 1,
        context_register: "R_R15",
        context_size: std::mem::size_of::<X86DsrContext>() as u32,
        exit_resume_offset: std::mem::offset_of!(X86DsrContext, exit_resume) as u32,
    }
}

#[cfg(target_arch = "x86_64")]
fn host_supports_xsaveopt() -> u32 {
    static SUPPORTED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| std::arch::x86_64::__cpuid_count(0x0d, 1).eax & 1)
}

#[cfg(not(target_arch = "x86_64"))]
fn host_supports_xsaveopt() -> u32 {
    0
}

impl X86DsrContext {
    /// Construct persistent state for one host guest thread.
    ///
    /// `entry` and `exit_resume` seed the first entry only; later entries must
    /// call [`Self::prepare_entry`] rather than reconstructing the context.
    pub fn new(snapshot: X86UcontextSnapshot, entry: u64, exit_resume: u64) -> Self {
        let mut host_xsave = [std::mem::MaybeUninit::uninit(); XSAVE_AREA_LEN];
        // XSAVE need not overwrite reserved header bytes, while XRSTOR requires
        // them to be zero. Enabled component payloads are written by XSAVE.
        host_xsave[512..576].fill(std::mem::MaybeUninit::new(0));
        Self {
            snapshot,
            host_xsave,
            host_rsp: 0,
            host_callee: [0; 6],
            entry,
            exit_resume,
            exit_status: 0,
            exit_pad: 0,
            exit_syscall_addr: 0,
            exit_indirect_addr: 0,
            exit_sensitive_addr: 0,
            scratch: 0,
            scratch2: 0,
            guest_fsbase: 0,
            host_fsbase: 0,
            fault: carrick_dsr::fault::FaultRecord::new(),
            // Default: save/restore the FPU area (the always-correct behavior).
            // The runtime driver sets it per block from `X86Block::uses_fpu`;
            // in-crate tests keep the conservative default.
            save_fpu: 1,
            use_xsaveopt: host_supports_xsaveopt(),
            chain_patch_site: 0,
            identity: X86IdentityStamp::default(),
            diagnostic_flags: 0,
            host_xsave_initialized: 0,
            indirect_cache_table: 0,
            indirect_cache_len: 0,
            indirect_cache_site: 0,
            indirect_actual_target: 0,
            kick_restore_rcx: 0,
            exit_kicked_addr: 0,
            executable_stop_word: 0,
            last_copied_x87_guest_va: 0,
            last_copied_x87_guest_data_va: 0,
            last_copied_x87_data_valid: 0,
        }
    }

    /// Update the scalar inputs for one gateway entry without moving either
    /// XSAVE area. Output and host-save fields are overwritten by the gateway.
    pub fn prepare_entry(
        &mut self,
        entry: u64,
        exit_resume: u64,
        save_fpu: bool,
        identity: Option<X86IdentityStamp>,
        executable_stop_word: Option<&std::sync::atomic::AtomicU32>,
    ) {
        self.entry = entry;
        self.exit_resume = exit_resume;
        self.save_fpu = u32::from(save_fpu);
        self.identity = identity.unwrap_or_default();
        self.executable_stop_word = executable_stop_word
            .map(|word| std::ptr::from_ref(word) as u64)
            .unwrap_or(0);
        self.diagnostic_flags = 0;
        self.indirect_cache_site = 0;
        self.indirect_actual_target = 0;
        self.kick_restore_rcx = 0;
        self.last_copied_x87_guest_va = 0;
        self.last_copied_x87_guest_data_va = 0;
        self.last_copied_x87_data_valid = 0;
        // Only a chain-miss stub writes this. Clear it so a prior miss cannot
        // misclassify the next genuine indirect exit.
        self.chain_patch_site = 0;
    }

    /// Publish a stable indirect-cache slice for the immediately following
    /// translated interval.
    ///
    /// # Safety
    /// The slice must not move, shrink, or be mutated while
    /// [`enter_translated`] is executing. The runtime satisfies this by growing
    /// and arming the thread-local vector only at gateway boundaries.
    pub unsafe fn publish_indirect_cache(&mut self, entries: &[X86IndirectCacheEntry]) {
        self.indirect_cache_table = if entries.is_empty() {
            0
        } else {
            entries.as_ptr() as u64
        };
        self.indirect_cache_len = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    }
}

// The C gateway indexes these by byte offset; keep them in lockstep with
// gateway_x86_64.S (the `.equ` block). A drift here is a compile error.
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, gpr) == 0);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, rip) == 128);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, rflags) == 136);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, virtual_pkru) == 144);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, virtual_x87_fcs) == 148);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, virtual_x87_fds) == 150);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, xsave) == 192);
const _: () = assert!(std::mem::size_of::<X86UcontextSnapshot>() == 16_576);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, snapshot) == 0);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_xsave) == 16_576);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_rsp) == 32_960);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_callee) == 32_968);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, entry) == 33_016);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_resume) == 33_024);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_status) == 33_032);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_syscall_addr) == 33_040);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_indirect_addr) == 33_048);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_sensitive_addr) == 33_056);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch) == 33_064);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch) as i32 == CTX_SCRATCH);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch2) as i32 == CTX_SCRATCH2);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, guest_fsbase) as i32 == CTX_GUEST_FSBASE);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_fsbase) as i32 == CTX_HOST_FSBASE);
const _: () = assert!(
    std::mem::offset_of!(X86UcontextSnapshot, gpr) + 15 * 8 == SNAP_GUEST_R15 as usize,
    "the emitter's r15 rename addresses gpr[15] directly"
);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, fault) as u32 == CTX_FAULT_RECORD);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, save_fpu) as i32 == CTX_SAVE_FPU);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, use_xsaveopt) == 33_124);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, chain_patch_site) as i32 == CTX_CHAIN_PATCH);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, identity)
        + std::mem::offset_of!(X86IdentityStamp, live_gate)
        == CTX_IDENTITY_LIVE_GATE as usize
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, identity) + std::mem::offset_of!(X86IdentityStamp, pid)
        == CTX_IDENTITY_PID as usize
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, identity) + std::mem::offset_of!(X86IdentityStamp, tid)
        == CTX_IDENTITY_TID as usize
);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, diagnostic_flags) as i32 == CTX_DIAGNOSTIC_FLAGS);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, host_xsave_initialized) as i32
        == CTX_HOST_XSAVE_INITIALIZED
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, indirect_cache_table) as i32 == CTX_INDIRECT_CACHE_TABLE
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, indirect_cache_len) as i32 == CTX_INDIRECT_CACHE_LEN
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, indirect_cache_site) as i32 == CTX_INDIRECT_CACHE_SITE
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, indirect_actual_target) as i32
        == CTX_INDIRECT_ACTUAL_TARGET
);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, kick_restore_rcx) as i32 == CTX_KICK_RESTORE_RCX);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, exit_kicked_addr) as i32 == CTX_EXIT_KICKED_ADDR);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, executable_stop_word) as i32 == CTX_EXECUTABLE_STOP_WORD
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, last_copied_x87_guest_va) as i32
        == CTX_LAST_COPIED_X87_GUEST_VA
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, last_copied_x87_guest_data_va) as i32
        == CTX_LAST_COPIED_X87_GUEST_DATA_VA
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, last_copied_x87_data_valid) as i32
        == CTX_LAST_COPIED_X87_DATA_VALID
);
const _: () = assert!(std::mem::size_of::<X86IndirectCacheEntry>() == 32);
const _: () = assert!(std::mem::size_of::<X86DsrContext>() == 33_280);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_resume) as i32 == CTX_EXIT_RESUME);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, exit_syscall_addr) as i32 == CTX_EXIT_SYSCALL_ADDR);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, entry) as i32 == CTX_ENTRY);

/// Whether this CPU exposes the FSGSBASE instructions
/// (`rdfsbase`/`wrfsbase`), which the gateway's fs-base swap uses (CPUID
/// leaf 7 subleaf 0, EBX bit 0). The kernel must also have enabled
/// CR4.FSGSBASE — FreeBSD does so whenever the CPU has it — and the
/// execution tests prove the pair end-to-end. A runtime without this must
/// refuse guests that set a TLS base rather than approximate.
#[cfg(target_arch = "x86_64")]
pub fn fsgsbase_supported() -> bool {
    // cpuid is unprivileged; leaf 7 exists on every x86_64 CPU new enough to
    // run this code (the intrinsic is safe on x86_64 targets).
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    leaf7.ebx & 1 != 0
}

#[cfg(not(target_arch = "x86_64"))]
pub fn fsgsbase_supported() -> bool {
    false
}

// The assembled gateway is the ONE target boundary in this crate. build.rs
// assembles gateway_x86_64.S on target_arch = "x86_64" (any OS — the asm is
// SysV-ABI-portable). Everything that enters translated execution lives here.
#[cfg(target_arch = "x86_64")]
mod native_gateway {
    use super::{X86DsrContext, XSAVE_AREA_LEN};

    fn host_xsave_fits_snapshot() -> bool {
        static FITS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *FITS.get_or_init(|| {
            let features = std::arch::x86_64::__cpuid(1).ecx;
            let xsave_enabled = features & ((1 << 26) | (1 << 27)) == ((1 << 26) | (1 << 27));
            xsave_enabled
                && std::arch::x86_64::__cpuid_count(0x0d, 0).ebx as usize <= XSAVE_AREA_LEN
        })
    }

    unsafe extern "C" {
        fn carrick_dsr_x86_enter_raw(context: *mut X86DsrContext) -> i32;
        fn carrick_dsr_x86_exit_syscall();
        fn carrick_dsr_x86_exit_indirect();
        fn carrick_dsr_x86_exit_sensitive();
        fn carrick_dsr_x86_exit_signal();
        fn carrick_dsr_x86_exit_kicked();
    }

    /// Absolute address of the signal exit stub — what the host-OS seam's
    /// fault shim installs as the redirected RIP after recording a guest
    /// fault (paired with [`super::CTX_FAULT_RECORD`]).
    pub fn signal_stub_addr() -> u64 {
        carrick_dsr_x86_exit_signal as *const () as u64
    }

    /// Absolute address of the asynchronous host-kick exit stub.
    pub fn kick_stub_addr() -> u64 {
        carrick_dsr_x86_exit_kicked as *const () as u64
    }

    /// Absolute addresses of the three exit stubs. Emitted code branches to
    /// one via `jmp *disp(%r15)` where `disp` is the matching
    /// `CTX_EXIT_*_ADDR` offset.
    pub fn exit_stub_addresses() -> (u64, u64, u64) {
        (
            carrick_dsr_x86_exit_syscall as *const () as u64,
            carrick_dsr_x86_exit_indirect as *const () as u64,
            carrick_dsr_x86_exit_sensitive as *const () as u64,
        )
    }

    /// Enter the translated block described by `context`. Returns the raw
    /// exit status (decode with [`super::X86ExitStatus::from_raw`]). On
    /// return, `context.snapshot` holds the updated guest state.
    ///
    /// # Safety
    /// `context.entry` must be a valid, executable cache VA holding a
    /// translated block that ends in one of the gateway's exit stubs, and
    /// `context.snapshot.gpr[RSP]` must point at a valid guest stack. The
    /// caller must keep the JIT region mapped for the duration.
    pub unsafe fn enter_translated(context: &mut X86DsrContext) -> i32 {
        if !host_xsave_fits_snapshot() {
            return -1;
        }
        let (syscall, indirect, sensitive) = exit_stub_addresses();
        context.exit_syscall_addr = syscall;
        context.exit_indirect_addr = indirect;
        context.exit_sensitive_addr = sensitive;
        context.exit_kicked_addr = kick_stub_addr();
        // SAFETY: forwarded to the caller's contract above; the trampoline
        // saves/restores all host callee-saved state around the guest run.
        unsafe { carrick_dsr_x86_enter_raw(context as *mut X86DsrContext) }
    }
}

#[cfg(target_arch = "x86_64")]
pub use native_gateway::{enter_translated, exit_stub_addresses, kick_stub_addr, signal_stub_addr};

/// Off-x86 fail-closed complement: the gateway only exists on x86_64. This
/// keeps the crate compiling (and unit-testable) on other host arches, where
/// translated x86 execution is meaningless.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn enter_translated(_context: &mut X86DsrContext) -> i32 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiler_layout_tracks_the_gateway_context() {
        let layout = x86_dsr_profiler_layout();
        assert_eq!(layout.version, 1);
        assert_eq!(layout.context_register, "R_R15");
        assert_eq!(
            layout.context_size as usize,
            std::mem::size_of::<X86DsrContext>()
        );
        assert_eq!(
            layout.exit_resume_offset as usize,
            std::mem::offset_of!(X86DsrContext, exit_resume)
        );
        assert_eq!(layout.exit_resume_offset as i32, CTX_EXIT_RESUME);
    }

    #[test]
    fn prepare_entry_reuses_context_and_clears_transient_state() {
        let mut context = X86DsrContext::new(X86UcontextSnapshot::new(), 1, 2);
        let address = std::ptr::addr_of!(context);
        let stop_word = std::sync::atomic::AtomicU32::new(0);
        assert_eq!(context.host_xsave_initialized, 0);
        assert_eq!(context.exit_kicked_addr, 0);
        assert_eq!(context.executable_stop_word, 0);
        context.prepare_entry(
            3,
            4,
            true,
            Some(X86IdentityStamp::live(5, 6, 7)),
            Some(&stop_word),
        );
        assert_eq!(context.entry, 3);
        assert_eq!(context.exit_resume, 4);
        assert_eq!(context.save_fpu, 1);
        assert_eq!(context.identity.pid, 6);
        assert_eq!(
            context.executable_stop_word,
            std::ptr::from_ref(&stop_word) as u64
        );

        context.chain_patch_site = 8;
        context.diagnostic_flags = 1;
        context.host_xsave_initialized = 1;
        context.last_copied_x87_guest_va = 0x4010;
        context.last_copied_x87_guest_data_va = 0;
        context.last_copied_x87_data_valid = 1;
        context.prepare_entry(9, 10, false, None, None);
        assert_eq!(std::ptr::addr_of!(context), address);
        assert_eq!(context.save_fpu, 0);
        assert_eq!(context.identity, X86IdentityStamp::default());
        assert_eq!(context.chain_patch_site, 0);
        assert_eq!(context.diagnostic_flags, 0);
        assert_eq!(context.host_xsave_initialized, 1);
        assert_eq!(context.executable_stop_word, 0);
        assert_eq!(context.last_copied_x87_guest_va, 0);
        assert_eq!(context.last_copied_x87_guest_data_va, 0);
        assert_eq!(context.last_copied_x87_data_valid, 0);
    }

    #[test]
    fn virtual_selectors_keep_x87_noninitial_after_hardware_save_elision() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.xsave[512..520].fill(0);
        assert_eq!(snapshot.xstate_bv(), 0);

        snapshot.restore_x87_selectors(0x1357, 0x2468);
        assert_eq!(
            snapshot.xstate_bv(),
            1,
            "virtual selector state is part of the logical x87 component"
        );

        snapshot.restore_x87_selectors(
            carrick_abi::LINUX_X8664_USER_CS,
            carrick_abi::LINUX_X8664_USER_DS,
        );
        assert_eq!(snapshot.xstate_bv(), 0);
    }

    #[test]
    fn xstate_summary_reports_controls_and_distinguishes_component_changes() {
        let mut snapshot = X86UcontextSnapshot::new();
        let initial = snapshot.xstate_summary();
        assert_eq!(initial.fcw, 0x037f);
        assert_eq!(initial.mxcsr, 0x1f80);
        assert_eq!(initial.xstate_bv, 0x3);

        snapshot.xsave[32] ^= 0x5a;
        let legacy_changed = snapshot.xstate_summary();
        assert_ne!(legacy_changed.legacy_hash, initial.legacy_hash);
        assert_eq!(legacy_changed.extended_hash, initial.extended_hash);

        snapshot.xsave[576] ^= 0xa5;
        let extended_changed = snapshot.xstate_summary();
        assert_ne!(extended_changed.extended_hash, legacy_changed.extended_hash);

        if let Some((start, _)) = xsave_component_bounds(2) {
            snapshot.xsave[start] ^= 0x3c;
            assert_ne!(
                snapshot.xstate_summary().ymm_hash,
                extended_changed.ymm_hash
            );
        }
        snapshot.apply_guest_pkru_write(3);
        assert_eq!(snapshot.pkru().raw(), 3);
        assert!(snapshot.pkru().requires_guest_residency());
        if let Some((start, _)) = xsave_component_bounds(9).filter(|(_, len)| *len >= 4) {
            assert_eq!(
                &snapshot.xsave[start..start + 4],
                &[0; 4],
                "virtual guest PKRU must never revoke gateway memory access"
            );
        }
    }

    #[test]
    fn signal_xstate_roundtrip_is_complete_and_malformed_input_is_atomic() {
        let capabilities = signal_xstate_capabilities().expect("x86 test host exposes XSAVE");
        let mut original = X86UcontextSnapshot::new();
        original.xsave[28..32].copy_from_slice(&capabilities.mxcsr_mask.to_le_bytes());
        original.xsave[32] = 0x5a;
        original.xsave[160] = 0xa5;
        original.xsave[512..520].copy_from_slice(&capabilities.supported_features.to_le_bytes());
        for component in 2..64usize {
            if capabilities.supported_features & (1u64 << component) == 0 {
                continue;
            }
            let range = capabilities.components[component];
            let start = range.offset as usize;
            let end = range.end().expect("validated component range");
            for (index, byte) in original.xsave[start..end].iter_mut().enumerate() {
                *byte = (component as u8).wrapping_mul(17).wrapping_add(index as u8);
            }
        }
        original.apply_guest_pkru_write(3);

        original.restore_x87_selectors(0x1357, 0x2468);
        let (bytes, xfeatures, virtual_pkru, virtual_x87_fcs, virtual_x87_fds) = original
            .export_signal_xstate()
            .expect("export signal xstate");
        assert_eq!(xfeatures, capabilities.supported_features);
        assert_eq!(virtual_pkru, 3);
        assert_eq!(virtual_x87_fcs, 0x1357);
        assert_eq!(virtual_x87_fds, 0x2468);
        assert_eq!(bytes.len(), capabilities.standard_size as usize);

        let mut restored = X86UcontextSnapshot::new();
        restored
            .restore_signal_xstate(
                &bytes,
                xfeatures,
                virtual_pkru,
                virtual_x87_fcs,
                virtual_x87_fds,
            )
            .expect("restore signal xstate");
        assert_eq!(&restored.xsave[..464], &original.xsave[..464]);
        assert_eq!(restored.xstate_bv(), capabilities.supported_features);
        assert_eq!(restored.pkru().raw(), 3);
        assert_eq!(restored.x87_fcs(), 0x1357);
        assert_eq!(restored.x87_fds(), 0x2468);
        for component in 2..64usize {
            if capabilities.supported_features & (1u64 << component) == 0 {
                continue;
            }
            let range = capabilities.components[component];
            let start = range.offset as usize;
            let end = range.end().expect("validated component range");
            assert_eq!(
                &restored.xsave[start..end],
                &original.xsave[start..end],
                "component {component}"
            );
        }

        let before = restored.clone();
        let mut malformed = bytes;
        malformed[520] = 1;
        assert!(
            restored
                .restore_signal_xstate(&malformed, xfeatures, 0, 0, 0)
                .is_err()
        );
        assert_eq!(restored.xsave, before.xsave);
        assert_eq!(restored.pkru(), before.pkru());
        assert_eq!(restored.x87_fcs(), before.x87_fcs());
        assert_eq!(restored.x87_fds(), before.x87_fds());

        let mut constrained = X86UcontextSnapshot::new();
        constrained.xsave[512..520].copy_from_slice(&(0x3 | (1u64 << 17)).to_le_bytes());
        assert!(matches!(
            constrained.export_signal_xstate(),
            Err(X86SnapshotXstateError::Unavailable(_))
        ));
    }

    #[test]
    fn initial_snapshot_seeds_linux_fpu_control_words() {
        // A fresh standard XSAVE image carries Linux's initial FP control
        // state. FCW at byte 0 = 0x037F; MXCSR at byte 24 = 0x1F80; XSTATE_BV
        // names the initialized x87/SSE legacy components. Virtual selectors
        // come from Carrick's guest GDT contract, never from the FreeBSD host.
        let s = X86UcontextSnapshot::new();
        assert_eq!(u16::from_le_bytes([s.xsave[0], s.xsave[1]]), 0x037F, "FCW");
        assert_eq!(
            u32::from_le_bytes([s.xsave[24], s.xsave[25], s.xsave[26], s.xsave[27]]),
            0x1F80,
            "MXCSR"
        );
        assert_eq!(
            u64::from_le_bytes(s.xsave[512..520].try_into().unwrap()),
            0x3,
            "XSTATE_BV"
        );
        assert_eq!(s.x87_fcs(), carrick_abi::LINUX_X8664_USER_CS);
        assert_eq!(s.x87_fds(), carrick_abi::LINUX_X8664_USER_DS);
        assert!(s.xsave[28..512].iter().all(|&byte| byte == 0));
        assert!(s.xsave[520..].iter().all(|&byte| byte == 0));
    }
}
