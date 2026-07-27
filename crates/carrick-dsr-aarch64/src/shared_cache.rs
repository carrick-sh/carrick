//! Portable identity and wire contracts for immutable AArch64 translation units.

use carrick_dsr::address::NativeHostBias;
use carrick_guest_mem::GuestVa;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const TRANSLATOR_ABI_V1: u32 = 1;
const DARWIN_HOST_PAGE_SIZE: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SourceFingerprint(pub [u8; 32]);

impl SourceFingerprint {
    pub fn from_words(words: &[u32]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"carrick-aarch64-shared-source-v1");
        digest.update((words.len() as u64).to_le_bytes());
        for word in words {
            digest.update(word.to_le_bytes());
        }
        Self(digest.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum NativePageProfileIdentity {
    Native16k,
    Linux4kOn16k,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ExecutableIdentity {
    HostFile {
        device: u64,
        inode: u64,
        size: u64,
        mtime_seconds: i64,
        mtime_nanoseconds: i64,
    },
    Digest([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageFileOffset(u64);

impl ImageFileOffset {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageFileLen(u64);

impl ImageFileLen {
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GuestCodeLen(u64);

impl GuestCodeLen {
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HostBiasIdentity(u64);

impl HostBiasIdentity {
    const fn from_validated(bias: NativeHostBias) -> Self {
        Self(bias.get())
    }

    fn from_wire(raw: u64) -> Option<Self> {
        NativeHostBias::new(raw, DARWIN_HOST_PAGE_SIZE)
            .ok()
            .map(Self::from_validated)
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressModeIdentity {
    Direct,
    Biased { host_bias: HostBiasIdentity },
}

impl AddressModeIdentity {
    pub const fn biased(host_bias: NativeHostBias) -> Self {
        Self::Biased {
            host_bias: HostBiasIdentity::from_validated(host_bias),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TranslationUnitKey {
    executable: ExecutableIdentity,
    segment_file_offset: ImageFileOffset,
    segment_file_len: ImageFileLen,
    guest_va_start: GuestVa,
    guest_va_len: GuestCodeLen,
    source_fingerprint: SourceFingerprint,
    page_profile: NativePageProfileIdentity,
    address_mode: AddressModeIdentity,
    translator_abi: u32,
}

impl TranslationUnitKey {
    #[allow(clippy::too_many_arguments)]
    pub fn for_segment(
        executable: ExecutableIdentity,
        segment_file_offset: ImageFileOffset,
        segment_file_len: ImageFileLen,
        guest_va_start: GuestVa,
        guest_va_len: GuestCodeLen,
        source_fingerprint: SourceFingerprint,
        page_profile: NativePageProfileIdentity,
        address_mode: AddressModeIdentity,
    ) -> Self {
        Self {
            executable,
            segment_file_offset,
            segment_file_len,
            guest_va_start,
            guest_va_len,
            source_fingerprint,
            page_profile,
            address_mode,
            translator_abi: TRANSLATOR_ABI_V1,
        }
    }

    pub const fn guest_va_start(&self) -> GuestVa {
        self.guest_va_start
    }

    pub fn file_stem(&self) -> Result<String, serde_json::Error> {
        let encoded = serde_json::to_vec(self)?;
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        let mut stem = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(stem, "{byte:02x}");
        }
        Ok(stem)
    }
}

#[derive(Serialize, Deserialize)]
enum WireAddressModeIdentity {
    Direct,
    Biased { host_bias: u64 },
}

impl From<AddressModeIdentity> for WireAddressModeIdentity {
    fn from(value: AddressModeIdentity) -> Self {
        match value {
            AddressModeIdentity::Direct => Self::Direct,
            AddressModeIdentity::Biased { host_bias } => Self::Biased {
                host_bias: host_bias.get(),
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WireTranslationUnitKey {
    executable: ExecutableIdentity,
    segment_file_offset: u64,
    segment_file_len: u64,
    guest_va_start: u64,
    guest_va_len: u64,
    source_fingerprint: SourceFingerprint,
    page_profile: NativePageProfileIdentity,
    address_mode: WireAddressModeIdentity,
    translator_abi: u32,
}

impl From<&TranslationUnitKey> for WireTranslationUnitKey {
    fn from(value: &TranslationUnitKey) -> Self {
        Self {
            executable: value.executable.clone(),
            segment_file_offset: value.segment_file_offset.get(),
            segment_file_len: value.segment_file_len.get(),
            guest_va_start: value.guest_va_start.raw(),
            guest_va_len: value.guest_va_len.get(),
            source_fingerprint: value.source_fingerprint,
            page_profile: value.page_profile,
            address_mode: value.address_mode.into(),
            translator_abi: value.translator_abi,
        }
    }
}

impl Serialize for TranslationUnitKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireTranslationUnitKey::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TranslationUnitKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireTranslationUnitKey::deserialize(deserializer)?;
        let segment_file_len = ImageFileLen::new(wire.segment_file_len)
            .ok_or_else(|| serde::de::Error::custom("segment file length is zero"))?;
        let guest_va_len = GuestCodeLen::new(wire.guest_va_len)
            .ok_or_else(|| serde::de::Error::custom("guest code length is zero"))?;
        let address_mode = match wire.address_mode {
            WireAddressModeIdentity::Direct => AddressModeIdentity::Direct,
            WireAddressModeIdentity::Biased { host_bias } => {
                let host_bias = HostBiasIdentity::from_wire(host_bias)
                    .ok_or_else(|| serde::de::Error::custom("host bias is invalid"))?;
                AddressModeIdentity::Biased { host_bias }
            }
        };
        Ok(Self {
            executable: wire.executable,
            segment_file_offset: ImageFileOffset::new(wire.segment_file_offset),
            segment_file_len,
            guest_va_start: GuestVa(wire.guest_va_start),
            guest_va_len,
            source_fingerprint: wire.source_fingerprint,
            page_profile: wire.page_profile,
            address_mode,
            translator_abi: wire.translator_abi,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::address::NativeHostBias;
    use carrick_guest_mem::GuestVa;

    fn key(
        executable: ExecutableIdentity,
        source: SourceFingerprint,
        address_mode: AddressModeIdentity,
    ) -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            executable,
            ImageFileOffset::new(0x1000),
            ImageFileLen::new(0x4000).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(0x4000).expect("nonzero guest length"),
            source,
            NativePageProfileIdentity::Native16k,
            address_mode,
        )
    }

    #[test]
    fn same_guest_va_with_different_images_never_aliases() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        let second = key(
            ExecutableIdentity::Digest([0x22; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );

        assert_ne!(first, second);
        assert_ne!(
            first.file_stem().expect("first stem"),
            second.file_stem().expect("second stem")
        );
    }

    #[test]
    fn same_image_with_different_source_fingerprints_never_aliases() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::Direct,
        );
        let second = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xbb; 32]),
            AddressModeIdentity::Direct,
        );

        assert_ne!(first, second);
        assert_ne!(
            first.file_stem().expect("first stem"),
            second.file_stem().expect("second stem")
        );
    }

    #[test]
    fn same_image_with_different_host_biases_never_aliases() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        let second = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x9000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );

        assert_ne!(first, second);
        assert_ne!(
            first.file_stem().expect("first stem"),
            second.file_stem().expect("second stem")
        );
    }

    #[test]
    fn source_fingerprint_uses_all_words_in_little_endian_order() {
        let first = SourceFingerprint::from_words(&[0x0102_0304, 0x0506_0708]);
        let second = SourceFingerprint::from_words(&[0x0102_0304, 0x0506_0709]);
        let reordered = SourceFingerprint::from_words(&[0x0506_0708, 0x0102_0304]);

        assert_ne!(first, second);
        assert_ne!(first, reordered);
    }

    #[test]
    fn key_json_round_trips_typed_guest_va() {
        let original = key(
            ExecutableIdentity::Digest([0x44; 32]),
            SourceFingerprint([0x55; 32]),
            AddressModeIdentity::Direct,
        );

        let json = serde_json::to_vec(&original).expect("serialize key");
        let decoded: TranslationUnitKey = serde_json::from_slice(&json).expect("deserialize key");

        assert_eq!(decoded, original);
        assert_eq!(decoded.guest_va_start(), GuestVa(0x400000));
    }
}
