//! Precompiled in-guest EL1 kernel binary image.

/// The raw flat binary of the `carrick-el1` in-guest kernel image.
pub static IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/carrick-el1.bin"));

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{IMAGE_MAGIC, IMAGE_VERSION, ImageHeader};

    #[test]
    fn test_embedded_image_header() {
        let header = ImageHeader::read_from_prefix(IMAGE).expect("valid ImageHeader in IMAGE");
        assert_eq!(header.magic, IMAGE_MAGIC);
        assert_eq!(header.version, IMAGE_VERSION);
        // `image_size` is the loaded memory footprint (`_image_end` includes
        // `.bss`); `objcopy -O binary` omits the trailing zero-initialised
        // `.bss`, so the flat file may be shorter. The loader places IMAGE at
        // the start of a freshly zeroed region, which zero-fills the rest.
        assert!(IMAGE.len() as u64 <= header.image_size);
        assert!(header.image_size <= carrick_el1_abi::EL1_IMAGE_SIZE);
        assert!(header.entry_offset < IMAGE.len() as u64);
    }
}
