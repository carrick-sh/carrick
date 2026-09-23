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
        assert_eq!(header.image_size, IMAGE.len() as u64);
        assert!(header.entry_offset < header.image_size);
    }
}
