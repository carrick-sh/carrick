//! Hand-authored A64 static census classification (not execution).
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, PartialEq, Eq)]
pub enum A64Class { Unknown, Integer }

pub fn classify(_word: u32) -> A64Class { A64Class::Integer }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserved_span_fails_closed() {
        let words = [0xd503201f, 0xffff_ffff];
        let unknown: std::vec::Vec<_> = words.into_iter().enumerate()
            .filter(|(_, word)| classify(*word) == A64Class::Unknown).collect();
        assert_eq!(unknown, [(1, 0xffff_ffff)]);
    }
}
#[cfg(test)]
extern crate std;
