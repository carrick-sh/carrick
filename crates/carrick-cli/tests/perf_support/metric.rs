//! Parse a probe's `key=value` stdout into a lookup. Tolerant of extra
//! non-`key=value` lines (warnings etc.); only well-formed pairs are kept.
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Metrics(pub HashMap<String, String>);

impl Metrics {
    pub fn parse(output: &str) -> Self {
        let mut m = HashMap::new();
        for line in output.lines() {
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                // Only accept bare identifier-ish keys, so a stray "a = b = c"
                // or an env dump line doesn't pollute the map.
                if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    m.insert(k.to_string(), v.to_string());
                }
            }
        }
        Metrics(m)
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.0.get(key).and_then(|v| v.parse::<f64>().ok())
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(|v| v.parse::<u64>().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "tcp_rr_p50_us=8.421\ntcp_rr_p95_us=14.0\nrr_iters=5000\nnproc=4\n";

    #[test]
    fn parses_floats_and_ints() {
        let m = Metrics::parse(SAMPLE);
        assert_eq!(m.get_f64("tcp_rr_p50_us"), Some(8.421));
        assert_eq!(m.get_u64("rr_iters"), Some(5000));
        assert_eq!(m.get_u64("nproc"), Some(4));
    }

    #[test]
    fn ignores_noise_lines() {
        let m = Metrics::parse("carrick: --fs host warning\ntcp_rr_p50_us=9.0\n<TIMEOUT after 45s>\n");
        assert_eq!(m.get_f64("tcp_rr_p50_us"), Some(9.0));
        assert_eq!(m.0.len(), 1);
    }

    #[test]
    fn missing_key_is_none() {
        let m = Metrics::parse(SAMPLE);
        assert_eq!(m.get_f64("nope"), None);
    }
}
