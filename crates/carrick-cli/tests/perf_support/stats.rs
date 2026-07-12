#[path = "../../src/perf_stats.rs"]
mod implementation;

// Keep the test harness on the same reusable summary and seeded-bootstrap
// implementation as the CLI's DSR evidence collector.
pub use implementation::*;
