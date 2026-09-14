use std::fmt::Debug;

/// Infallible publication sink for a carrier-owned descriptor ceiling.
///
/// Implementations own their atomic backing. Calls must not re-enter kernel
/// file-table locks or perform fallible mapping work.
pub trait FdCeilingPublisher: Debug + Send + Sync {
    fn raise(&self, maximum: u32);
    fn disable(&self);
}
