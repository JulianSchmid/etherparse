
/// Lax payload parsing result which can be either cut off or complete.
/// 
/// If a payload is complete or "cut off" is determined by if all data
/// indicated by the length field in the header (e.g. IP or UDP).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LaxPayload<T: core::fmt::Debug + Clone + Eq + PartialEq> {
    /// Payload is complete.
    Complete(T),
    /// Payload has been cut off early.
    CutOff(T),
}
