use crate::*;
use std::collections::HashMap;

/// Pool of buffers to reconstruct multiple fragmented IP packets in
/// parallel (re-uses buffers to minimize allocations).
///
/// # This implementation is NOT safe against "Out of Memory" attacks
///
/// If you use the [`DefragPool`] in an untrusted environment an attacker could
/// cause an "out of memory error" by opening up multiple parallel TP streams,
/// never ending them and filling them up with as much data as possible.
///
/// Mitigations will hopefully be offered in future versions but if you have
/// take care right now you can still use [`IpDefragBuf`] directly and implement the
/// connection handling and mitigation yourself.
#[derive(Debug, Clone)]
pub struct IpDefragPool<Timestamp = (), CustomChannelId = ()>
where
    Timestamp: Sized + core::fmt::Debug + Clone,
    CustomChannelId: Sized + core::fmt::Debug + Clone + core::hash::Hash + Eq + PartialEq,
{
    /// Currently reconstructing TP streams.
    active: HashMap<IpFragId<CustomChannelId>, (IpDefragBuf, Timestamp)>,

    /// Buffers that have finished receiving data and can be re-used.
    finished: Vec<IpDefragBuf>,
}

impl<Timestamp, CustomChannelId> IpDefragPool<Timestamp, CustomChannelId>
where
    Timestamp: Sized + core::fmt::Debug + Clone,
    CustomChannelId: Sized + core::fmt::Debug + Clone + core::hash::Hash + Eq + PartialEq,
{

}
