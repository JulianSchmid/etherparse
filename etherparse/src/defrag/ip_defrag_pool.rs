use crate::{defrag::*, *};
use std::collections::HashMap;
use std::vec::Vec;

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
    /// Currently reconstructing IP packets.
    active: HashMap<IpFragId<CustomChannelId>, (IpDefragBuf, Timestamp)>,

    /// Data buffers that have finished receiving data and can be re-used.
    finished_data_bufs: Vec<Vec<u8>>,

    /// Section buffers that have finished receiving data and can be re-used.
    finished_section_bufs: Vec<Vec<IpFragRange>>,
}

impl<Timestamp, CustomChannelId> IpDefragPool<Timestamp, CustomChannelId>
where
    Timestamp: Sized + core::fmt::Debug + Clone,
    CustomChannelId: Sized + core::fmt::Debug + Clone + core::hash::Hash + Eq + PartialEq,
{
    pub fn new() -> IpDefragPool {
        IpDefragPool {
            active: HashMap::new(),
            finished_data_bufs: Vec::new(),
            finished_section_bufs: Vec::new(),
        }
    }

    /// Add data from a sliced packet.
    pub fn process_sliced_packet(
        &mut self,
        slice: &SlicedPacket,
        timestamp: Timestamp,
        channel_id: CustomChannelId,
    ) -> Result<Option<IpDefragPayloadVec>, IpDefragError> {
        // extract the fragment related data and skip non-fragmented packets
        let (frag_id, offset, more_fragments, payload, is_ipv4) = match &slice.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                if false == header.is_fragmenting_payload() {
                    // nothing to defragment here, skip packet
                    return Ok(None);
                }

                let (outer_vlan_id, inner_vlan_id) = match &slice.vlan {
                    Some(VlanSlice::SingleVlan(s)) => (Some(s.vlan_identifier()), None),
                    Some(VlanSlice::DoubleVlan(d)) => (
                        Some(d.outer().vlan_identifier()),
                        Some(d.inner().vlan_identifier()),
                    ),
                    None => (None, None),
                };

                (
                    IpFragId {
                        outer_vlan_id,
                        inner_vlan_id,
                        ip: IpFragVersionSpecId::Ipv4 {
                            source: header.source(),
                            destination: header.destination(),
                            identification: header.identification(),
                        },
                        payload_ip_number: ipv4.payload().ip_number,
                        channel_id,
                    },
                    header.fragments_offset(),
                    header.more_fragments(),
                    ipv4.payload(),
                    true,
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                // skip unfragmented packets
                if false == ipv6.is_payload_fragmented() {
                    // nothing to defragment here, skip packet
                    return Ok(None);
                }

                // get fragmentation header
                let frag = {
                    let mut f = None;
                    for ext in ipv6.extensions().clone().into_iter() {
                        use Ipv6ExtensionSlice::*;
                        if let Fragment(frag_it) = ext {
                            f = Some(frag_it);
                            break;
                        }
                    }
                    if let Some(f) = f {
                        f.to_header()
                    } else {
                        // nothing to defragment here, skip packet
                        return Ok(None);
                    }
                };

                let (outer_vlan_id, inner_vlan_id) = match &slice.vlan {
                    Some(VlanSlice::SingleVlan(s)) => (Some(s.vlan_identifier()), None),
                    Some(VlanSlice::DoubleVlan(d)) => (
                        Some(d.outer().vlan_identifier()),
                        Some(d.inner().vlan_identifier()),
                    ),
                    None => (None, None),
                };

                // calculate frag id
                (
                    IpFragId {
                        outer_vlan_id,
                        inner_vlan_id,
                        ip: IpFragVersionSpecId::Ipv6 {
                            source: ipv6.header().source(),
                            destination: ipv6.header().destination(),
                            identification: frag.identification,
                        },
                        payload_ip_number: ipv6.payload().ip_number,
                        channel_id,
                    },
                    frag.fragment_offset,
                    frag.more_fragments,
                    ipv6.payload(),
                    false,
                )
            }
            None => {
                // nothing to defragment here, skip packet
                return Ok(None);
            }
        };

        // get the reconstruction buffer
        use std::collections::hash_map::Entry;
        match self.active.entry(frag_id) {
            Entry::Occupied(mut entry) => {
                let buf = entry.get_mut();
                buf.0.add(offset, more_fragments, payload.payload)?;
                buf.1 = timestamp;
                if buf.0.is_complete() {
                    let (defraged_payload, sections) = entry.remove().0.take_bufs();
                    self.finished_section_bufs.push(sections);
                    Ok(Some(IpDefragPayloadVec {
                        ip_number: payload.ip_number,
                        len_source: if is_ipv4 {
                            LenSource::Ipv4HeaderTotalLen
                        } else {
                            LenSource::Ipv6HeaderPayloadLen
                        },
                        payload: defraged_payload,
                    }))
                } else {
                    Ok(None)
                }
            }
            Entry::Vacant(entry) => {
                let data_buf = if let Some(mut d) = self.finished_data_bufs.pop() {
                    d.clear();
                    d
                } else {
                    Vec::with_capacity(payload.payload.len() * 2)
                };
                let sections = if let Some(mut s) = self.finished_section_bufs.pop() {
                    s.clear();
                    s
                } else {
                    Vec::with_capacity(4)
                };

                let mut defrag_buf = IpDefragBuf::new(payload.ip_number, data_buf, sections);
                match defrag_buf.add(offset, more_fragments, payload.payload) {
                    Ok(()) => {
                        if defrag_buf.is_complete() {
                            let (defraged_payload, sections) = defrag_buf.take_bufs();
                            self.finished_section_bufs.push(sections);
                            Ok(Some(IpDefragPayloadVec {
                                ip_number: payload.ip_number,
                                len_source: if is_ipv4 {
                                    LenSource::Ipv4HeaderTotalLen
                                } else {
                                    LenSource::Ipv6HeaderPayloadLen
                                },
                                payload: defraged_payload,
                            }))
                        } else {
                            entry.insert((defrag_buf, timestamp));
                            Ok(None)
                        }
                    }
                    Err(err) => {
                        // return the buffers
                        let (data_buf, sections) = defrag_buf.take_bufs();
                        self.finished_data_bufs.push(data_buf);
                        self.finished_section_bufs.push(sections);
                        Err(err)
                    }
                }
            }
        }
    }

    /// Returns a buffer to the pool so it can be re-used.
    pub fn return_buf(&mut self, buf: IpDefragPayloadVec) {
        self.finished_data_bufs.push(buf.payload);
    }
}

#[cfg(test)]
mod test {}
