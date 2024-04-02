use crate::{*, defrag::*};
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
    /// Add data from a sliced packet.
    pub fn process_sliced_packet(&mut self, slice: &SlicedPacket, channel_id: CustomChannelId) -> Result<(), IpDefragError> {

        // extract the fragment related data and skip non-fragmented packets
        let (frag_id, offset, more_fragments, payload) = match &slice.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                if false == header.is_fragmenting_payload() {
                    // nothing to defragment here, skip packet
                    return Ok(());
                }

                let (outer_vlan_id, inner_vlan_id) = match &slice.vlan {
                    Some(VlanSlice::SingleVlan(s)) => (Some(s.vlan_identifier()), None),
                    Some(VlanSlice::DoubleVlan(d)) => (Some(d.outer().vlan_identifier()), Some(d.inner().vlan_identifier())),
                    None => (None, None)
                };

                (
                    IpFragId {
                        outer_vlan_id,
                        inner_vlan_id,
                        ip: IpFragVersionSpecId::Ipv4{
                            source: header.source(),
                            destination: header.destination(),
                            identification: header.identification(),
                        },
                        channel_id,
                    },
                    header.fragments_offset(),
                    header.more_fragments(),
                    ipv4.payload()
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                // skip unfragmented packets
                if false == ipv6.is_payload_fragmented() {
                    // nothing to defragment here, skip packet
                    return Ok(());
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
                        return Ok(());
                    }
                };

                let (outer_vlan_id, inner_vlan_id) = match &slice.vlan {
                    Some(VlanSlice::SingleVlan(s)) => (Some(s.vlan_identifier()), None),
                    Some(VlanSlice::DoubleVlan(d)) => (Some(d.outer().vlan_identifier()), Some(d.inner().vlan_identifier())),
                    None => (None, None)
                };

                // calculate frag id
                (
                    IpFragId {
                        outer_vlan_id,
                        inner_vlan_id,
                        ip: IpFragVersionSpecId::Ipv6{
                            source: ipv6.header().source(),
                            destination: ipv6.header().destination(),
                            identification: frag.identification,
                        },
                        channel_id,
                    },
                    frag.fragment_offset,
                    frag.more_fragments,
                    ipv6.payload()
                )
            }
            None => {
                // nothing to defragment here, skip packet
                return Ok(());
            }
        };

        // get the reconstruction buffer
        use std::collections::hash_map::Entry;
        match self.active.entry(frag_id) {
            Entry::Occupied(mut entry) => {
                let buf = entry.get_mut();
                
            }
            Entry::Vacant(mut entry) => {

            }
        }

        //header.
        //slice.

        

        Ok(())
    }
}
