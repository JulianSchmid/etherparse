use super::super::*;

proptest! {
    /// Constructor check
    #[test]
    fn new(
        next_header in any::<u8>(),
        fragment_offset in any::<u16>(),
        more_fragments in any::<bool>(),
        identification in any::<u32>(),
    ) {
        let a = Ipv6FragmentHeader::new(
            next_header,
            fragment_offset,
            more_fragments,
            identification
        );
        assert_eq!(next_header, a.next_header);
        assert_eq!(fragment_offset, a.fragment_offset);
        assert_eq!(more_fragments, a.more_fragments);
        assert_eq!(identification, a.identification);
    }
}

proptest! {
    /// Check that aribtrary fragment header can be serialized and deserialized
    #[test]
    fn write_read(
        input in ipv6_fragment_any(),
        dummy_data in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(16);
        input.write(&mut buffer).unwrap();
        buffer.extend(&dummy_data[..]);
        //deserialize (with Ipv6ExtensionHeaderSlice)
        {
            let result = Ipv6FragmentHeaderSlice::from_slice(&buffer[..]).unwrap();

            //check equivalence
            assert_eq!(input.next_header, result.next_header());
            assert_eq!(input.fragment_offset, result.fragment_offset());
            assert_eq!(input.more_fragments, result.more_fragments());
            assert_eq!(input.identification, result.identification());
            assert_eq!(input, result.to_header());
        }
        //deserialize (with read_from_slice)
        {
            let result = Ipv6FragmentHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(input, result.0);
            assert_eq!(&buffer[8..], result.1);
        }
    }
}

proptest! {
    /// Check that a too big offset triggers an error
    #[test]
    fn write_bad_offset(
        next_header in any::<u8>(),
        fragment_offset in 0b0010_0000_0000_0000u16..=0xffffu16,
        more_fragments in any::<bool>(),
        identification in any::<u32>(),
    ) {
        use crate::ValueError::*;
        use crate::ErrorField::*;

        let input = Ipv6FragmentHeader::new(
            next_header,
            fragment_offset,
            more_fragments,
            identification
        );
        let mut buffer: Vec<u8> = Vec::with_capacity(0);
        assert_eq!(
            input.write(&mut buffer).unwrap_err().value_error().unwrap(),
            U16TooLarge{value: fragment_offset, max: 0b0001_1111_1111_1111, field: Ipv6FragmentOffset}
        );

    }
}
