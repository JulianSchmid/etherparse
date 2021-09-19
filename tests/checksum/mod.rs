use super::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn u32_u16_comparison(
        data in proptest::collection::vec(any::<u8>(), 0..0xfffusize)
    ) {
        use super::etherparse::checksum::*;

        let u32_oc = u32_16bit_word::ones_complement(
            u32_16bit_word::add_slice(0, &data)
        );
        let u64_oc = u64_16bit_word::ones_complement(
            u64_16bit_word::add_slice(0, &data)
        );
        assert_eq!(u32_oc, u64_oc);

        let struct_oc = Sum16BitWords::new()
            .add_slice(&data)
            .ones_complement();
        assert_eq!(u32_oc, struct_oc);
    }
}
