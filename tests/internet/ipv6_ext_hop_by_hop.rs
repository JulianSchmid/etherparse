use super::super::*;

#[test]
fn header_new_raw() {
    let actual_data = [1,2,3,4,5,6,7,8];
    let actual = Ipv6HopByHopHeader::new_raw(123, &actual_data);
    assert_eq!(123, actual.next_header);
    assert_eq!(&actual_data[..], actual.options);
}

#[test]
fn slice_from_slice() {

    // base test
    let data = {
        let mut data = [0;6*8];
        data[0] = 1; // next header type
        data[1] = 4; // header length
        data
    };
    let actual = Ipv6HopByHopHeaderSlice::from_slice(&data).unwrap();
    assert_eq!(1, actual.next_header());
    assert_eq!(
        &data[..5*8],
        actual.slice()
    );
    assert_eq!(
        &data[2..5*8],
        actual.raw_options()
    );

    {
        let header = actual.to_header();
        assert_eq!(1, header.next_header);
        assert_eq!(&data[2..5*8], header.options);
    }
}

#[test]
fn slice_from_slice_error() {
    // errors:
    // length smaller then 8
    {
        assert_matches!(
            Ipv6HopByHopHeaderSlice::from_slice(&[0;7]),
            Err(ReadError::UnexpectedEndOfSlice(8))
        );
    }
    // length smaller then spezified size
    {
        let data = {
            let mut data: [u8;4*8 - 1] = [0;4*8 - 1];
            // set length field
            data[1] = 3;
            data
        };
        assert_matches!(
            Ipv6HopByHopHeaderSlice::from_slice(&data),
            Err(ReadError::UnexpectedEndOfSlice(32))
        );
    }
}

#[test]
fn write() {
    struct SerTest<'a> {
        options: &'a [u8],
        expected: &'a [u8]
    }

    let tests = [
        // no options
        SerTest{options: &[], expected: &[0,0,0,0,0,0]},
        // options with a smaller size then 6
        SerTest{options: &[1,2,3,4,5], expected: &[1,2,3,4,5,0]},
        // options with a size == 6
        SerTest{options: &[1,2,3,4,5,6], expected: &[1,2,3,4,5,6]},
        // options with a size == 7, 17, 21, 22, 23
        SerTest{options: &[1,2,3,4,5,6,7], expected: &[
                1,2,3,4,5,6,
            7,0,0,0,0,0,0,0
        ]},
        SerTest{
            options: &[
                        1, 2, 3, 4, 5, 6,
                  7, 8, 9,10,11,12,13,14,
                 15,16,17,
            ], expected: &[
                        1, 2, 3, 4, 5, 6,
                  7, 8, 9,10,11,12,13,14,
                 15,16,17, 0, 0, 0, 0, 0
            ]
        },
        SerTest{
            options: &[
                       1, 2, 3, 4, 5, 6,
                 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21
            ], expected: &[
                       1, 2, 3, 4, 5, 6,
                 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21, 0
            ]
        },
        SerTest{
            options: &[
                       1, 2, 3, 4, 5, 6,
                 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21,22
            ], expected: &[
                       1, 2, 3, 4, 5, 6,
                 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21,22
            ]
        },
        SerTest{
            options: &[
                       1, 2, 3, 4, 5, 6,
                 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21,22,
                23
            ], expected: &[
                       1, 2, 3, 4, 5, 6,
                 7, 8, 9,10,11,12,13,14,
                15,16,17,18,19,20,21,22,
                23, 0, 0, 0, 0, 0, 0, 0,
            ]
        },
    ];

    for test in tests.iter() {
        let input = Ipv6HopByHopHeader::new_raw(123, test.options);
        let mut buffer: Vec<u8> = Vec::new();
        input.write(&mut buffer).unwrap();
        let actual = Ipv6HopByHopHeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(123, actual.next_header());
        assert_eq!(test.expected, actual.raw_options());
    }
}

#[test]
fn write_error() {
    // options with a too large size
    const TOOBIG_SIZE : usize = 0xff*8 + 6 + 1;
    const TOOBIG : [u8;TOOBIG_SIZE] = [0;TOOBIG_SIZE];
    {
        let input = Ipv6HopByHopHeader::new_raw(233, &TOOBIG);
        let mut buffer: Vec<u8> = Vec::new();
        assert_matches!(
            input.write(&mut buffer),
            Err(WriteError::ValueError(
                ValueError::Ipv6HopByHopOptionsTooLarge(TOOBIG_SIZE)
            ))
        );
    }

    // one smaller should be ok
    {
        let input = Ipv6HopByHopHeader::new_raw(234, &TOOBIG[..TOOBIG_SIZE-1]);
        let mut buffer: Vec<u8> = Vec::new();
        input.write(&mut buffer).unwrap();
        let actual = Ipv6HopByHopHeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(234, actual.next_header());
        assert_eq!(&TOOBIG[..TOOBIG_SIZE-1], actual.raw_options());
    }
}