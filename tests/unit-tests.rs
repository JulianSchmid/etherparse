extern crate etherparse;
use etherparse::*;

#[cfg(test)] #[macro_use]
extern crate assert_matches;

use std::io;

mod link;
mod internet;
mod transport;

#[test]
fn test_debug_write() {
    println!("{:?}", ErrorField::Ipv4HeaderLength);
    println!("{:?}", ValueError::Ipv4OptionsLengthBad(13));
    println!("{:?}", WriteError::ValueError(ValueError::Ipv4OptionsLengthBad(13)));
    println!("{:?}", ReadError::IpUnsupportedVersion(0));
}