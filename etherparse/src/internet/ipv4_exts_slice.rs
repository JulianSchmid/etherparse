use crate::*;

/// Slices of the IPv4 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
///
/// Currently not supported:
/// * Encapsulating Security Payload Header (ESP)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv4ExtensionsSlice<'a> {
    pub auth: Option<IpAuthHeaderSlice<'a>>,
}

impl<'a> Ipv4ExtensionsSlice<'a> {
    /// Read all known ipv4 extensions and return an `Ipv4ExtensionSlices` with the
    /// identified slices, the final ip number and a slice pointing to the non parsed data.
    pub fn from_slice(
        start_ip_number: IpNumber,
        start_slice: &'a [u8],
    ) -> Result<(Ipv4ExtensionsSlice, IpNumber, &[u8]), err::ip_auth::HeaderSliceError> {
        use ip_number::*;
        if AUTH == start_ip_number {
            let header = IpAuthHeaderSlice::from_slice(start_slice)?;
            let rest = &start_slice[header.slice().len()..];
            let next_header = header.next_header();
            Ok((
                Ipv4ExtensionsSlice { auth: Some(header) },
                next_header,
                rest,
            ))
        } else {
            Ok((Default::default(), start_ip_number, start_slice))
        }
    }

    /// Convert the slices into actual headers.
    pub fn to_header(&self) -> Ipv4Extensions {
        Ipv4Extensions {
            auth: self.auth.as_ref().map(|v| v.to_header()),
        }
    }

    /// Returns true if no IPv4 extension header is present (all fields `None`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.auth.is_none()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use crate::test_gens::*;
    use alloc::vec::Vec;

    proptest! {
        #[test]
        fn debug(auth in ip_auth_any()) {
            use alloc::format;

            // None
            assert_eq!(
                &format!("Ipv4ExtensionsSlice {{ auth: {:?} }}", Option::<IpAuthHeader>::None),
                &format!(
                    "{:?}",
                    Ipv4ExtensionsSlice {
                        auth: None,
                    }
                )
            );

            // Some
            let buffer = {
                let mut buffer = Vec::with_capacity(auth.header_len());
                auth.write(&mut buffer).unwrap();
                buffer
            };
            let auth_slice = IpAuthHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                &format!("Ipv4ExtensionsSlice {{ auth: {:?} }}", Some(auth_slice.clone())),
                &format!(
                    "{:?}",
                    Ipv4ExtensionsSlice {
                        auth: Some(auth_slice.clone()),
                    }
                )
            );
        }
    }


    proptest! {
        #[test]
        fn clone_eq(auth in ip_auth_any()) {
            // None
            {
                let header = Ipv4ExtensionsSlice{
                    auth: None,
                };
                assert_eq!(
                    header.clone(),
                    Ipv4ExtensionsSlice{
                        auth: None,
                    }
                );
            }

            // Some
            {
                let buffer = {
                    let mut buffer = Vec::with_capacity(auth.header_len());
                    auth.write(&mut buffer).unwrap();
                    buffer
                };
                let auth_slice = IpAuthHeaderSlice::from_slice(&buffer).unwrap();
                let slice = Ipv4ExtensionsSlice {
                    auth: Some(auth_slice.clone()),
                };
                assert_eq!(
                    slice.clone(),
                    Ipv4ExtensionsSlice{
                        auth: Some(auth_slice.clone()),
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn to_header(auth in ip_auth_any()) {
            // None
            assert_eq!(
                Ipv4ExtensionsSlice{
                    auth: None,
                }.to_header(),
                Ipv4Extensions{
                    auth: None,
                }
            );

            // Some
            {
                let buffer = {
                    let mut buffer = Vec::with_capacity(auth.header_len());
                    auth.write(&mut buffer).unwrap();
                    buffer
                };
                let slice = Ipv4ExtensionsSlice{
                    auth: Some(
                        IpAuthHeaderSlice::from_slice(&buffer).unwrap()
                    ),
                };
                assert_eq!(
                    slice.to_header(),
                    Ipv4Extensions{
                        auth: Some(auth.clone()),
                    }
                );
            }
        }
    }

    #[test]
    fn is_empty() {
        // empty
        assert!(Ipv4ExtensionsSlice { auth: None }.is_empty());

        // auth
        {
            let buffer = {
                let auth = IpAuthHeader::new(ip_number::UDP, 0, 0, &[]).unwrap();
                let mut buffer = Vec::with_capacity(auth.header_len());
                auth.write(&mut buffer).unwrap();
                buffer
            };
            assert_eq!(
                false,
                Ipv4ExtensionsSlice {
                    auth: Some(IpAuthHeaderSlice::from_slice(&buffer).unwrap()),
                }
                .is_empty()
            );
        }
    }
}
