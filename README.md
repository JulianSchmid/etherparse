# etherparse
[![Build Status][build_badge]][build_status]
[![Code Coverage][coverage_badge]][coverage_report]

A library for parsing & writing a bunch of packet based protocols (EthernetII, IPv4, IPv6, UDP ...).

Currently supported are:
* Ethernet II
* IEEE 802.1Q VLAN Tagging Header
* IPv4
* IPv6 (missing extension headers, but supporting skipping them)
* UDP

# References
* Darpa Internet Program Protocol Specification [RFC 791](https://tools.ietf.org/html/rfc791)
* Internet Protocol, Version 6 (IPv6) Specification [RFC 8200](https://tools.ietf.org/html/rfc8200)
* [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
* [Wikipedia IEEE_802.1Q](https://en.wikipedia.org/w/index.php?title=IEEE_802.1Q&oldid=820983900)
* User Datagram Protocol (UDP) [RFC 768](https://tools.ietf.org/html/rfc768)

[build_badge]: https://travis-ci.org/JulianSchmid/etherparse.svg?branch=master
[build_status]: https://travis-ci.org/JulianSchmid/etherparse
[coverage_badge]: https://codecov.io/gh/JulianSchmid/etherparse/branch/master/graph/badge.svg
[coverage_report]: https://codecov.io/gh/JulianSchmid/etherparse/branch/master