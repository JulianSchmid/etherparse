#![no_std]
#![no_main]

use core::error::Error;
use core::panic::PanicInfo;

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let e = etherparse::err::ip::HeaderError::UnsupportedIpVersion { version_number: 5 };
    e.source();
    
    loop {}
}
