use std::mem;

use containerd_shim::{other, Error, Result};
use log::debug;

/// Bring up the loopback (lo) interface inside the container's network namespace.
/// Uses ioctl(SIOCSIFFLAGS) to set IFF_UP — no external commands needed.
pub fn setup_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(other!(
            "socket for loopback setup: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    // Set interface name to "lo"
    let name = b"lo\0";
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name.len(),
        );
    }

    // Set IFF_UP | IFF_RUNNING
    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;

    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifr) };
    unsafe { libc::close(sock) };

    if ret != 0 {
        return Err(other!(
            "ioctl SIOCSIFFLAGS for lo: {}",
            std::io::Error::last_os_error()
        ));
    }

    debug!("loopback interface brought up");
    Ok(())
}
