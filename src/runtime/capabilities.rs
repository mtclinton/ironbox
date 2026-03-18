use containerd_shim::{other, Error, Result};
use log::debug;
use oci_spec::runtime::{Capability, Spec};

/// Maximum Linux capability number (CAP_LAST_CAP as of kernel 6.x).
const CAP_LAST_CAP: u32 = 40;

/// Map OCI Capability enum to Linux capability number.
fn cap_to_num(cap: &Capability) -> u32 {
    match cap {
        Capability::Chown => 0,
        Capability::DacOverride => 1,
        Capability::DacReadSearch => 2,
        Capability::Fowner => 3,
        Capability::Fsetid => 4,
        Capability::Kill => 5,
        Capability::Setgid => 6,
        Capability::Setuid => 7,
        Capability::Setpcap => 8,
        Capability::LinuxImmutable => 9,
        Capability::NetBindService => 10,
        Capability::NetBroadcast => 11,
        Capability::NetAdmin => 12,
        Capability::NetRaw => 13,
        Capability::IpcLock => 14,
        Capability::IpcOwner => 15,
        Capability::SysModule => 16,
        Capability::SysRawio => 17,
        Capability::SysChroot => 18,
        Capability::SysPtrace => 19,
        Capability::SysPacct => 20,
        Capability::SysAdmin => 21,
        Capability::SysBoot => 22,
        Capability::SysNice => 23,
        Capability::SysResource => 24,
        Capability::SysTime => 25,
        Capability::SysTtyConfig => 26,
        Capability::Mknod => 27,
        Capability::Lease => 28,
        Capability::AuditWrite => 29,
        Capability::AuditControl => 30,
        Capability::Setfcap => 31,
        Capability::MacOverride => 32,
        Capability::MacAdmin => 33,
        Capability::Syslog => 34,
        Capability::WakeAlarm => 35,
        Capability::BlockSuspend => 36,
        Capability::AuditRead => 37,
        Capability::Perfmon => 38,
        Capability::Bpf => 39,
        Capability::CheckpointRestore => 40,
    }
}

/// Convert a set of OCI Capabilities to a bitmask.
fn caps_to_mask<'a>(caps: impl IntoIterator<Item = &'a Capability>) -> u64 {
    let mut mask = 0u64;
    for cap in caps {
        mask |= 1u64 << cap_to_num(cap);
    }
    mask
}

/// Apply capability restrictions from the OCI spec.
pub fn apply_capabilities(spec: &Spec) -> Result<()> {
    let process = match spec.process() {
        Some(p) => p,
        None => return Ok(()),
    };

    let capabilities = match process.capabilities() {
        Some(c) => c,
        None => return Ok(()),
    };

    // 1. Drop capabilities not in the bounding set
    let bounding = capabilities
        .bounding()
        .as_ref()
        .map(|v| caps_to_mask(v))
        .unwrap_or(0);

    for cap in 0..=CAP_LAST_CAP {
        if bounding & (1u64 << cap) == 0 {
            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as u64, 0, 0, 0) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINVAL) {
                    return Err(other!("PR_CAPBSET_DROP cap {}: {}", cap, err));
                }
            }
        }
    }

    // 2. Set effective/permitted/inheritable via capset(2)
    let effective = capabilities
        .effective()
        .as_ref()
        .map(|v| caps_to_mask(v))
        .unwrap_or(0);
    let permitted = capabilities
        .permitted()
        .as_ref()
        .map(|v| caps_to_mask(v))
        .unwrap_or(0);
    let inheritable = capabilities
        .inheritable()
        .as_ref()
        .map(|v| caps_to_mask(v))
        .unwrap_or(0);

    set_caps(effective, permitted, inheritable)?;

    // 3. Set ambient capabilities
    if let Some(ambient) = capabilities.ambient() {
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as u64,
                0, 0, 0,
            );
        }
        for cap in ambient {
            let num = cap_to_num(cap);
            let ret = unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as u64,
                    num as u64, 0, 0,
                )
            };
            if ret != 0 {
                debug!(
                    "PR_CAP_AMBIENT_RAISE cap {}: {} (non-fatal)",
                    num,
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    // 4. Set no_new_privs if specified
    if process.no_new_privileges().unwrap_or(false) {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(other!(
                "PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    debug!(
        "capabilities applied: bounding={:#x} effective={:#x} permitted={:#x} inheritable={:#x}",
        bounding, effective, permitted, inheritable
    );

    Ok(())
}

/// Set capability sets using capset(2) syscall.
fn set_caps(effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };

    let data = [
        CapData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        CapData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];

    let ret = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if ret != 0 {
        return Err(other!("capset: {}", std::io::Error::last_os_error()));
    }

    Ok(())
}
