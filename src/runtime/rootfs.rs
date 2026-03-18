use std::{
    fs,
    path::Path,
};

use containerd_shim::{other, Error, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use oci_spec::runtime::{Mount as OciMount, Spec};

/// Set up the container rootfs: bind-mount it, then pivot_root into it.
pub fn setup_rootfs(rootfs: &Path) -> Result<()> {
    // Bind mount rootfs onto itself so pivot_root works
    // (pivot_root requires new_root to be a mount point)
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| other!("bind mount rootfs: {}", e))?;

    Ok(())
}

/// Perform pivot_root: switch the root filesystem to the container's rootfs.
pub fn pivot_root(rootfs: &Path) -> Result<()> {
    let old_root = rootfs.join("oldrootfs");
    fs::create_dir_all(&old_root)
        .map_err(|e| other!("mkdir oldrootfs: {}", e))?;

    nix::unistd::pivot_root(rootfs, &old_root)
        .map_err(|e| other!("pivot_root: {}", e))?;

    // Change to new root
    std::env::set_current_dir("/")
        .map_err(|e| other!("chdir /: {}", e))?;

    // Unmount and remove old root
    umount2("/oldrootfs", MntFlags::MNT_DETACH)
        .map_err(|e| other!("umount old root: {}", e))?;

    fs::remove_dir("/oldrootfs").unwrap_or_default();

    Ok(())
}

/// Set up all mounts from the OCI spec (proc, sysfs, devpts, tmpfs, bind mounts, etc.)
pub fn setup_mounts(spec: &Spec) -> Result<()> {
    let mounts = match spec.mounts() {
        Some(m) => m,
        None => return Ok(()),
    };

    for m in mounts {
        setup_mount(m)?;
    }

    Ok(())
}

fn setup_mount(m: &OciMount) -> Result<()> {
    let dest = m.destination();

    // Create the mount point
    if dest.to_string_lossy().contains('/') {
        fs::create_dir_all(dest)
            .map_err(|e| other!("mkdir {}: {}", dest.display(), e))?;
    }

    let fs_type = m.typ().as_deref().unwrap_or("");
    let source = m.source().as_ref().map(|s| s.as_path());
    let flags = parse_mount_flags(m.options().as_ref());
    let data = parse_mount_data(m.options().as_ref());

    mount(
        source,
        dest,
        Some(fs_type),
        flags,
        if data.is_empty() {
            None
        } else {
            Some(data.as_str())
        },
    )
    .map_err(|e| other!("mount {} on {}: {}", fs_type, dest.display(), e))?;

    Ok(())
}

/// Parse OCI mount options into MsFlags.
fn parse_mount_flags(options: Option<&Vec<String>>) -> MsFlags {
    let mut flags = MsFlags::empty();
    if let Some(opts) = options {
        for opt in opts {
            match opt.as_str() {
                "bind" => flags |= MsFlags::MS_BIND,
                "rbind" => flags |= MsFlags::MS_BIND | MsFlags::MS_REC,
                "ro" => flags |= MsFlags::MS_RDONLY,
                "nosuid" => flags |= MsFlags::MS_NOSUID,
                "nodev" => flags |= MsFlags::MS_NODEV,
                "noexec" => flags |= MsFlags::MS_NOEXEC,
                "relatime" => flags |= MsFlags::MS_RELATIME,
                "strictatime" => flags |= MsFlags::MS_STRICTATIME,
                "noatime" => flags |= MsFlags::MS_NOATIME,
                "private" => flags |= MsFlags::MS_PRIVATE,
                "rprivate" => flags |= MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                "slave" => flags |= MsFlags::MS_SLAVE,
                "rslave" => flags |= MsFlags::MS_SLAVE | MsFlags::MS_REC,
                "shared" => flags |= MsFlags::MS_SHARED,
                "rshared" => flags |= MsFlags::MS_SHARED | MsFlags::MS_REC,
                "remount" => flags |= MsFlags::MS_REMOUNT,
                _ => {}
            }
        }
    }
    flags
}

/// Extract non-flag mount options as data string.
fn parse_mount_data(options: Option<&Vec<String>>) -> String {
    let flag_opts = [
        "bind", "rbind", "ro", "rw", "nosuid", "nodev", "noexec", "relatime",
        "strictatime", "noatime", "private", "rprivate", "slave", "rslave",
        "shared", "rshared", "remount",
    ];
    if let Some(opts) = options {
        let data_opts: Vec<&str> = opts
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !flag_opts.contains(s))
            .collect();
        data_opts.join(",")
    } else {
        String::new()
    }
}

/// Create default devices in the container (/dev/null, /dev/zero, etc.)
pub fn setup_default_devices() -> Result<()> {
    fs::create_dir_all("/dev").unwrap_or_default();

    let devices: &[(&str, libc::mode_t, u64, u64)] = &[
        ("/dev/null", libc::S_IFCHR, 1, 3),
        ("/dev/zero", libc::S_IFCHR, 1, 5),
        ("/dev/full", libc::S_IFCHR, 1, 7),
        ("/dev/random", libc::S_IFCHR, 1, 8),
        ("/dev/urandom", libc::S_IFCHR, 1, 9),
        ("/dev/tty", libc::S_IFCHR, 5, 0),
    ];

    for &(path, dev_type, major, minor) in devices {
        let dev = nix::sys::stat::makedev(major, minor);
        let _ = fs::remove_file(path);
        let c_path = std::ffi::CString::new(path)
            .map_err(|e| other!("invalid path {}: {}", path, e))?;
        let ret = unsafe { libc::mknod(c_path.as_ptr(), dev_type | 0o666, dev) };
        if ret != 0 {
            // If mknod fails (e.g., in user namespace), try bind-mounting from host
            if Path::new(path).exists() || {
                fs::write(path, "").is_ok()
            } {
                mount(
                    Some(path),
                    path,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .unwrap_or_default();
            }
        }
    }

    fs::create_dir_all("/dev/pts").unwrap_or_default();
    fs::create_dir_all("/dev/shm").unwrap_or_default();

    let symlinks = [
        ("/proc/self/fd", "/dev/fd"),
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr"),
    ];

    for (src, dst) in &symlinks {
        let _ = fs::remove_file(dst);
        std::os::unix::fs::symlink(src, dst).unwrap_or_default();
    }

    Ok(())
}

/// Unmount rootfs during container deletion.
pub fn cleanup_rootfs(rootfs: &Path) -> Result<()> {
    umount2(rootfs, MntFlags::MNT_DETACH)
        .map_err(|e| other!("umount rootfs {}: {}", rootfs.display(), e))?;
    Ok(())
}
