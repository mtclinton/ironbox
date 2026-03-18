use std::{
    ffi::CString,
    fs,
    io::Read,
    os::unix::{
        fs::OpenOptionsExt,
        io::{AsRawFd, FromRawFd, OwnedFd},
    },
    path::{Path, PathBuf},
};

use containerd_shim::{other, Error, Result};
use log::debug;
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use oci_spec::runtime::Spec;

use super::{
    namespace::setup_namespaces,
    rootfs::{cleanup_rootfs, pivot_root, setup_default_devices, setup_mounts, setup_rootfs},
};

/// Stdio paths (named FIFOs) for the container process.
pub struct StdioPaths {
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    pub terminal: bool,
}

/// Result of creating a container: the init PID and the pipe to signal start.
pub struct ContainerProcess {
    /// PID of the container init process.
    pub pid: i32,
    /// Write end of the start pipe. Writing to this signals the init process to exec.
    pub start_pipe: OwnedFd,
    /// The rootfs path (for cleanup).
    pub rootfs: PathBuf,
}

/// Create a new container from an OCI bundle.
///
/// This forks a child process that:
/// 1. Redirects stdio to containerd's FIFOs
/// 2. Unshares namespaces per the OCI spec
/// 3. Sets up rootfs (bind mount + pivot_root)
/// 4. Sets up mounts from the OCI spec
/// 5. Signals "ready" to the parent
/// 6. Blocks waiting for the "start" signal
/// 7. Execs the process from the OCI spec
///
/// Returns a ContainerProcess with the child PID and start pipe.
pub fn create_container(
    id: &str,
    bundle: &str,
    spec: &Spec,
    pid_file: &Path,
    stdio: &StdioPaths,
) -> Result<ContainerProcess> {
    let rootfs_path = resolve_rootfs(bundle, spec);

    // Open stdio FIFOs BEFORE forking so the child inherits the fds.
    // The child will dup2 these onto fd 0/1/2.
    let stdin_fd = if !stdio.stdin.is_empty() {
        Some(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&stdio.stdin)
                .map_err(|e| other!("open stdin fifo {}: {}", &stdio.stdin, e))?,
        )
    } else {
        None
    };

    let stdout_fd = if !stdio.stdout.is_empty() {
        Some(
            fs::OpenOptions::new()
                .write(true)
                .open(&stdio.stdout)
                .map_err(|e| other!("open stdout fifo {}: {}", &stdio.stdout, e))?,
        )
    } else {
        None
    };
    let stderr_fd = if !stdio.stderr.is_empty() {
        Some(
            fs::OpenOptions::new()
                .write(true)
                .open(&stdio.stderr)
                .map_err(|e| other!("open stderr fifo {}: {}", &stdio.stderr, e))?,
        )
    } else {
        None
    };

    // Create sync pipes
    // init_pipe: parent writes → child reads (start signal)
    // ready_pipe: child writes → parent reads (setup complete signal)
    let (init_rd, init_wr) = pipe()?;
    let (ready_rd, ready_wr) = pipe()?;
    // error_pipe: child writes error messages → parent reads
    let (err_rd, err_wr) = pipe()?;

    debug!("create_container: forking for container {}", id);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(other!("fork failed: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        // === CHILD PROCESS ===
        // Close parent-side pipe ends
        drop(init_wr);
        drop(ready_rd);
        drop(err_rd);

        // Redirect stdio to the containerd FIFOs
        if let Some(ref f) = stdin_fd {
            // Clear O_NONBLOCK for stdin
            let raw = f.as_raw_fd();
            unsafe {
                let flags = libc::fcntl(raw, libc::F_GETFL);
                libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                libc::dup2(raw, 0);
            }
        }
        if let Some(ref f) = stdout_fd {
            unsafe { libc::dup2(f.as_raw_fd(), 1); }
        }
        if let Some(ref f) = stderr_fd {
            unsafe { libc::dup2(f.as_raw_fd(), 2); }
        }
        // Close the original fds (now duped onto 0/1/2)
        drop(stdin_fd);
        drop(stdout_fd);
        drop(stderr_fd);

        // Run child setup; if anything fails, write error to err_pipe and exit
        let result = child_setup(spec, &rootfs_path, init_rd, ready_wr);
        if let Err(e) = result {
            let msg = format!("{}", e);
            let _ = nix::unistd::write(&err_wr, msg.as_bytes());
            drop(err_wr);
            unsafe { libc::_exit(1) };
        }
        // child_setup should never return Ok — it either execs or loops waiting
        unreachable!();
    }

    // === PARENT PROCESS ===
    // Close child-side pipe ends and stdio fds
    drop(init_rd);
    drop(ready_wr);
    drop(err_wr);
    drop(stdin_fd);
    drop(stdout_fd);
    drop(stderr_fd);

    debug!("create_container: forked child pid={}", pid);

    // Wait for child to signal ready (or error)
    let mut ready_buf = [0u8; 1];
    let mut ready_file = unsafe { fs::File::from_raw_fd(ready_rd.as_raw_fd()) };
    // Prevent double-close
    std::mem::forget(ready_rd);

    match ready_file.read_exact(&mut ready_buf) {
        Ok(_) => {
            if ready_buf[0] != b'R' {
                // Child sent an error indicator
                let mut err_msg = String::new();
                let mut err_file = unsafe { fs::File::from_raw_fd(err_rd.as_raw_fd()) };
                std::mem::forget(err_rd);
                let _ = err_file.read_to_string(&mut err_msg);
                return Err(other!("container init failed: {}", err_msg));
            }
        }
        Err(e) => {
            // Child died before signaling ready — read error pipe
            let mut err_msg = String::new();
            let mut err_file = unsafe { fs::File::from_raw_fd(err_rd.as_raw_fd()) };
            std::mem::forget(err_rd);
            let _ = err_file.read_to_string(&mut err_msg);
            if err_msg.is_empty() {
                return Err(other!("container init died unexpectedly: {}", e));
            }
            return Err(other!("container init failed: {}", err_msg));
        }
    }

    // Write PID file
    fs::write(pid_file, pid.to_string())
        .map_err(|e| other!("write pid file: {}", e))?;

    debug!("create_container: container {} created with pid {}", id, pid);

    Ok(ContainerProcess {
        pid,
        start_pipe: init_wr,
        rootfs: rootfs_path,
    })
}

/// Child process setup: namespaces, rootfs, mounts, then wait for start signal.
fn child_setup(
    spec: &Spec,
    rootfs: &Path,
    init_pipe_rd: OwnedFd,
    ready_pipe_wr: OwnedFd,
) -> Result<()> {
    // 1. Set up namespaces (unshare)
    setup_namespaces(spec)?;

    // 2. Set hostname if UTS namespace is being created
    if let Some(hostname) = spec.hostname() {
        nix::unistd::sethostname(hostname)
            .map_err(|e| other!("sethostname: {}", e))?;
    }

    // 3. Set up rootfs
    setup_rootfs(rootfs)?;

    // 4. Pivot root
    pivot_root(rootfs)?;

    // 5. Set up remaining mounts (proc, sysfs, etc.) — these are inside the new root
    setup_mounts(spec)?;

    // 6. Create default devices
    setup_default_devices()?;

    // 7. Set up process attributes from spec
    if let Some(process) = spec.process() {
        // Set working directory
        if let Some(cwd) = process.cwd().to_str() {
            if !cwd.is_empty() {
                fs::create_dir_all(cwd).unwrap_or_default();
                std::env::set_current_dir(cwd)
                    .map_err(|e| other!("chdir {}: {}", cwd, e))?;
            }
        }

        // Set environment variables
        if let Some(env) = process.env() {
            for var in env {
                if let Some((key, value)) = var.split_once('=') {
                    std::env::set_var(key, value);
                }
            }
        }

        // Set rlimits
        if let Some(rlimits) = process.rlimits() {
            for rlimit in rlimits {
                let resource = match rlimit.typ() {
                    oci_spec::runtime::PosixRlimitType::RlimitNofile => libc::RLIMIT_NOFILE,
                    oci_spec::runtime::PosixRlimitType::RlimitNproc => libc::RLIMIT_NPROC,
                    oci_spec::runtime::PosixRlimitType::RlimitCore => libc::RLIMIT_CORE,
                    oci_spec::runtime::PosixRlimitType::RlimitFsize => libc::RLIMIT_FSIZE,
                    oci_spec::runtime::PosixRlimitType::RlimitMemlock => libc::RLIMIT_MEMLOCK,
                    oci_spec::runtime::PosixRlimitType::RlimitStack => libc::RLIMIT_STACK,
                    oci_spec::runtime::PosixRlimitType::RlimitAs => libc::RLIMIT_AS,
                    oci_spec::runtime::PosixRlimitType::RlimitCpu => libc::RLIMIT_CPU,
                    oci_spec::runtime::PosixRlimitType::RlimitData => libc::RLIMIT_DATA,
                    oci_spec::runtime::PosixRlimitType::RlimitLocks => libc::RLIMIT_LOCKS,
                    oci_spec::runtime::PosixRlimitType::RlimitMsgqueue => libc::RLIMIT_MSGQUEUE,
                    oci_spec::runtime::PosixRlimitType::RlimitNice => libc::RLIMIT_NICE,
                    oci_spec::runtime::PosixRlimitType::RlimitRss => libc::RLIMIT_RSS,
                    oci_spec::runtime::PosixRlimitType::RlimitRtprio => libc::RLIMIT_RTPRIO,
                    oci_spec::runtime::PosixRlimitType::RlimitRttime => libc::RLIMIT_RTTIME,
                    oci_spec::runtime::PosixRlimitType::RlimitSigpending => libc::RLIMIT_SIGPENDING,
                };
                let limit = libc::rlimit {
                    rlim_cur: rlimit.soft(),
                    rlim_max: rlimit.hard(),
                };
                let ret = unsafe { libc::setrlimit(resource, &limit) };
                if ret != 0 {
                    return Err(other!(
                        "setrlimit {:?}: {}",
                        rlimit.typ(),
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }
    }

    // 8. Signal parent that setup is complete
    let _ = nix::unistd::write(&ready_pipe_wr, b"R");
    drop(ready_pipe_wr);

    // 9. Block waiting for start signal
    let mut buf = [0u8; 1];
    let mut init_file = unsafe { fs::File::from_raw_fd(init_pipe_rd.as_raw_fd()) };
    std::mem::forget(init_pipe_rd);
    let _ = init_file.read_exact(&mut buf);

    // 10. Exec the container process
    exec_container_process(spec)?;

    // Should not reach here
    Ok(())
}

/// Exec the container's entrypoint process.
fn exec_container_process(spec: &Spec) -> Result<()> {
    let process = spec
        .process()
        .as_ref()
        .ok_or_else(|| other!("no process in spec"))?;

    let args = process
        .args()
        .as_ref()
        .ok_or_else(|| other!("no args in process spec"))?;

    if args.is_empty() {
        return Err(other!("empty args in process spec"));
    }

    let program = CString::new(args[0].as_str())
        .map_err(|e| other!("invalid program name: {}", e))?;
    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    // If the program is not an absolute path, search PATH
    nix::unistd::execvp(&program, &c_args)
        .map_err(|e| other!("execvp {}: {}", args[0], e))?;

    unreachable!()
}

/// Signal a container to start executing (write to start pipe).
pub fn start_container(start_pipe: &OwnedFd) -> Result<()> {
    nix::unistd::write(start_pipe, b"S")
        .map_err(|e| other!("write start signal: {}", e))?;
    Ok(())
}

/// Delete a container: kill all processes, clean up cgroup, unmount rootfs.
pub fn delete_container(pid: i32, rootfs: &Path, force: bool) -> Result<()> {
    if force && pid > 0 {
        // Kill the init process and all children via cgroup
        kill_container_processes(pid);
    }

    // Unmount rootfs (best effort)
    let _ = cleanup_rootfs(rootfs);

    Ok(())
}

/// Kill all processes in a container's cgroup, then the init process.
fn kill_container_processes(pid: i32) {
    // Try to read PIDs from cgroup
    if let Ok(cgroup_content) = fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        if let Some(cgroup_rel) = cgroup_content.lines().find_map(|line| {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                Some(parts[2].to_string())
            } else {
                None
            }
        }) {
            let procs_path = format!("/sys/fs/cgroup{}/cgroup.procs", cgroup_rel);
            if let Ok(procs) = fs::read_to_string(&procs_path) {
                for line in procs.lines() {
                    if let Ok(p) = line.trim().parse::<i32>() {
                        let _ = kill(Pid::from_raw(p), Signal::SIGKILL);
                    }
                }
            }

            // Clean up the cgroup directory
            let cgroup_dir = format!("/sys/fs/cgroup{}", cgroup_rel);
            let _ = fs::remove_dir(&cgroup_dir);
        }
    }

    // Also directly kill the init process
    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
}

/// Resolve the rootfs path from the bundle and OCI spec.
fn resolve_rootfs(bundle: &str, spec: &Spec) -> PathBuf {
    let root = spec.root().as_ref().map(|r| r.path().clone());
    match root {
        Some(p) if p.is_absolute() => p,
        Some(p) => Path::new(bundle).join(p),
        None => Path::new(bundle).join("rootfs"),
    }
}

/// Create a pipe, returning (read_end, write_end) as OwnedFd.
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        return Err(other!("pipe2: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(fds[0]),
            OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

