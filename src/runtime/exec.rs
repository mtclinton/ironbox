use std::{
    ffi::CString,
    fs,
    io::Read,
    os::unix::io::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

use containerd_shim::{other, Error, Result};
use log::debug;
use nix::sched::{setns, CloneFlags};
use oci_spec::runtime::Process;

/// Exec a new process inside an existing container's namespaces.
///
/// Forks a child, joins the container's namespaces via setns(2), then
/// execs the specified process. Returns the child PID.
pub fn exec_in_container(
    container_pid: i32,
    process: &Process,
    pid_file: Option<&Path>,
) -> Result<i32> {
    // Collect namespace fds before forking
    let ns_types = [
        ("ipc", CloneFlags::CLONE_NEWIPC),
        ("uts", CloneFlags::CLONE_NEWUTS),
        ("net", CloneFlags::CLONE_NEWNET),
        ("pid", CloneFlags::CLONE_NEWPID),
        ("mnt", CloneFlags::CLONE_NEWNS),
    ];

    // Open namespace fds
    let mut ns_fds: Vec<(std::fs::File, CloneFlags)> = Vec::new();
    for (name, flag) in &ns_types {
        let path = format!("/proc/{}/ns/{}", container_pid, name);
        if let Ok(f) = std::fs::File::open(&path) {
            ns_fds.push((f, *flag));
        }
    }

    // Create sync pipes
    let (err_rd, err_wr) = pipe()?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(other!("fork for exec failed: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        // === CHILD PROCESS ===
        drop(err_rd);

        let result = exec_child_setup(&ns_fds, process);
        if let Err(e) = result {
            let msg = format!("{}", e);
            let _ = nix::unistd::write(&err_wr, msg.as_bytes());
            drop(err_wr);
            unsafe { libc::_exit(1) };
        }
        unreachable!();
    }

    // === PARENT PROCESS ===
    drop(err_wr);
    drop(ns_fds);

    // Check for child setup errors
    let mut err_msg = String::new();
    let mut err_file = unsafe { fs::File::from_raw_fd(err_rd.as_raw_fd()) };
    std::mem::forget(err_rd);
    let _ = err_file.read_to_string(&mut err_msg);

    if !err_msg.is_empty() {
        return Err(other!("exec setup failed: {}", err_msg));
    }

    // Write PID file
    if let Some(path) = pid_file {
        fs::write(path, pid.to_string())
            .map_err(|e| other!("write exec pid file: {}", e))?;
    }

    debug!("exec_in_container: child pid={}", pid);

    Ok(pid)
}

/// Child process for exec: join namespaces and exec.
fn exec_child_setup(
    ns_fds: &[(std::fs::File, CloneFlags)],
    process: &Process,
) -> Result<()> {
    // Join each namespace
    for (fd, flag) in ns_fds {
        setns(fd, *flag)
            .map_err(|e| other!("setns {:?}: {}", flag, e))?;
    }

    // After joining PID namespace, fork again so the child is actually in the new PID namespace
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(other!("inner fork failed: {}", std::io::Error::last_os_error()));
    }
    if pid > 0 {
        // Middle process: wait for inner child
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            1
        };
        unsafe { libc::_exit(code) };
    }

    // === INNER CHILD (now in the container's PID namespace) ===

    // After setns(MNT), we're in the container's mount namespace.
    // The container's rootfs is at / — just chdir there.
    std::env::set_current_dir("/")
        .map_err(|e| other!("chdir /: {}", e))?;

    // Set working directory from process spec
    let cwd = process.cwd();
    if let Some(cwd_str) = cwd.to_str() {
        if !cwd_str.is_empty() {
            std::env::set_current_dir(cwd_str)
                .map_err(|e| other!("chdir {}: {}", cwd_str, e))?;
        }
    }

    // Set environment variables
    // First clear inherited env
    for (key, _) in std::env::vars() {
        std::env::remove_var(&key);
    }
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
                _ => continue,
            };
            let limit = libc::rlimit {
                rlim_cur: rlimit.soft(),
                rlim_max: rlimit.hard(),
            };
            unsafe { libc::setrlimit(resource, &limit) };
        }
    }

    // Exec
    let args = process
        .args()
        .as_ref()
        .ok_or_else(|| other!("no args in exec process spec"))?;

    if args.is_empty() {
        return Err(other!("empty args in exec process spec"));
    }

    let program = CString::new(args[0].as_str())
        .map_err(|e| other!("invalid program name: {}", e))?;
    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    nix::unistd::execvp(&program, &c_args)
        .map_err(|e| other!("execvp {}: {}", args[0], e))?;

    unreachable!()
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
