use std::fs::File;

use containerd_shim::{other, Error, Result};
use nix::sched::{unshare, CloneFlags};
use oci_spec::runtime::{LinuxNamespaceType, Spec};

/// Map OCI namespace types to Linux clone flags.
fn namespace_to_clone_flag(ns_type: &LinuxNamespaceType) -> CloneFlags {
    match ns_type {
        LinuxNamespaceType::Pid => CloneFlags::CLONE_NEWPID,
        LinuxNamespaceType::Network => CloneFlags::CLONE_NEWNET,
        LinuxNamespaceType::Mount => CloneFlags::CLONE_NEWNS,
        LinuxNamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
        LinuxNamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
        LinuxNamespaceType::User => CloneFlags::CLONE_NEWUSER,
        LinuxNamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        LinuxNamespaceType::Time => CloneFlags::empty(), // not widely supported
    }
}

/// Map OCI namespace type to /proc/<pid>/ns/<name>.
fn namespace_to_proc_name(ns_type: &LinuxNamespaceType) -> &'static str {
    match ns_type {
        LinuxNamespaceType::Pid => "pid",
        LinuxNamespaceType::Network => "net",
        LinuxNamespaceType::Mount => "mnt",
        LinuxNamespaceType::Ipc => "ipc",
        LinuxNamespaceType::Uts => "uts",
        LinuxNamespaceType::User => "user",
        LinuxNamespaceType::Cgroup => "cgroup",
        LinuxNamespaceType::Time => "time",
    }
}

/// Call unshare(2) for all namespaces specified in the OCI spec that don't have a path
/// (i.e., namespaces we create fresh rather than join).
pub fn setup_namespaces(spec: &Spec) -> Result<()> {
    let linux = spec
        .linux()
        .as_ref()
        .ok_or_else(|| other!("no linux config in spec"))?;

    let namespaces = match linux.namespaces() {
        Some(ns) => ns,
        None => return Ok(()),
    };

    let mut flags = CloneFlags::empty();
    for ns in namespaces {
        // Only unshare namespaces that don't have a path (fresh namespaces).
        // Namespaces with a path will be joined via setns() separately.
        if ns.path().is_none() {
            flags |= namespace_to_clone_flag(&ns.typ());
        }
    }

    if !flags.is_empty() {
        unshare(flags).map_err(|e| other!("unshare failed: {}", e))?;
    }

    Ok(())
}

/// Join existing namespaces specified in the OCI spec that have a path.
pub fn join_namespaces(spec: &Spec) -> Result<()> {
    let linux = spec
        .linux()
        .as_ref()
        .ok_or_else(|| other!("no linux config in spec"))?;

    let namespaces = match linux.namespaces() {
        Some(ns) => ns,
        None => return Ok(()),
    };

    for ns in namespaces {
        if let Some(path) = ns.path() {
            let f = File::open(path)
                .map_err(|e| other!("open namespace {}: {}", path.display(), e))?;
            let flag = namespace_to_clone_flag(&ns.typ());
            nix::sched::setns(&f, flag)
                .map_err(|e| other!("setns {:?}: {}", ns.typ(), e))?;
        }
    }

    Ok(())
}

/// Enter all namespaces of an existing container process.
/// Used for exec operations.
pub fn enter_namespaces(pid: i32, ns_types: &[LinuxNamespaceType]) -> Result<()> {
    for ns_type in ns_types {
        let ns_name = namespace_to_proc_name(ns_type);
        let ns_path = format!("/proc/{}/ns/{}", pid, ns_name);
        let f = File::open(&ns_path)
            .map_err(|e| other!("open namespace {}: {}", ns_path, e))?;
        let flag = namespace_to_clone_flag(ns_type);
        nix::sched::setns(&f, flag)
            .map_err(|e| other!("setns {} for pid {}: {}", ns_name, pid, e))?;
    }
    Ok(())
}
