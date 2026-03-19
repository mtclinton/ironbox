use std::fs;
use std::path::Path;

use containerd_shim::{other, Error, Result};
use log::debug;
use oci_spec::runtime::Spec;

/// Apply SELinux process label from the OCI spec.
///
/// Writes the label to /proc/self/attr/exec so that the next exec
/// transitions to the specified SELinux context.
pub fn apply_selinux(spec: &Spec) -> Result<()> {
    let process = match spec.process() {
        Some(p) => p,
        None => return Ok(()),
    };

    let label = match process.selinux_label() {
        Some(l) if !l.is_empty() => l,
        _ => return Ok(()),
    };

    // Check if SELinux is available and enforcing
    if !Path::new("/sys/fs/selinux").exists() {
        debug!("SELinux not available, skipping label {}", label);
        return Ok(());
    }

    // Write the label to /proc/self/attr/exec
    let path = "/proc/self/attr/exec";
    fs::write(path, label)
        .map_err(|e| other!("set SELinux label '{}' via {}: {}", label, path, e))?;

    debug!("SELinux label set to '{}'", label);
    Ok(())
}
