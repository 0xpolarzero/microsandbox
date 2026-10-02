//! Pin caller-supplied host paths before a local sandbox is persisted or launched.

use std::path::PathBuf;

use microsandbox_types::{Patch, RootDisk, RootfsSource, VolumeMount};

use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig, snapshot::SnapshotReference};

#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve local inputs once, before creation yields or saves its configuration.
///
/// Keep this at the local backend boundary: cloud paths belong to the remote host,
/// and callers can bypass `SandboxBuilder` by supplying a `SandboxConfig` directly.
/// Do not call this when reopening existing saved state: legacy relative paths keep
/// their previous interpretation and must not be rewritten during restart.
pub(crate) fn resolve_host_paths(config: &mut SandboxConfig) -> MicrosandboxResult<()> {
    // Restore sources are operation-only paths too. They can be consumed after
    // snapshot preparation or a background task has yielded.
    if !config.local_restore_paths_resolved {
        if let Some(reference) = &mut config.snapshot_reference {
            resolve_snapshot_reference(reference)?;
        }
        if let Some(path) = &mut config.snapshot_archive_source {
            *path = std::path::absolute(&*path)?;
        }
        if let Some(base) = &mut config.snapshot_base {
            let mut reference = SnapshotReference::auto(&*base);
            resolve_snapshot_reference(&mut reference)?;
            if let SnapshotReference::Auto(value) = reference {
                *base = value;
            }
        }
        config.local_restore_paths_resolved = true;
    }
    visit_host_paths(config, true, |path, label| {
        if !path.is_absolute() {
            // `absolute` anchors the path without following symlinks or requiring
            // the target to exist. Canonicalizing here would bypass bind mounts'
            // default refusal to follow symlinks in caller-supplied components.
            *path = std::path::absolute(&*path).map_err(|error| {
                MicrosandboxError::InvalidConfig(format!(
                    "cannot resolve {label} {}: {error}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    })?;
    check_bind_roots_do_not_follow_symlinks(config)
}

/// Report a symlinked bind mount root now instead of when the sandbox boots.
///
/// The runtime opens a bind mount root without following symlinks in any
/// component, including the last, unless `follow_root_symlinks` is set. Mirror
/// that check here so creation fails with an actionable error before the sandbox
/// is persisted. File binds are canonicalized by `SingleFileFs` and are not
/// subject to it. The runtime enforces the policy itself; this only explains it.
#[cfg(unix)]
fn check_bind_roots_do_not_follow_symlinks(config: &SandboxConfig) -> MicrosandboxResult<()> {
    for mount in &config.spec.mounts {
        let VolumeMount::Bind {
            host,
            follow_root_symlinks: false,
            ..
        } = mount
        else {
            continue;
        };
        if host.is_file() {
            continue;
        }
        let mut current = PathBuf::new();
        for component in host.components() {
            current.push(component);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let message = if current == *host {
                        format!("bind mount host path {} is a symlink", host.display())
                    } else {
                        format!(
                            "bind mount host path {} goes through symlink {}",
                            host.display(),
                            current.display()
                        )
                    };
                    let fix = match (std::fs::canonicalize(&current), std::fs::canonicalize(host)) {
                        (Err(_), _) => "whose target does not exist".to_string(),
                        (Ok(_), Ok(path)) => format!(
                            "use the resolved path {} or add follow-root-symlinks",
                            path.display()
                        ),
                        (Ok(_), Err(_)) => "add follow-root-symlinks".to_string(),
                    };
                    let separator = if fix.starts_with("whose") { ", " } else { "; " };
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "{message}{separator}{fix}"
                    )));
                }
                Ok(_) => {}
                // A missing or unreadable component is still reported at start.
                Err(_) => break,
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_bind_roots_do_not_follow_symlinks(_config: &SandboxConfig) -> MicrosandboxResult<()> {
    Ok(())
}

/// Capture explicit builder inputs without turning omitted settings into overrides.
/// The temporary value only feeds the common path visitor; copy back path-bearing
/// fields that were present, retaining sparse layer and managed-policy semantics.
pub(crate) fn resolve_patch_paths(patch: &mut crate::SandboxConfigPatch) -> MicrosandboxResult<()> {
    let mut config = patch.clone().into_config();
    resolve_host_paths(&mut config)?;
    if patch.spec.image.is_some() {
        patch.spec.image = Some(config.spec.image);
    }
    if patch.spec.mounts.is_some() {
        patch.spec.mounts = Some(config.spec.mounts);
    }
    if patch.spec.patches.is_some() {
        patch.spec.patches = Some(config.spec.patches);
    }
    if let Some(tls) = &mut patch.spec.network.tls
        && let Some(resolved) = config.spec.network.tls
    {
        if tls.upstream_ca_cert.is_some() {
            tls.upstream_ca_cert = Some(resolved.upstream_ca_cert);
        }
        if tls.scoped_upstream_ca_cert.is_some() {
            tls.scoped_upstream_ca_cert = Some(resolved.scoped_upstream_ca_cert);
        }
        if tls.intercept_ca.is_some() {
            tls.intercept_ca = Some(resolved.intercept_ca);
        }
    }
    patch.snapshot_reference = config.snapshot_reference;
    patch.snapshot_archive_source = config.snapshot_archive_source;
    patch.snapshot_base = config.snapshot_base;
    patch.local_restore_paths_resolved = Some(true);
    Ok(())
}

/// Capture explicit paths and path-shaped selectors without rebasing names or IDs.
pub(crate) fn resolve_snapshot_reference(
    reference: &mut SnapshotReference,
) -> MicrosandboxResult<()> {
    let value = match reference {
        SnapshotReference::Path(value) => {
            if value.is_empty() {
                return Err(MicrosandboxError::InvalidConfig(
                    "snapshot path or name must not be empty".into(),
                ));
            }
            value
        }
        SnapshotReference::Auto(value)
            if super::snapshot::looks_like_path(value) || std::path::Path::new(value).is_file() =>
        {
            value
        }
        SnapshotReference::Auto(_) | SnapshotReference::Id(_) => return Ok(()),
    };
    *value = std::path::absolute(&*value)?.to_string_lossy().into_owned();
    Ok(())
}

/// Enumerate host inputs explicitly so guest paths and resource names stay untouched.
fn visit_host_paths(
    config: &mut SandboxConfig,
    include_patch_sources: bool,
    mut visit: impl FnMut(&mut PathBuf, &str) -> MicrosandboxResult<()>,
) -> MicrosandboxResult<()> {
    match &mut config.spec.image {
        RootfsSource::Bind { path, .. } => visit(path, "bind rootfs path")?,
        RootfsSource::DiskImage { path, .. } => visit(path, "root disk image path")?,
        RootfsSource::Oci(oci) => match &mut oci.root_disk {
            Some(RootDisk::DiskImage { path, .. }) => visit(path, "OCI root disk image path")?,
            Some(RootDisk::Managed { .. } | RootDisk::Tmpfs { .. } | RootDisk::Flat { .. })
            | None => {}
        },
    }

    for mount in &mut config.spec.mounts {
        match mount {
            VolumeMount::Bind { host, .. } => visit(host, "bind mount host path")?,
            VolumeMount::DiskImage { host, .. } => visit(host, "disk mount host path")?,
            VolumeMount::Owned { .. } | VolumeMount::Named { .. } | VolumeMount::Tmpfs { .. } => {}
        }
    }

    // Patch sources can be read after an image pull has yielded. They share the
    // creation directory even though patches are only applied during creation.
    if include_patch_sources {
        for patch in &mut config.spec.patches {
            match patch {
                Patch::CopyFile { src, .. } | Patch::CopyDir { src, .. } => {
                    visit(src, "patch source path")?;
                }
                Patch::Text { .. }
                | Patch::File { .. }
                | Patch::Symlink { .. }
                | Patch::Mkdir { .. }
                | Patch::Remove { .. }
                | Patch::Append { .. } => {}
            }
        }
    }

    // TLS files are reopened on every boot too. A different cwd must not select
    // a different trust store or interception identity for the same sandbox.
    if let Some(tls) = &mut config.spec.network.tls {
        for path in &mut tls.upstream_ca_cert {
            visit(path, "upstream CA certificate path")?;
        }
        for scoped in &mut tls.scoped_upstream_ca_cert {
            visit(&mut scoped.path, "scoped upstream CA certificate path")?;
        }
        if let Some(path) = &mut tls.intercept_ca.cert_path {
            visit(path, "interception CA certificate path")?;
        }
        if let Some(path) = &mut tls.intercept_ca.key_path {
            visit(path, "interception CA key path")?;
        }
    }
    Ok(())
}
