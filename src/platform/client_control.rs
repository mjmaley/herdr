//! Security policy for client-owned control endpoints, separate from shared IPC.

use std::fs;
use std::io;
use std::path::Path;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::validate_client_control_peer;

pub(crate) fn prepare_client_control_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_client_control_directory(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        // Existing state directories need not be private; the control directory
        // is the access boundary. Never follow an existing symlink when creating
        // the missing portion of that boundary.
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() => validate_ancestors(path)?,
            Ok(_) => {
                return Err(denied(
                    "client control parent must be a directory, not a symlink",
                ))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                prepare_client_control_directory(parent)?;
            }
            Err(err) => return Err(err),
        }
    }
    match create_private_directory(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err),
    }
    validate_client_control_directory(path)
}

pub(crate) fn validate_client_control_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_ancestors(path)?;
    if !metadata.is_dir() || !private_path(path, &metadata)? {
        return Err(denied(
            "client control directory must be user-owned, private, and not a symlink",
        ));
    }
    Ok(())
}

pub(crate) fn validate_client_control_socket(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| denied("client control socket requires a private directory"))?;
    validate_client_control_directory(parent)?;
    let metadata = fs::symlink_metadata(path)?;
    if !socket_metadata(&metadata) || !private_path(path, &metadata)? {
        return Err(denied(
            "client control endpoint must be user-owned, private, and not a symlink",
        ));
    }
    Ok(())
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn validate_ancestors(path: &Path) -> io::Result<()> {
    // A private leaf is not sufficient if another user can rename its parent.
    // Ancestors may allow public read/search access, but their ownership and
    // permissions must protect the control boundary from replacement.
    let absolute = std::path::absolute(path)?;
    for parent in absolute.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || !trusted_ancestor(parent, &metadata)? {
            return Err(denied(
                "client control ancestors must be trusted directories, not symlinks",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_ancestor(_path: &Path, metadata: &fs::Metadata) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    // SAFETY: geteuid takes no pointers and has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    Ok((metadata.uid() == uid || metadata.uid() == 0)
        && (metadata.mode() & 0o022 == 0 || root_sticky))
}

#[cfg(windows)]
fn trusted_ancestor(path: &Path, _metadata: &fs::Metadata) -> io::Result<bool> {
    windows::trusted_ancestor(path)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    super::windows::create_remote_private_dir(path)
}

#[cfg(unix)]
fn private_path(_path: &Path, metadata: &fs::Metadata) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    // SAFETY: geteuid takes no pointers and has no preconditions.
    Ok(metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0)
}

#[cfg(windows)]
fn private_path(path: &Path, _metadata: &fs::Metadata) -> io::Result<bool> {
    windows::private_path(path)
}

#[cfg(unix)]
fn socket_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    metadata.file_type().is_socket()
}

#[cfg(windows)]
fn socket_metadata(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}
