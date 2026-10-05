//! Windows control-boundary policy. Metadata attributes only detect reparse
//! points; ownership and access are checked against the kernel object's DACL.

use std::{
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{
        fs::OpenOptionsExt as _,
        io::{AsHandle as _, AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    path::Path,
    ptr::{null_mut, read_unaligned},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER, GENERIC_ALL, GENERIC_WRITE, HANDLE},
    Security::{
        Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, GetTokenInformation, IsValidAcl, IsValidSid, IsWellKnownSid, TokenUser,
        WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Principal {
    User,
    System,
    Administrators,
    TrustedInstaller,
    OwnerRights,
    Foreign,
}

#[derive(Clone, Copy)]
enum Boundary {
    Private,
    Ancestor,
}

impl Boundary {
    fn trusts_owner(self, principal: Principal) -> bool {
        match self {
            Self::Private => principal == Principal::User,
            Self::Ancestor => matches!(
                principal,
                Principal::User
                    | Principal::System
                    | Principal::Administrators
                    | Principal::TrustedInstaller
            ),
        }
    }

    fn allows_ace(self, principal: Principal, mask: u32) -> bool {
        let trusted = match self {
            Self::Private => matches!(
                principal,
                Principal::User | Principal::System | Principal::OwnerRights
            ),
            Self::Ancestor => principal != Principal::Foreign,
        };
        if trusted {
            return true;
        }
        match self {
            Self::Private => mask == 0,
            // Public search/read and create-subdirectory rights are compatible
            // with normal volume/profile ancestors. Replacement, reparse-point
            // writes and permission changes are not. In particular, a parent's
            // DELETE_CHILD bypasses even a private child's DACL.
            Self::Ancestor => {
                mask & (DELETE
                    | FILE_DELETE_CHILD
                    | WRITE_DAC
                    | WRITE_OWNER
                    | FILE_WRITE_DATA
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | GENERIC_WRITE
                    | GENERIC_ALL)
                    == 0
            }
        }
    }
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: both GetSecurityInfo and ConvertStringSidToSidW allocate with
        // LocalAlloc; this wrapper is their sole owner.
        unsafe { LocalFree(self.0) };
    }
}

struct Security {
    _allocation: LocalAllocation,
    owner: PSID,
    dacl: *mut ACL,
}

impl Security {
    fn query(handle: HANDLE, with_dacl: bool) -> io::Result<Self> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let flags = OWNER_SECURITY_INFORMATION
            | if with_dacl {
                DACL_SECURITY_INFORMATION
            } else {
                0
            };
        // SAFETY: handle is borrowed from a live object, output pointers are
        // valid, and the returned descriptor owns the SID/ACL storage.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                flags,
                &mut owner,
                null_mut(),
                if with_dacl { &mut dacl } else { null_mut() },
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let security = Self {
            _allocation: LocalAllocation(descriptor),
            owner,
            dacl,
        };
        if security.owner.is_null() || unsafe { IsValidSid(security.owner) } == 0 {
            return Err(super::denied("client control object has no valid owner"));
        }
        Ok(security)
    }
}

// Pointer-aligned storage for TOKEN_USER and its trailing SID. The returned SID
// borrows this allocation, never a closed process/token handle.
struct TokenUserBuffer(Vec<usize>);

impl TokenUserBuffer {
    fn query(process: HANDLE) -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: process is a live process handle; token is a valid out pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken returned an owned handle, closed exactly once.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut needed = 0;
        let result = unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed)
        };
        if result != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || needed < size_of::<TOKEN_USER>() as u32
        {
            return Err(super::denied("could not obtain the process account"));
        }
        let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        // SAFETY: storage has the requested size and TOKEN_USER alignment.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(storage))
    }

    fn sid(&self) -> PSID {
        // SAFETY: query populated aligned TOKEN_USER storage and the SID points
        // into that allocation, which remains alive for this borrow.
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

struct Identity {
    user: TokenUserBuffer,
    trusted_installer: LocalAllocation,
}

impl Identity {
    fn current() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns a valid non-owned pseudo-handle.
        let user = TokenUserBuffer::query(unsafe { GetCurrentProcess() })?;
        // The fixed Windows Modules Installer service SID, not a display name
        // (which could be localized or resolved to a foreign account).
        let text = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            user,
            trusted_installer: LocalAllocation(sid),
        })
    }

    fn classify(&self, sid: PSID) -> Principal {
        // SAFETY: callers supply a validated descriptor SID or a bounded ACE
        // SID; all comparison SID allocations remain live.
        unsafe {
            if EqualSid(sid, self.user.sid()) != 0 {
                Principal::User
            } else if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                Principal::System
            } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                Principal::Administrators
            } else if EqualSid(sid, self.trusted_installer.0) != 0 {
                Principal::TrustedInstaller
            } else if IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0 {
                Principal::OwnerRights
            } else {
                Principal::Foreign
            }
        }
    }
}

fn validate_path(path: &Path, boundary: Boundary) -> io::Result<bool> {
    // OPEN_REPARSE_POINT ensures that security is read from the entry itself,
    // not a junction's target. BACKUP_SEMANTICS permits directory handles.
    let file: File = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    use std::os::windows::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(false);
    }
    let identity = Identity::current()?;
    let security = Security::query(file.as_raw_handle(), true)?;
    if !boundary.trusts_owner(identity.classify(security.owner)) || security.dacl.is_null() {
        // A NULL/absent DACL grants everyone full access, unlike an empty DACL.
        return Ok(false);
    }
    // SAFETY: GetSecurityInfo returned the ACL inside its live allocation.
    if unsafe { IsValidAcl(security.dacl) } == 0 {
        return Ok(false);
    }
    let count = unsafe { (*security.dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace = null_mut();
        if unsafe { GetAce(security.dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce supplies a header in a validated ACL. Read unaligned
        // because the ABI does not guarantee Rust reference alignment here.
        let header = unsafe { read_unaligned(ace.cast::<ACE_HEADER>()) };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            || u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
        {
            continue;
        }
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            // Object/callback/conditional grants are not equivalent to a plain
            // allow ACE. Fail closed rather than accidentally ignoring a grant.
            return Ok(false);
        }
        let offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if usize::from(header.AceSize) < offset + 8 {
            return Ok(false);
        }
        let bytes = ace.cast::<u8>();
        let sid = unsafe { bytes.add(offset) };
        // Bound the variable-sized SID before handing it to any Win32 SID API.
        let sid_length = 8 + 4 * usize::from(unsafe { *sid.add(1) });
        if offset + sid_length > usize::from(header.AceSize)
            || unsafe { IsValidSid(sid.cast()) } == 0
        {
            return Ok(false);
        }
        let mask = unsafe {
            read_unaligned(
                bytes
                    .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                    .cast::<u32>(),
            )
        };
        if !boundary.allows_ace(identity.classify(sid.cast()), mask) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn private_path(path: &Path) -> io::Result<bool> {
    validate_path(path, Boundary::Private)
}

pub(super) fn trusted_ancestor(path: &Path) -> io::Result<bool> {
    validate_path(path, Boundary::Ancestor)
}

pub(crate) fn validate_client_control_peer(stream: &crate::ipc::LocalStream) -> io::Result<()> {
    let crate::ipc::LocalStream::NamedPipe(pipe) = stream;
    let handle = pipe.as_handle().as_raw_handle();
    let identity = Identity::current()?;
    // Authenticate the connected kernel pipe, not its discovery marker. This
    // owner check is load-bearing: Windows/interprocess peer credentials supply
    // only a reusable PID, not a connection-bound account SID. A foreign account
    // cannot create a current-user-owned pipe without administrative privilege.
    let security = Security::query(handle, false)?;
    if identity.classify(security.owner) != Principal::User {
        return Err(super::denied(
            "client control named pipe is not owned by the current user",
        ));
    }
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(handle, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess returned an owned handle; keep it pinned throughout
    // the token query and the second lookup rather than authenticating by PID.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let server = TokenUserBuffer::query(process.as_raw_handle())?;
    let mut confirmed_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(handle, &mut confirmed_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if confirmed_pid != pid || identity.classify(server.sid()) != Principal::User {
        return Err(super::denied(
            "client control named pipe server is not the current user",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{FILE_APPEND_DATA, FILE_READ_DATA};

    #[test]
    fn private_boundary_requires_user_ownership_and_private_grants() {
        assert!(Boundary::Private.trusts_owner(Principal::User));
        for principal in [
            Principal::System,
            Principal::Administrators,
            Principal::TrustedInstaller,
            Principal::OwnerRights,
            Principal::Foreign,
        ] {
            assert!(!Boundary::Private.trusts_owner(principal));
        }
        for principal in [Principal::User, Principal::System, Principal::OwnerRights] {
            assert!(Boundary::Private.allows_ace(principal, GENERIC_ALL));
        }
        for principal in [
            Principal::Administrators,
            Principal::TrustedInstaller,
            Principal::Foreign,
        ] {
            assert!(!Boundary::Private.allows_ace(principal, GENERIC_READ));
            assert!(!Boundary::Private.allows_ace(principal, FILE_READ_DATA));
            assert!(!Boundary::Private.allows_ace(principal, WRITE_DAC));
        }
    }

    #[test]
    fn ancestors_accept_system_profile_owners_but_never_foreign_owners() {
        for principal in [
            Principal::User,
            Principal::System,
            Principal::Administrators,
            Principal::TrustedInstaller,
        ] {
            assert!(Boundary::Ancestor.trusts_owner(principal));
            assert!(Boundary::Ancestor.allows_ace(principal, GENERIC_ALL));
        }
        assert!(!Boundary::Ancestor.trusts_owner(Principal::Foreign));
        assert!(!Boundary::Ancestor.trusts_owner(Principal::OwnerRights));
    }

    #[test]
    fn ancestor_public_access_must_not_replace_the_boundary() {
        assert!(Boundary::Ancestor.allows_ace(Principal::Foreign, GENERIC_READ | FILE_APPEND_DATA));
        for mask in [
            DELETE,
            FILE_DELETE_CHILD,
            WRITE_DAC,
            WRITE_OWNER,
            FILE_WRITE_DATA,
            FILE_WRITE_EA,
            FILE_WRITE_ATTRIBUTES,
            GENERIC_WRITE,
            GENERIC_ALL,
        ] {
            assert!(!Boundary::Ancestor.allows_ace(Principal::Foreign, mask));
            assert!(!Boundary::Ancestor.allows_ace(Principal::Foreign, mask | GENERIC_READ));
        }
    }
}
