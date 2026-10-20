use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, WRITE_DAC,
};

// OW resolves to the file's owner. P protects the DACL from broader parent
// permissions, including Users and Authenticated Users grants on a data root.
const OWNER_ONLY: &str = "D:P(A;;FA;;;OW)";

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor is allocated by the SDDL conversion API and
        // owned exclusively by this guard until it is freed with LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

pub(super) fn open_owner_only(path: &Path) -> io::Result<File> {
    let descriptor = security_descriptor(OWNER_ONLY)?;
    let file = create_with_descriptor(path, &descriptor)?;
    // CreateFile ignores its security descriptor for an EXISTING file. Tighten
    // that file on the same handle before new bytes are written, too.
    set_dacl(&file, OWNER_ONLY)?;
    Ok(file)
}

fn create_with_descriptor(path: &Path, descriptor: &SecurityDescriptor) -> io::Result<File> {
    // Resolve relative paths before using the verbatim prefix, retaining long
    // Unicode paths without requiring a longPathAware executable manifest.
    let absolute = std::path::absolute(path)?;
    let mut wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in secret path",
        ));
    }
    if !wide.starts_with(&[92, 92, 63, 92]) {
        let prefix = if wide.starts_with(&[92, 92]) {
            wide.drain(..2);
            r"\\?\UNC\"
        } else {
            r"\\?\"
        };
        wide = prefix.encode_utf16().chain(wide).collect();
    }
    wide.push(0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: wide is NUL-terminated, and attributes and its descriptor remain
    // live through this synchronous call. New files are private AT CREATION:
    // inheriting a broad DACL then repairing it lets another user open and keep
    // a readable handle during that gap, even if bytes are written only later.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFile returned a new, exclusively owned valid handle. File
    // now owns closing it, including when the later permission repair fails.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn security_descriptor(sddl: &str) -> io::Result<SecurityDescriptor> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: wide is a live NUL-terminated string and descriptor points to a
    // writable output slot. Successful conversion transfers an allocation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(SecurityDescriptor(descriptor))
}

fn set_dacl(file: &File, sddl: &str) -> io::Result<()> {
    let descriptor = security_descriptor(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    // SAFETY: descriptor is valid and all output pointers reference live slots.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // A NULL DACL grants everyone full access. Reject it before setting one.
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret DACL is missing",
        ));
    }
    // SAFETY: file owns the live handle with WRITE_DAC; dacl is borrowed from
    // descriptor, which remains alive throughout the synchronous call.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, SE_DACL_PROTECTED};

    fn protected_dacl(path: &Path) -> (bool, String) {
        let file = File::open(path).unwrap();
        let mut descriptor = ptr::null_mut();
        // SAFETY: file has READ_CONTROL and descriptor is a writable output.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        let descriptor = SecurityDescriptor(descriptor);
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: descriptor is valid and the output slots remain live.
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        let mut text = ptr::null_mut();
        let mut length = 0;
        // SAFETY: descriptor is valid; text and length are live output slots.
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor.0,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    &mut length,
                )
            },
            0
        );
        // SAFETY: the API returns an allocation of length UTF-16 code units.
        // Read only through the first NUL, including when Windows reports a
        // larger output buffer than the text it actually formatted.
        let value = unsafe {
            let wide = std::slice::from_raw_parts(text, length as usize);
            let end = wide
                .iter()
                .position(|unit| *unit == 0)
                .expect("SDDL terminator");
            String::from_utf16_lossy(&wide[..end])
        };
        // SAFETY: the API allocates text with LocalAlloc; it is no longer used.
        unsafe { LocalFree(text.cast()) };
        // Windows may retain the informational AI (auto-inherited) control
        // flag after protecting a DACL. Assert the protection bit itself and
        // the exact ACE list rather than that incidental SDDL representation.
        let entries = value[value.find('(').expect("DACL must contain an ACE")..].to_string();
        (control & SE_DACL_PROTECTED != 0, entries)
    }

    #[test]
    fn a_new_file_is_private_before_any_permission_repair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret-\u{79d8}\u{5bc6}");
        let descriptor = security_descriptor(OWNER_ONLY).unwrap();
        let file = create_with_descriptor(&path, &descriptor).unwrap();
        assert_eq!(protected_dacl(&path), (true, "(A;;FA;;;OW)".into()));
        drop(file);
    }

    #[test]
    fn long_secret_paths_keep_the_owner_only_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("a".repeat(120)).join("b".repeat(120));
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("secret.pem");
        crate::transport_primitives::write_secret(&path, b"key").unwrap();
        assert_eq!(protected_dacl(&path), (true, "(A;;FA;;;OW)".into()));
        assert_eq!(std::fs::read(path).unwrap(), b"key");
    }

    #[test]
    fn new_secret_has_a_protected_owner_only_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        crate::transport_primitives::write_secret(&path, b"key").unwrap();
        assert_eq!(protected_dacl(&path), (true, "(A;;FA;;;OW)".into()));
        assert_eq!(std::fs::read(&path).unwrap(), b"key");
    }

    #[test]
    fn rewriting_a_world_readable_secret_removes_broad_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE | WRITE_DAC)
            .open(&path)
            .unwrap();
        set_dacl(&file, "D:P(A;;FA;;;WD)").unwrap();
        std::io::Write::write_all(&mut file, b"old").unwrap();
        drop(file);
        assert_eq!(protected_dacl(&path), (true, "(A;;FA;;;WD)".into()));

        crate::transport_primitives::write_secret(&path, b"new").unwrap();
        assert_eq!(protected_dacl(&path), (true, "(A;;FA;;;OW)".into()));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }
}
