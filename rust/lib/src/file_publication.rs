//! Native namespace replacement for complete files staged on the same volume.
//! Callers own staging, cleanup and durability barriers.

use std::io;
use std::path::Path;

/// Publish a staged file, replacing the destination without closing its readers.
///
/// Existing readers retain their old snapshot; subsequent opens see the new
/// file. This operates inside an application-controlled storage tree and is not
/// a path authorization API. Successful replacement alone does not imply crash
/// durability. Unsupported filesystems/platform capabilities return their error.
pub fn replace_file(staged: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::replace_file(staged, destination)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(staged, destination)
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::mem::{offset_of, size_of};
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfoEx, SetFileInformationByHandle, DELETE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_RENAME_INFO,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
    };

    pub(super) fn replace_file(staged: &Path, destination: &Path) -> io::Result<()> {
        // Resolve the parent, not the destination: a first publication has no
        // destination yet. canonicalize also supplies Windows' long-path prefix.
        let name = destination.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "replacement needs a file name")
        })?;
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty());
        let destination = parent.unwrap_or(Path::new(".")).canonicalize()?.join(name);
        let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replacement path contains NUL",
            ));
        }
        let name_bytes = u32::try_from(name.len() * size_of::<u16>()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "replacement path too long")
        })?;
        let size = offset_of!(FILE_RENAME_INFO, FileName) + name_bytes as usize + size_of::<u16>();
        let size_u32 = u32::try_from(size).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "replacement path too long")
        })?;
        // The typed allocation supplies native struct alignment and enough
        // trailing storage for the variable-length UTF-16 name plus its NUL.
        let mut buffer =
            vec![FILE_RENAME_INFO::default(); size.div_ceil(size_of::<FILE_RENAME_INFO>())];
        let info = buffer.as_mut_ptr();
        let file = std::fs::OpenOptions::new()
            .access_mode(DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(staged)?;
        // Do not begin with MoveFileExW: Rust's std::fs::rename only selects
        // POSIX replacement as a fallback. Concurrent readers need the same
        // namespace semantics on every replacement, including the first try.
        // SAFETY: buffer is aligned, initialized and large enough for all
        // fields and name bytes. Both it and the owned file outlive the call.
        let result = unsafe {
            (*info).Anonymous.Flags =
                FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
            (*info).FileNameLength = name_bytes;
            name.as_ptr().copy_to_nonoverlapping(
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileRenameInfoEx,
                info.cast(),
                size_u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
