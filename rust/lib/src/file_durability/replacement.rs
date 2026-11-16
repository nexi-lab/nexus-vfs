use std::io;
use std::path::Path;

/// Publish a staged file over its destination without invalidating open readers.
///
/// Callers stage on the destination filesystem and synchronize contents before
/// replacement and the parent directory afterward when durability requires it.
/// Windows must support `FileRenameInfoEx` POSIX replacement; an unsupported
/// filesystem or genuine sharing/permission refusal remains an error. Never
/// fall back to delete-pending replacement, which can deny concurrent opens.
pub fn replace_file(staged: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        std::fs::rename(staged, destination)
    }
    #[cfg(windows)]
    {
        replace_windows(staged, destination)
    }
}

#[cfg(windows)]
fn replace_windows(staged: &Path, destination: &Path) -> io::Result<()> {
    use std::mem::{offset_of, size_of, MaybeUninit};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfoEx, SetFileInformationByHandle, DELETE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_RENAME_INFO, FILE_RENAME_INFO_0,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
    };

    let destination = std::path::absolute(destination)?;
    let mut name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    if name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement destination contains a null character",
        ));
    }
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replacement path too long"))?;
    let buffer_bytes = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes as usize)
        .and_then(|bytes| bytes.checked_add(size_of::<u16>()))
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replacement path too long"))?;
    // Win32 consumes a NUL-terminated FileName, even though FileNameLength
    // excludes that terminator. Struct-alignment padding is not guaranteed.
    name.push(0);
    // Whole struct elements provide the native alignment and enough trailing
    // storage for both FileName's counted UTF-16 sequence and its terminator.
    let elements = (buffer_bytes as usize).div_ceil(size_of::<FILE_RENAME_INFO>());
    let mut storage = vec![MaybeUninit::<FILE_RENAME_INFO>::zeroed(); elements];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let file = std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(staged)?;
    // SAFETY: storage is aligned for FILE_RENAME_INFO and includes every byte
    // in the counted name and its terminator. The source handle remains owned through the call;
    // Windows reads this initialized buffer synchronously and retains no pointer.
    let result = unsafe {
        (&raw mut (*info).Anonymous).write(FILE_RENAME_INFO_0 {
            Flags: FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS,
        });
        (&raw mut (*info).RootDirectory).write(std::ptr::null_mut());
        (&raw mut (*info).FileNameLength).write(name_bytes);
        name.as_ptr()
            .copy_to_nonoverlapping((&raw mut (*info).FileName).cast::<u16>(), name.len());
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            info.cast(),
            buffer_bytes,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
