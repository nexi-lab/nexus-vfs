//! The open-file limit a node runs with.
//!
//! A node holds a socket for every peer and client stream, its stores' files and
//! each runtime's event queue, and a restart is when it needs the most at once:
//! every agent and bridge on the host reconnects together. launchd starts a
//! process with a soft limit of 256, which is below that peak. A Mac node's first
//! start after an upgrade panicked building its kernel runtime with "Too many
//! open files" (EMFILE), and launchd's retry nine seconds later came up. The
//! steady state is about 90 descriptors.
//!
//! The soft limit is a per-process default the process may raise up to the
//! hard limit, so the daemon raises it itself instead of depending on how each
//! host's supervisor is configured.

/// Raise this process's open-file soft limit to the most the system allows: the
/// hard limit, which on macOS is further capped by `kern.maxfilesperproc` (a soft
/// limit above it, or `RLIM_INFINITY`, is refused there). Returns the limits
/// before and after, or why it could not.
#[cfg(unix)]
pub fn raise_open_file_limit() -> Result<(libc::rlim_t, libc::rlim_t), String> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(format!("getrlimit: {}", std::io::Error::last_os_error()));
    }
    let before = limit.rlim_cur;
    let target = system_ceiling(limit.rlim_max);
    if target <= before {
        return Ok((before, before));
    }
    limit.rlim_cur = target;
    // SAFETY: `limit` is a valid rlimit; setrlimit only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(format!(
            "setrlimit {before} -> {target}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((before, target))
}

#[cfg(all(unix, target_os = "macos"))]
fn system_ceiling(hard: libc::rlim_t) -> libc::rlim_t {
    let mut per_process: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated; `per_process` and `size` describe a
    // writable int of the size passed; no new value is set.
    let read = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut per_process as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read == 0 && per_process > 0 {
        hard.min(per_process as libc::rlim_t)
    } else {
        // OPEN_MAX: the ceiling macOS documents for setrlimit(RLIMIT_NOFILE).
        hard.min(10_240)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_ceiling(hard: libc::rlim_t) -> libc::rlim_t {
    hard
}

#[cfg(all(test, unix))]
mod tests {
    use super::raise_open_file_limit;

    /// After the call the soft limit is the system ceiling, and calling again
    /// changes nothing.
    #[test]
    fn the_soft_limit_rises_to_the_ceiling_and_stays_there() {
        let (_, raised) = raise_open_file_limit().expect("raise");
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a valid, writable rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert_eq!(limit.rlim_cur, raised);
        assert!(raised >= 256, "{raised}");
        assert_eq!(raise_open_file_limit().unwrap(), (raised, raised));
    }
}
