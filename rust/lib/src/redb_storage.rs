//! Native redb storage, shared by local and Raft stores.

mod memory;

use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::Path;

use redb::{Builder, Database, DatabaseError, StorageError};

/// Create an ephemeral database whose memory follows its written pages.
///
/// The storage already lives in RAM, so redb reads it without a second page
/// cache. Sparse backing leaves the database's unused growth reserve unallocated.
pub fn create_in_memory() -> Result<Database, DatabaseError> {
    Database::builder()
        .set_cache_size(0)
        .create_with_backend(memory::SparseMemoryBackend::default())
}

/// Open an existing database, or initialize and atomically publish a new one.
///
/// redb's `create` initializes directly at the destination. A process killed
/// during initialization can leave an incomplete header there. Initialize a
/// private sibling first so the authoritative path is always absent or valid.
/// Existing files, including invalid ones, are never replaced or reinitialized.
/// Concurrent creators publish without overwriting the winner; normal redb
/// file locking still decides which process may use the database.
pub fn open_or_create(path: &Path, builder: &Builder) -> Result<Database, DatabaseError> {
    open_or_create_with(path, builder, |file| builder.create_file(file))
}

fn open_or_create_with(
    path: &Path,
    builder: &Builder,
    initialize: impl FnOnce(File) -> Result<Database, DatabaseError>,
) -> Result<Database, DatabaseError> {
    match builder.open(path) {
        Ok(database) => return Ok(database),
        Err(DatabaseError::Storage(StorageError::Io(error)))
            if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staged = tempfile::Builder::new()
        .prefix(".redb-bootstrap-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    // Closing flushes redb's initial state. Explicit sync also covers the file
    // length and metadata before its name becomes authoritative.
    drop(initialize(staged.reopen()?)?);
    staged.as_file().sync_all()?;
    // Hold redb's lock across publication; another opener must not race the
    // publisher between rename and open.
    let database = builder.open(staged.path())?;
    match staged.persist_noclobber(path) {
        Ok(_) => {
            #[cfg(unix)]
            crate::file_durability::sync_directory(parent)?;
            Ok(database)
        }
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => {
            drop(database);
            builder.open(path)
        }
        Err(error) => Err(io::Error::from(error).into()),
    }
}

#[cfg(test)]
mod tests;
