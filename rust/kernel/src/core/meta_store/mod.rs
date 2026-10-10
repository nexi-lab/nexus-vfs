//! MetaStore pillar — kernel-internal concrete impls.
//!
//! The trait declaration + helper types live in
//! `crate::abc::meta_store`; this module is the home for the
//! kernel-internal *implementation*:
//!
//! * [`LocalMetaStore`] — redb-backed durable impl (~5μs reads).
//!   Used everywhere — bare-kernel boot opens one against a tempdir
//!   so tests / quickstarts have a working SSOT without explicit
//!   ``set_metastore_path``; production swaps in a real path.
//!
//! Remote / federation impls live in their respective neighbours:
//! [`remote`] (gRPC proxy) and `raft::meta_store`.

pub mod remote;

// Re-export the trait surface from `abc/` so callers writing
// `use crate::core::meta_store::{MetaStore, FileMetadata, …}` (or the
// flat `crate::meta_store::…` shim) reach the canonical declaration in
// `crate::abc::meta_store` without churn. This is a stable compat
// alias, not a parallel declaration.
pub use crate::abc::meta_store::{
    pas_update_content_id, FileMetadata, MetaStore, MetaStoreError, PaginatedList, PathEtag,
    PathValueStr, PutIfVersionResult, StreamSegment, DT_DIR, DT_EXTERNAL_STORAGE, DT_LINK,
    DT_MOUNT, DT_PIPE, DT_REG, DT_STREAM,
};

use dashmap::DashMap;

// pas_update_content_id is defined in crate::abc::meta_store and re-exported
// above. ``LocalMetaStore`` (below) uses it via the re-export.

// ── LocalMetaStore — single-node redb-backed metastore ──────────────────
//
// "redb" is a shared implementation detail — the Raft state machine
// also uses redb underneath. The distinguishing axis is "single-node vs
// raft-replicated", captured by the Local / Zone naming pair.

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

/// redb table: path (str) → serialized FileMetadata (bytes).
///
/// The value encoding is `bincode` over `FileMetadata`'s serde derives; the
/// store records which encoding it holds in [`SCHEMA_TABLE`].
const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

/// redb table: "path\0key" → auxiliary metadata value bytes. Mirrors the
/// Python `DictMetastore._file_metadata` dict-of-dicts, flattened into a
/// single table with a composite key so range-scans can enumerate all
/// keys for a given path.
const FILE_METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("file_metadata");

/// redb table: schema key → version. Currently one row,
/// [`METADATA_FORMAT_KEY`].
///
/// The store says which encoding its `METADATA_TABLE` values are in, rather
/// than each record carrying a tag byte. That is not a space optimization: a
/// bincode `FileMetadata` begins with `path`'s length as a u64, so a 3- or
/// 4-character path starts the record with the byte `3` or `4` — exactly the
/// legacy format's tag values. Per-record sniffing cannot tell those apart.
/// One row per store can.
const SCHEMA_TABLE: TableDefinition<&str, u64> = TableDefinition::new("schema");

/// Key in [`SCHEMA_TABLE`] holding the `METADATA_TABLE` value encoding.
const METADATA_FORMAT_KEY: &str = "metadata_format";

/// `FileMetadata` values are bincode over the serde derives.
///
/// 5 continues the hand-rolled codec's tag sequence (which reached 4) so the
/// two numbering schemes cannot be confused when reading an old report or
/// log line, even though they now live in different places.
const METADATA_FORMAT_BINCODE: u64 = 5;

/// Absent [`METADATA_FORMAT_KEY`] means the hand-rolled positional codec —
/// every store written before this row existed.
const METADATA_FORMAT_LEGACY_POSITIONAL: u64 = 4;

/// Single-node (non-replicated) MetaStore backed by redb — ~5μs reads,
/// zero GIL.
///
/// Used by standalone deployments; federation mounts install a
/// ``ZoneMetaStore`` instead (same on-disk crate, raft-replicated).
///
/// **Internal cache** — every `MetaStore` impl backed by a slow store
/// (disk / RPC / raft) carries its own `cache: DashMap` projection of
/// hot entries.  `get` consults the cache first and populates on miss;
/// `put` commits the store first and refreshes the cache row on
/// commit success, so a failed commit can never leave a phantom hit
/// in the cache; `delete` invalidates the cache before the store
/// delete so concurrent readers cannot observe a stale hit after the
/// row is gone. Cache management is metastore-internal and
/// transparent to callers — there is no separate metadata cache that
/// callers can consult.
pub struct LocalMetaStore {
    db: Arc<Database>,
    cache: DashMap<String, FileMetadata>,
}

impl LocalMetaStore {
    /// Open or create a redb database at the given path.
    pub fn open(path: &Path) -> Result<Self, MetaStoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| MetaStoreError::IOError(format!("mkdir {}: {e}", parent.display())))?;
        }
        let cache_bytes = std::env::var("NEXUS_REDB_CACHE_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64)
            * 1024
            * 1024;
        let db = Database::builder()
            .set_cache_size(cache_bytes)
            .create(path)
            .map_err(|e| MetaStoreError::IOError(format!("redb open {}: {e}", path.display())))?;

        Self::from_database(db, path)
    }

    /// Create an ephemeral namespace using the same metadata API and encoding.
    pub fn in_memory() -> Result<Self, MetaStoreError> {
        let db = Database::builder()
            .set_cache_size(1024 * 1024)
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|e| MetaStoreError::IOError(format!("redb in-memory open: {e}")))?;
        Self::from_database(db, Path::new("in-memory"))
    }

    fn from_database(db: Database, path: &Path) -> Result<Self, MetaStoreError> {
        // Ensure tables exist and the value encoding is the current one. One
        // write txn: a half-migrated store is not a state anything downstream
        // knows how to read, so the rewrite and the version row commit together
        // or not at all.
        let txn = db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb begin_write: {e}")))?;
        {
            let _fm_table = txn.open_table(FILE_METADATA_TABLE).map_err(|e| {
                MetaStoreError::IOError(format!("redb open file_metadata table: {e}"))
            })?;
            let mut schema = txn
                .open_table(SCHEMA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open schema table: {e}")))?;
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;

            let recorded = schema
                .get(METADATA_FORMAT_KEY)
                .map_err(|e| MetaStoreError::IOError(format!("redb read schema: {e}")))?
                .map(|v| v.value());

            match recorded {
                Some(METADATA_FORMAT_BINCODE) => {}
                // No row: either a store this build created (empty, nothing to
                // convert) or one the positional codec wrote. Both end at the
                // current version; only the second has records to rewrite.
                None => {
                    let legacy: Vec<(String, FileMetadata)> = table
                        .iter()
                        .map_err(|e| MetaStoreError::IOError(format!("redb iter: {e}")))?
                        .map(|row| {
                            let (k, v) = row.map_err(|e| {
                                MetaStoreError::IOError(format!("redb iter row: {e}"))
                            })?;
                            let meta = decode_legacy_positional(v.value()).map_err(|e| {
                                MetaStoreError::IOError(format!(
                                    "migrate {}: {e:?}; the store at {} is not a \
                                     tag-3/4 positional store and carries no \
                                     {METADATA_FORMAT_KEY} row",
                                    k.value(),
                                    path.display(),
                                ))
                            })?;
                            Ok((k.value().to_string(), meta))
                        })
                        .collect::<Result<_, MetaStoreError>>()?;

                    if !legacy.is_empty() {
                        tracing::warn!(
                            path = %path.display(),
                            records = legacy.len(),
                            "migrating metastore values from the positional codec to \
                             bincode (one-way: an older build cannot read this store \
                             afterwards)"
                        );
                        for (key, meta) in &legacy {
                            table
                                .insert(key.as_str(), serialize_metadata(meta).as_slice())
                                .map_err(|e| {
                                    MetaStoreError::IOError(format!("migrate insert {key}: {e}"))
                                })?;
                        }
                    }
                    schema
                        .insert(METADATA_FORMAT_KEY, METADATA_FORMAT_BINCODE)
                        .map_err(|e| MetaStoreError::IOError(format!("redb write schema: {e}")))?;
                }
                Some(other) => {
                    return Err(MetaStoreError::IOError(format!(
                        "metastore at {} is {METADATA_FORMAT_KEY}={other}; this build \
                         reads {METADATA_FORMAT_BINCODE} (and migrates \
                         {METADATA_FORMAT_LEGACY_POSITIONAL} and older). It was \
                         written by a newer build — downgrading is not supported.",
                        path.display(),
                    )));
                }
            }
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;

        Ok(Self {
            db: Arc::new(db),
            cache: DashMap::new(),
        })
    }
}

/// Compose the flat `FILE_METADATA_TABLE` key `path\0key`.
fn fm_composite_key(path: &str, key: &str) -> String {
    let mut s = String::with_capacity(path.len() + key.len() + 1);
    s.push_str(path);
    s.push('\0');
    s.push_str(key);
    s
}

/// Encode a `FileMetadata` for `METADATA_TABLE`.
///
/// Derived, not hand-written: `bincode` over `FileMetadata`'s
/// `serde::Serialize`. A field added to the struct is encoded without anyone
/// editing this file, which is the whole point — nexi-lab/nexus-vfs#371 is
/// about a struct that had THREE hand-maintained encodings, where wiring a new
/// field into two of them let it survive one hop and vanish on another.
///
/// The codec this replaced was ~90 lines of length-prefixed writes justified as
/// "compact binary format (not JSON — too slow for hot path)". The JSON half of
/// that was right and the conclusion did not follow: `benches/metadata_codec.rs`
/// measures bincode at 50 ns encode / 165 ns decode against the hand-rolled
/// 47 ns / 170 ns on a populated row — inside noise, and either way a few
/// percent of the ~5 µs redb read it sits inside. It costs 12-18% more bytes.
///
/// `bincode` is positional, so this is NOT tolerant of a field appended by a
/// newer build the way the old codec's "ran out of bytes ⇒ None" tail was.
/// That tolerance is not missed: it is what let a pre-subtree record read back
/// as `target_subtree: None` and mean "the whole zone", which is the silent
/// default that made nexi-lab/nexus-vfs#361 subtle. Schema changes now go
/// through [`SCHEMA_TABLE`] and a migration that says what it did.
fn serialize_metadata(meta: &FileMetadata) -> Vec<u8> {
    // Infallible for this type: every field is a String/Option/integer, none of
    // which bincode can refuse, and the writer is a Vec. `expect` rather than a
    // Result keeps the 11 call sites from each growing an error arm that cannot
    // fire.
    bincode::serialize(meta).expect("bincode cannot fail on FileMetadata into a Vec")
}

/// Decode a `METADATA_TABLE` value written by [`serialize_metadata`].
fn deserialize_metadata(data: &[u8]) -> Result<FileMetadata, MetaStoreError> {
    bincode::deserialize(data)
        .map_err(|e| MetaStoreError::IOError(format!("decode FileMetadata: {e}")))
}

/// Decode a record written by the hand-rolled positional codec (tag 3 or 4).
///
/// **Migration only.** [`LocalMetaStore::open`] calls this once per legacy
/// record to rewrite the store, and nothing else does — the encoder is gone, so
/// no new record can land in this format. It is kept rather than deleted
/// because deleting it is what would make the migration impossible, and it goes
/// when no deployment can still hold a tag-3/4 store.
///
/// Tag 4 appends `gen` (u64) and `owner_id`, then `target_subtree`, after the
/// tag-3 fields. Strings carry a u32 length prefix; `Option<_>` is framed by a
/// 1-byte present flag. A tag-3 record simply runs out of bytes at `gen`, which
/// reads back as 0. Its tests feed FROZEN BYTES rather than round-tripping,
/// since there is no longer an encoder to round-trip through and the bytes on an
/// operator's disk are the actual contract.
fn decode_legacy_positional(data: &[u8]) -> Result<FileMetadata, MetaStoreError> {
    if data.is_empty() {
        return Err(MetaStoreError::IOError("empty record".into()));
    }
    let tag = data[0];
    if tag != 3 && tag != 4 {
        return Err(MetaStoreError::IOError(format!(
            "unsupported FileMetadata serialization tag {tag}; expected 3 or 4"
        )));
    }
    let mut pos = 1usize;

    fn read_str(data: &[u8], pos: &mut usize) -> Result<String, MetaStoreError> {
        if *pos + 4 > data.len() {
            return Err(MetaStoreError::IOError("truncated string length".into()));
        }
        let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
        *pos += 4;
        if *pos + len > data.len() {
            return Err(MetaStoreError::IOError("truncated string data".into()));
        }
        let s = std::str::from_utf8(&data[*pos..*pos + len])
            .map_err(|e| MetaStoreError::IOError(format!("invalid utf8: {e}")))?
            .to_string();
        *pos += len;
        Ok(s)
    }
    fn read_opt_str(data: &[u8], pos: &mut usize) -> Result<Option<String>, MetaStoreError> {
        if *pos >= data.len() {
            return Err(MetaStoreError::IOError("truncated optional flag".into()));
        }
        let flag = data[*pos];
        *pos += 1;
        if flag == 0 {
            Ok(None)
        } else {
            read_str(data, pos).map(Some)
        }
    }

    let path = read_str(data, &mut pos)?;

    if pos + 8 > data.len() {
        return Err(MetaStoreError::IOError("truncated size".into()));
    }
    let size = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;

    let content_id = read_opt_str(data, &mut pos)?;

    if pos + 4 > data.len() {
        return Err(MetaStoreError::IOError("truncated version".into()));
    }
    let version = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;

    if pos >= data.len() {
        return Err(MetaStoreError::IOError("truncated entry_type".into()));
    }
    let entry_type = data[pos];
    pos += 1;

    let zone_id = read_opt_str(data, &mut pos)?;
    let mime_type = read_opt_str(data, &mut pos)?;

    fn read_opt_i64(data: &[u8], pos: &mut usize) -> Result<Option<i64>, MetaStoreError> {
        if *pos >= data.len() {
            return Ok(None);
        }
        let flag = data[*pos];
        *pos += 1;
        if flag == 0 {
            return Ok(None);
        }
        if *pos + 8 > data.len() {
            return Err(MetaStoreError::IOError("truncated i64".into()));
        }
        let n = i64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
        *pos += 8;
        Ok(Some(n))
    }

    let created_at_ms = read_opt_i64(data, &mut pos)?;
    let modified_at_ms = read_opt_i64(data, &mut pos)?;
    // Trailing optional slots may grow over time; missing reads return None.
    let last_writer_address = read_opt_str(data, &mut pos).ok().flatten();
    let target_zone_id = read_opt_str(data, &mut pos).ok().flatten();
    let link_target = read_opt_str(data, &mut pos).ok().flatten();
    let gen = if tag >= 4 {
        if pos + 8 > data.len() {
            return Err(MetaStoreError::IOError("truncated gen".into()));
        }
        let g = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        g
    } else {
        0
    };
    let owner_id = read_opt_str(data, &mut pos).ok().flatten();
    // `.ok().flatten()` is what makes the append backward-compatible: an older
    // record ends before this field and yields None rather than an error.
    let target_subtree = read_opt_str(data, &mut pos).ok().flatten();

    Ok(FileMetadata {
        path,
        size,
        content_id,
        gen,
        version,
        entry_type,
        zone_id,
        mime_type,
        created_at_ms,
        modified_at_ms,
        target_zone_id,
        target_subtree,
        last_writer_address,
        link_target,
        owner_id,
    })
}

impl MetaStore for LocalMetaStore {
    fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
        // Internal cache fast path — see struct docstring for invariants.
        if let Some(cached) = self.cache.get(path) {
            return Ok(Some(cached.clone()));
        }
        let txn = self
            .db
            .begin_read()
            .map_err(|e| MetaStoreError::IOError(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(METADATA_TABLE)
            .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
        match table.get(path) {
            Ok(Some(guard)) => {
                let data = guard.value();
                let meta = deserialize_metadata(data)?;
                // Populate cache from store result.
                self.cache.insert(path.to_string(), meta.clone());
                Ok(Some(meta))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(MetaStoreError::IOError(format!("redb get: {e}"))),
        }
    }

    fn put(&self, path: &str, metadata: FileMetadata) -> Result<(), MetaStoreError> {
        let data = serialize_metadata(&metadata);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
            table
                .insert(path, data.as_slice())
                .map_err(|e| MetaStoreError::IOError(format!("redb insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;
        // Write-through cache update — store commit succeeded, refresh
        // the cache row so subsequent get() observes the new value.
        self.cache.insert(path.to_string(), metadata);
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<bool, MetaStoreError> {
        // Invalidate cache before store delete — concurrent readers
        // observe either "cache empty → fall through to store" or
        // "store missing" depending on race timing, but never a stale
        // hit after the store delete.
        self.cache.remove(path);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        let existed;
        {
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
            existed = table
                .remove(path)
                .map_err(|e| MetaStoreError::IOError(format!("redb remove: {e}")))?
                .is_some();
        }
        // Drop any auxiliary file_metadata entries for this path in the
        // same txn via a range scan on the "path\0..." prefix. The upper
        // bound bumps the path's final byte (path + '\u{1}'), which is
        // strictly greater than any "path\0...suffix" key — the
        // alternative "start + '\u{1}'" left the range as
        // [path\0, path\0\u{1}) and missed every real "path\0key" entry
        // because letters sort after '\u{1}'.
        {
            let mut fm_table = txn
                .open_table(FILE_METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open fm table: {e}")))?;
            let start = fm_composite_key(path, "");
            let mut end = path.to_string();
            end.push('\u{1}');
            let keys: Vec<String> = {
                let iter = fm_table
                    .range(start.as_str()..end.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm range: {e}")))?;
                let mut keys = Vec::new();
                for entry in iter {
                    let (k, _) =
                        entry.map_err(|e| MetaStoreError::IOError(format!("redb fm iter: {e}")))?;
                    keys.push(k.value().to_string());
                }
                keys
            };
            for k in keys {
                fm_table
                    .remove(k.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm remove: {e}")))?;
            }
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;
        Ok(existed)
    }

    fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| MetaStoreError::IOError(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(METADATA_TABLE)
            .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;

        let mut results = Vec::new();

        if prefix.is_empty() {
            // Empty prefix = full table scan
            let iter = table
                .iter()
                .map_err(|e| MetaStoreError::IOError(format!("redb iter: {e}")))?;
            for entry in iter {
                let (_, value) =
                    entry.map_err(|e| MetaStoreError::IOError(format!("redb iter: {e}")))?;
                results.push(deserialize_metadata(value.value())?);
            }
        } else {
            // Range scan: prefix..prefix with last byte incremented
            let mut range_end = prefix.to_string();
            if let Some(last) = range_end.pop() {
                range_end.push(char::from_u32(last as u32 + 1).unwrap_or(char::MAX));
            }
            let iter = table
                .range(prefix..range_end.as_str())
                .map_err(|e| MetaStoreError::IOError(format!("redb range: {e}")))?;
            for entry in iter {
                let (_, value) =
                    entry.map_err(|e| MetaStoreError::IOError(format!("redb iter: {e}")))?;
                results.push(deserialize_metadata(value.value())?);
            }
        }
        Ok(results)
    }

    fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| MetaStoreError::IOError(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(METADATA_TABLE)
            .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
        table
            .get(path)
            .map(|opt| opt.is_some())
            .map_err(|e| MetaStoreError::IOError(format!("redb get: {e}")))
    }

    /// Single write transaction for all items — optimal for redb.
    fn put_batch(&self, items: &[(String, FileMetadata)]) -> Result<(), MetaStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
            for (path, meta) in items {
                let data = serialize_metadata(meta);
                table
                    .insert(path.as_str(), data.as_slice())
                    .map_err(|e| MetaStoreError::IOError(format!("redb insert: {e}")))?;
            }
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;
        // Write-through cache: refresh every put row after the redb
        // commit succeeds, mirroring single-key `put`.
        for (path, meta) in items {
            self.cache.insert(path.clone(), meta.clone());
        }
        Ok(())
    }

    /// Single write transaction for all deletes — optimal for redb.
    fn delete_batch(&self, paths: &[String]) -> Result<usize, MetaStoreError> {
        // Invalidate cache up-front (same race-safety reasoning as `delete`).
        for path in paths {
            self.cache.remove(path);
        }
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        let mut count = 0;
        {
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
            for path in paths {
                if table
                    .remove(path.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb remove: {e}")))?
                    .is_some()
                {
                    count += 1;
                }
            }
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;
        Ok(count)
    }

    /// Single read transaction for all paths.
    fn get_batch(&self, paths: &[String]) -> Result<Vec<Option<FileMetadata>>, MetaStoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| MetaStoreError::IOError(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(METADATA_TABLE)
            .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
        let mut results = Vec::with_capacity(paths.len());
        for path in paths {
            match table.get(path.as_str()) {
                Ok(Some(guard)) => {
                    let meta = deserialize_metadata(guard.value())?;
                    self.cache.insert(path.clone(), meta.clone());
                    results.push(Some(meta));
                }
                Ok(None) => results.push(None),
                Err(e) => return Err(MetaStoreError::IOError(format!("redb get_batch: {e}"))),
            }
        }
        Ok(results)
    }

    /// Single write txn: read current version, compare, write on match.
    fn put_if_version(
        &self,
        metadata: FileMetadata,
        expected_version: u32,
    ) -> Result<PutIfVersionResult, MetaStoreError> {
        let path = metadata.path.clone();
        let new_ver = metadata.version;
        let data = serialize_metadata(&metadata);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        let result;
        {
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
            let current_ver = match table.get(path.as_str()) {
                Ok(Some(guard)) => deserialize_metadata(guard.value())?.version,
                Ok(None) => 0,
                Err(e) => {
                    return Err(MetaStoreError::IOError(format!(
                        "redb put_if_version get: {e}"
                    )))
                }
            };
            if current_ver != expected_version {
                result = PutIfVersionResult {
                    success: false,
                    current_version: current_ver,
                };
            } else {
                table
                    .insert(path.as_str(), data.as_slice())
                    .map_err(|e| MetaStoreError::IOError(format!("redb cas insert: {e}")))?;
                result = PutIfVersionResult {
                    success: true,
                    current_version: new_ver,
                };
            }
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;
        // Refresh cache only on successful CAS commit; failed CAS leaves
        // the existing cache row alone.
        if result.success {
            self.cache.insert(path, metadata);
        }
        Ok(result)
    }

    /// Single write txn: rewrite `old_path` and all children under
    /// `old_path + "/"` to their new names. Keys are rewritten in place
    /// (remove + insert) since redb has no rename primitive.
    fn rename_path(
        &self,
        old_path: &str,
        new_path: &str,
        is_pas: bool,
    ) -> Result<(), MetaStoreError> {
        if old_path == new_path {
            return Ok(());
        }
        let old_prefix = format!("{}/", old_path.trim_end_matches('/'));
        let new_prefix = format!("{}/", new_path.trim_end_matches('/'));
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open_table: {e}")))?;
            // Gather everything first (top-level + children) so the range
            // iterator / remove guards all drop before we start inserting.
            let mut to_rewrite: Vec<(String, String, Vec<u8>)> = Vec::new();
            {
                let top_bytes = table
                    .get(old_path)
                    .map_err(|e| MetaStoreError::IOError(format!("redb get: {e}")))?
                    .map(|guard| guard.value().to_vec());
                if let Some(bytes) = top_bytes {
                    to_rewrite.push((old_path.to_string(), new_path.to_string(), bytes));
                }
                let mut range_end = old_prefix.clone();
                if let Some(last) = range_end.pop() {
                    range_end.push(char::from_u32(last as u32 + 1).unwrap_or(char::MAX));
                }
                let iter = table
                    .range(old_prefix.as_str()..range_end.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb range: {e}")))?;
                for entry in iter {
                    let (k, v) =
                        entry.map_err(|e| MetaStoreError::IOError(format!("redb iter: {e}")))?;
                    let old_child = k.value().to_string();
                    let suffix = old_child
                        .strip_prefix(&old_prefix)
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let new_child = format!("{}{}", new_prefix, suffix);
                    to_rewrite.push((old_child, new_child, v.value().to_vec()));
                }
            }
            // The destination may already exist — `rename(2)` replaces it. The
            // main-table `insert` below overwrites that row on its own, but the
            // side-car entries do not: they are keyed `path\0k`, so the old
            // destination's keys would survive under the new path and appear to
            // belong to the file that replaced it. Purge them here, inside the
            // same write transaction, so the replace stays atomic.
            let stale_start = fm_composite_key(new_path, "");
            let mut stale_end = new_path.to_string();
            stale_end.push('\u{1}');
            let mut stale_fm: Vec<String> = Vec::new();
            {
                let fm_probe = txn
                    .open_table(FILE_METADATA_TABLE)
                    .map_err(|e| MetaStoreError::IOError(format!("redb open fm table: {e}")))?;
                let iter = fm_probe
                    .range(stale_start.as_str()..stale_end.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm range: {e}")))?;
                for entry in iter {
                    let (k, _) =
                        entry.map_err(|e| MetaStoreError::IOError(format!("redb fm iter: {e}")))?;
                    stale_fm.push(k.value().to_string());
                }
            }

            for (old_key, new_key, bytes) in &to_rewrite {
                let mut meta = deserialize_metadata(bytes)?;
                meta.path = new_key.clone();
                if is_pas {
                    pas_update_content_id(&mut meta, old_key, new_key);
                }
                let new_bytes = serialize_metadata(&meta);
                table
                    .remove(old_key.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb remove: {e}")))?;
                table
                    .insert(new_key.as_str(), new_bytes.as_slice())
                    .map_err(|e| MetaStoreError::IOError(format!("redb insert: {e}")))?;
            }
            // Rewrite auxiliary file_metadata side-car entries the same
            // way: every "old\0k" key becomes "new\0k". Done in the same
            // write txn so rename is atomic across both tables.
            let mut fm_table = txn
                .open_table(FILE_METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open fm table: {e}")))?;
            for key in &stale_fm {
                fm_table
                    .remove(key.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm purge: {e}")))?;
            }
            let mut fm_to_rewrite: Vec<(String, String, Vec<u8>)> = Vec::new();
            for (old_key, new_key, _) in &to_rewrite {
                let start = fm_composite_key(old_key, "");
                let mut end = old_key.clone();
                end.push('\u{1}');
                let iter = fm_table
                    .range(start.as_str()..end.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm range: {e}")))?;
                for entry in iter {
                    let (k, v) =
                        entry.map_err(|e| MetaStoreError::IOError(format!("redb fm iter: {e}")))?;
                    let old_fm = k.value().to_string();
                    let suffix = old_fm
                        .strip_prefix(&format!("{old_key}\0"))
                        .unwrap_or("")
                        .to_string();
                    let new_fm = fm_composite_key(new_key, &suffix);
                    fm_to_rewrite.push((old_fm, new_fm, v.value().to_vec()));
                }
            }
            for (old_fm, new_fm, bytes) in fm_to_rewrite {
                fm_table
                    .remove(old_fm.as_str())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm remove: {e}")))?;
                fm_table
                    .insert(new_fm.as_str(), bytes.as_slice())
                    .map_err(|e| MetaStoreError::IOError(format!("redb fm insert: {e}")))?;
            }
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb commit: {e}")))?;
        // Invalidate any cached rows under the old name (top-level +
        // children).  Subsequent `get(new_path...)` repopulates from
        // the redb store; we deliberately do NOT pre-populate because
        // the rewritten metadata may have transformed fields (PAS
        // content_id rewrite) we'd need to mirror here.
        self.cache.remove(old_path);
        let old_prefix_for_cache = format!("{}/", old_path.trim_end_matches('/'));
        self.cache
            .retain(|k, _| !k.starts_with(&old_prefix_for_cache));
        // And under the new name. This was unnecessary while a rename refused an
        // existing destination — nothing could be cached at a path that was
        // required not to exist. Now that a rename replaces, a stale row for the
        // file that was replaced would be served in preference to the one that
        // replaced it, which reads as the rename having silently not happened.
        self.cache.remove(new_path);
        let new_prefix_for_cache = format!("{}/", new_path.trim_end_matches('/'));
        self.cache
            .retain(|k, _| !k.starts_with(&new_prefix_for_cache));
        Ok(())
    }

    fn set_file_metadata(
        &self,
        path: &str,
        key: &str,
        value: String,
    ) -> Result<(), MetaStoreError> {
        let composite = fm_composite_key(path, key);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MetaStoreError::IOError(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(FILE_METADATA_TABLE)
                .map_err(|e| MetaStoreError::IOError(format!("redb open fm table: {e}")))?;
            table
                .insert(composite.as_str(), value.as_bytes())
                .map_err(|e| MetaStoreError::IOError(format!("redb fm insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| MetaStoreError::IOError(format!("redb fm commit: {e}")))?;
        Ok(())
    }

    fn get_file_metadata(&self, path: &str, key: &str) -> Result<Option<String>, MetaStoreError> {
        let composite = fm_composite_key(path, key);
        let txn = self
            .db
            .begin_read()
            .map_err(|e| MetaStoreError::IOError(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(FILE_METADATA_TABLE)
            .map_err(|e| MetaStoreError::IOError(format!("redb open fm table: {e}")))?;
        match table.get(composite.as_str()) {
            Ok(Some(guard)) => {
                let bytes = guard.value();
                let s = std::str::from_utf8(bytes).map_err(|e| {
                    MetaStoreError::IOError(format!("redb fm utf8 decode {path}/{key}: {e}"))
                })?;
                Ok(Some(s.to_string()))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(MetaStoreError::IOError(format!("redb fm get: {e}"))),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// EVERY field survives the stored encoding — the anti-drift guard.
    ///
    /// Weaker than it was, on purpose: the encoding is now derived, so this can
    /// no longer catch "the author wired the field into the writer but not the
    /// reader" — that is not a mistake `bincode` lets anyone make. What it
    /// still catches is a field whose TYPE does not survive, and it is cheap,
    /// so it stays.
    ///
    /// Two encodings remain that a new field must reach, and neither is
    /// derived from this one: the prost proto (`nexus.core.FileMetadata`, wired
    /// by `nexus_raft::zone_meta_store::{kernel_to_proto, proto_to_kernel}`) and
    /// — until proto3 can express `Option` without the empty-string
    /// convention — nothing else. The proto mapping is guarded the same way
    /// this is: exhaustive destructuring with no `..`, so a new field fails to
    /// compile there.
    ///
    /// The struct literal has no `..Default::default()`, so a new field makes
    /// this FAIL TO COMPILE until someone supplies a value, and every field
    /// gets a NON-default value so the whole-value comparison bites — a `None`
    /// or `0` would round-trip through an encoding that dropped it.
    #[test]
    fn every_field_survives_the_binary_encoding() {
        let meta = FileMetadata {
            path: "/a/b/c.txt".to_string(),
            size: 4096,
            content_id: Some("blake3-deadbeef".to_string()),
            gen: 42,
            version: 7,
            entry_type: 2, // DT_MOUNT, the entry type the mount fields describe
            zone_id: Some("sharedzone".to_string()),
            mime_type: Some("text/plain".to_string()),
            created_at_ms: Some(1_700_000_000_000),
            modified_at_ms: Some(1_700_000_001_000),
            last_writer_address: Some("100.64.0.27:2126".to_string()),
            target_zone_id: Some("sharedzone".to_string()),
            target_subtree: Some("/agents".to_string()),
            link_target: Some("/conversations/9d41ae".to_string()),
            owner_id: Some("win-ai".to_string()),
        };

        let restored = deserialize_metadata(&serialize_metadata(&meta))
            .expect("a record this codec just wrote must decode");

        assert_eq!(
            restored, meta,
            "a field reached the struct without reaching this codec; it would              be dropped on every local metastore write"
        );
    }

    #[test]
    fn serialize_roundtrip_preserves_gen() {
        let meta = FileMetadata {
            path: "/gen.txt".to_string(),
            size: 9,
            content_id: Some("hash".to_string()),
            version: 2,
            entry_type: 0,
            zone_id: Some("root".to_string()),
            mime_type: Some("text/plain".to_string()),
            created_at_ms: Some(10),
            modified_at_ms: Some(20),
            last_writer_address: Some("nexus-1:2028".to_string()),
            target_zone_id: None,
            target_subtree: None,
            link_target: None,
            gen: 42,
            owner_id: None,
        };

        let restored = deserialize_metadata(&serialize_metadata(&meta)).unwrap();

        assert_eq!(restored.gen, 42);
        assert_eq!(restored.path, "/gen.txt");
        assert_eq!(restored.content_id.as_deref(), Some("hash"));
    }

    /// A real tag-4 record, captured from the positional encoder before it was
    /// deleted.
    ///
    /// Frozen bytes, not a round-trip: there is no encoder left to round-trip
    /// through, and these are what is actually on an operator's disk. A test
    /// that regenerated its own input would only prove the decoder agrees with
    /// itself.
    const LEGACY_V4_RECORD: &[u8] = &[
        4, 29, 0, 0, 0, 47, 97, 103, 101, 110, 116, 115, 47, 97, 117, 114, 111, 114, 97, 45, 109,
        98, 112, 47, 116, 114, 97, 110, 115, 99, 114, 105, 112, 116, 64, 188, 0, 0, 0, 0, 0, 0, 1,
        15, 0, 0, 0, 98, 108, 97, 107, 101, 51, 58, 57, 102, 50, 99, 52, 97, 101, 49, 12, 0, 0, 0,
        0, 1, 10, 0, 0, 0, 115, 104, 97, 114, 101, 100, 122, 111, 110, 101, 1, 17, 0, 0, 0, 97,
        112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 108, 1, 0, 246,
        145, 140, 153, 1, 0, 0, 1, 160, 177, 159, 140, 153, 1, 0, 0, 1, 15, 0, 0, 0, 49, 48, 48,
        46, 54, 52, 46, 48, 46, 55, 58, 50, 49, 50, 54, 1, 10, 0, 0, 0, 115, 104, 97, 114, 101,
        100, 122, 111, 110, 101, 1, 10, 0, 0, 0, 47, 101, 108, 115, 101, 119, 104, 101, 114, 101,
        37, 0, 0, 0, 0, 0, 0, 0, 1, 15, 0, 0, 0, 115, 107, 45, 97, 103, 101, 110, 116, 45, 97, 117,
        114, 111, 114, 97, 1, 7, 0, 0, 0, 47, 97, 103, 101, 110, 116, 115,
    ];

    /// The same row as a tag-3 record: tag 3, and the three fields v4 appended
    /// (`gen`, `owner_id`, `target_subtree`) simply absent off the end.
    const LEGACY_V3_RECORD: &[u8] = &[
        3, 29, 0, 0, 0, 47, 97, 103, 101, 110, 116, 115, 47, 97, 117, 114, 111, 114, 97, 45, 109,
        98, 112, 47, 116, 114, 97, 110, 115, 99, 114, 105, 112, 116, 64, 188, 0, 0, 0, 0, 0, 0, 1,
        15, 0, 0, 0, 98, 108, 97, 107, 101, 51, 58, 57, 102, 50, 99, 52, 97, 101, 49, 12, 0, 0, 0,
        0, 1, 10, 0, 0, 0, 115, 104, 97, 114, 101, 100, 122, 111, 110, 101, 1, 17, 0, 0, 0, 97,
        112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 108, 1, 0, 246,
        145, 140, 153, 1, 0, 0, 1, 160, 177, 159, 140, 153, 1, 0, 0, 1, 15, 0, 0, 0, 49, 48, 48,
        46, 54, 52, 46, 48, 46, 55, 58, 50, 49, 50, 54, 1, 10, 0, 0, 0, 115, 104, 97, 114, 101,
        100, 122, 111, 110, 101, 1, 10, 0, 0, 0, 47, 101, 108, 115, 101, 119, 104, 101, 114, 101,
    ];

    /// What `LEGACY_V4_RECORD` must decode to, field for field.
    fn frozen_row() -> FileMetadata {
        FileMetadata {
            path: "/agents/aurora-mbp/transcript".to_string(),
            size: 48_192,
            content_id: Some("blake3:9f2c4ae1".to_string()),
            gen: 37,
            version: 12,
            entry_type: 0,
            zone_id: Some("sharedzone".to_string()),
            mime_type: Some("application/jsonl".to_string()),
            created_at_ms: Some(1_759_000_000_000),
            modified_at_ms: Some(1_759_000_900_000),
            last_writer_address: Some("100.64.0.7:2126".to_string()),
            target_zone_id: Some("sharedzone".to_string()),
            target_subtree: Some("/agents".to_string()),
            link_target: Some("/elsewhere".to_string()),
            owner_id: Some("sk-agent-aurora".to_string()),
        }
    }

    /// The migration's whole job: every field of a stored tag-4 record comes
    /// back. Compared as a whole value, so a field the decoder drops fails here
    /// rather than needing its own assertion.
    #[test]
    fn the_migration_decoder_reads_a_frozen_v4_record_whole() {
        assert_eq!(
            decode_legacy_positional(LEGACY_V4_RECORD).unwrap(),
            frozen_row()
        );
    }

    /// A tag-3 record predates `gen`, `owner_id` and `target_subtree`, so those
    /// read back as defaults and everything before them is intact.
    ///
    /// `target_subtree: None` meaning "the whole zone" is the silent default
    /// that made nexi-lab/nexus-vfs#361 subtle. It is the correct reading of a
    /// record written before subtrees existed — but only here, decoding a
    /// genuinely old record. The bincode encoding that replaced this has no
    /// such tail, so a future field cannot acquire the same ambiguity by
    /// accident.
    #[test]
    fn the_migration_decoder_reads_a_frozen_v3_record_and_defaults_the_v4_tail() {
        assert_eq!(
            decode_legacy_positional(LEGACY_V3_RECORD).unwrap(),
            FileMetadata {
                gen: 0,
                owner_id: None,
                target_subtree: None,
                ..frozen_row()
            }
        );
    }

    /// Truncation inside a fixed-width field is an error, not a default.
    ///
    /// The decoder tolerates a short tail for opt-strs by design — that is how
    /// a v3 record reads — so only a cut that actually breaches `gen` tests
    /// anything, and `gen` is not last. In `LEGACY_V4_RECORD` the fields after
    /// it are both populated opt-strs: `owner_id` ("sk-agent-aurora", 1 flag +
    /// 4 len + 15) and `target_subtree` ("/agents", 1 + 4 + 7) = 32 bytes. One
    /// more reaches `gen`.
    ///
    /// Derived from the fixture rather than reused from the all-`None` record
    /// this test used to build for itself — where the same cut was 3 bytes. If
    /// the fixture changes, the assertion below names a different error and
    /// this fails loudly rather than passing vacuously on a tolerated tail.
    #[test]
    fn the_migration_decoder_refuses_a_record_truncated_inside_gen() {
        let after_gen = 1 + 4 + "sk-agent-aurora".len() + 1 + 4 + "/agents".len();
        let cut = &LEGACY_V4_RECORD[..LEGACY_V4_RECORD.len() - after_gen - 1];

        let err = decode_legacy_positional(cut).unwrap_err();

        assert!(
            matches!(&err, MetaStoreError::IOError(msg) if msg == "truncated gen"),
            "{err:?}"
        );
    }

    /// A bincode record must never be mistaken for a legacy one.
    ///
    /// This is why the format lives in `SCHEMA_TABLE` and not in a tag byte: a
    /// bincode `FileMetadata` opens with `path`'s length as a u64, so a 3- or
    /// 4-character path starts the record with the byte 3 or 4 — the legacy
    /// tags exactly. Per-record sniffing would hand those to the wrong decoder.
    #[test]
    fn a_short_path_makes_bincode_bytes_look_like_a_legacy_tag() {
        for path in ["/ab", "/abc"] {
            let meta = FileMetadata {
                path: path.to_string(),
                ..Default::default()
            };
            let encoded = serialize_metadata(&meta);
            assert_eq!(
                encoded[0] as usize,
                path.len(),
                "bincode leads with the path length, which is what collides"
            );
            assert!(
                encoded[0] == 3 || encoded[0] == 4,
                "{path:?} must produce a leading byte in the legacy tag range, \
                 or this test has stopped demonstrating the collision"
            );
            // And the round-trip still works, because nothing sniffs the byte.
            assert_eq!(deserialize_metadata(&encoded).unwrap(), meta);
        }
    }

    /// End to end: a store holding positional records opens, migrates, and
    /// answers `get` with the right values — then stays migrated.
    ///
    /// Built by writing the frozen bytes straight into redb, which is what an
    /// upgrading operator's file actually contains. Going through `put` would
    /// write bincode and test nothing.
    #[test]
    fn opening_a_positional_store_migrates_it_once_and_reads_back() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("legacy.redb");

        // An operator's pre-upgrade store: legacy bytes, and no schema row.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut t = txn.open_table(METADATA_TABLE).unwrap();
                t.insert("/agents/aurora-mbp/transcript", LEGACY_V4_RECORD)
                    .unwrap();
                t.insert("/old", LEGACY_V3_RECORD).unwrap();
            }
            txn.commit().unwrap();
        }

        let ms = LocalMetaStore::open(&path).unwrap();

        assert_eq!(
            ms.get("/agents/aurora-mbp/transcript").unwrap(),
            Some(frozen_row()),
            "a migrated record must read back whole"
        );
        assert_eq!(
            ms.get("/old").unwrap(),
            Some(FileMetadata {
                gen: 0,
                owner_id: None,
                target_subtree: None,
                ..frozen_row()
            })
        );
        drop(ms);

        // The bytes on disk are bincode now, and the version row says so — so
        // a second open has nothing to do. Without the row, this open would
        // hand bincode bytes to the legacy decoder.
        {
            let db = Database::open(&path).unwrap();
            let txn = db.begin_read().unwrap();
            let schema = txn.open_table(SCHEMA_TABLE).unwrap();
            assert_eq!(
                schema.get(METADATA_FORMAT_KEY).unwrap().map(|v| v.value()),
                Some(METADATA_FORMAT_BINCODE)
            );
            let t = txn.open_table(METADATA_TABLE).unwrap();
            let stored = t
                .get("/agents/aurora-mbp/transcript")
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            assert_eq!(
                deserialize_metadata(&stored).unwrap(),
                frozen_row(),
                "the rewrite must have happened on disk, not just in the cache"
            );
        }

        let reopened = LocalMetaStore::open(&path).unwrap();
        assert_eq!(
            reopened.get("/agents/aurora-mbp/transcript").unwrap(),
            Some(frozen_row()),
            "reopening a migrated store must not re-run the migration"
        );
    }

    /// A store from a newer build is refused rather than misread.
    #[test]
    fn opening_a_store_from_a_newer_format_is_an_error() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("future.redb");
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut s = txn.open_table(SCHEMA_TABLE).unwrap();
                s.insert(METADATA_FORMAT_KEY, METADATA_FORMAT_BINCODE + 1)
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let Err(err) = LocalMetaStore::open(&path) else {
            panic!("a store from a newer format must not open");
        };

        assert!(
            matches!(&err, MetaStoreError::IOError(m) if m.contains("newer build")),
            "{err:?}"
        );
    }

    /// Round-trip covers both a DT_REG entry and a DT_MOUNT entry so
    /// `entry_type` survives intact.
    #[test]
    fn test_serialize_roundtrip() {
        let cases = [
            FileMetadata {
                path: "/test/file.txt".to_string(),
                size: 1024,
                content_id: Some("hash123".to_string()),
                gen: 0,
                version: 3,
                entry_type: 0, // DT_REG
                zone_id: Some("root".to_string()),
                mime_type: None,
                created_at_ms: None,
                modified_at_ms: None,
                last_writer_address: Some("nexus-1:2028".to_string()),
                target_zone_id: None,
                target_subtree: None,
                link_target: None,
                owner_id: None,
            },
            FileMetadata {
                path: "/mnt/peer".to_string(),
                size: 0,
                content_id: None,
                gen: 0,
                version: 1,
                entry_type: 2, // DT_MOUNT
                zone_id: Some("zone-a".to_string()),
                mime_type: None,
                created_at_ms: None,
                modified_at_ms: None,
                last_writer_address: None,
                target_zone_id: Some("zone-a".to_string()),
                target_subtree: None,
                link_target: None,
                owner_id: None,
            },
        ];
        for meta in &cases {
            let restored = deserialize_metadata(&serialize_metadata(meta)).unwrap();
            assert_eq!(restored.path, meta.path);
            assert_eq!(restored.size, meta.size);
            assert_eq!(restored.content_id, meta.content_id);
            assert_eq!(restored.version, meta.version);
            assert_eq!(restored.entry_type, meta.entry_type);
            assert_eq!(restored.zone_id, meta.zone_id);
            assert_eq!(restored.mime_type, meta.mime_type);
            assert_eq!(restored.last_writer_address, meta.last_writer_address);
            assert_eq!(restored.target_zone_id, meta.target_zone_id);
        }
    }

    fn mk_meta(path: &str, version: u32) -> FileMetadata {
        FileMetadata {
            path: path.to_string(),
            size: 0,
            content_id: None,
            gen: 0,
            version,
            entry_type: 0,
            zone_id: None,
            mime_type: None,
            created_at_ms: None,
            modified_at_ms: None,
            last_writer_address: None,
            target_zone_id: None,
            target_subtree: None,
            link_target: None,
            owner_id: None,
        }
    }

    /// Open a fresh tempfile-backed ``LocalMetaStore`` for one test.
    /// The returned ``TempDir`` MUST be bound to a local with a name (or
    /// kept alive otherwise) — when it drops, redb's exclusive lock is
    /// released and the ephemeral file is unlinked.
    fn fresh_local() -> (tempfile::TempDir, LocalMetaStore) {
        let td = tempfile::tempdir().unwrap();
        let ms = LocalMetaStore::open(&td.path().join("ms.redb")).unwrap();
        (td, ms)
    }

    #[test]
    fn local_put_if_version_vacant_accepts_zero() {
        let (_td, ms) = fresh_local();
        let r = ms.put_if_version(mk_meta("/a", 1), 0).unwrap();
        assert!(r.success);
        assert_eq!(r.current_version, 1);
    }

    #[test]
    fn local_put_if_version_conflict_returns_current() {
        let (_td, ms) = fresh_local();
        ms.put("/a", mk_meta("/a", 3)).unwrap();
        let r = ms.put_if_version(mk_meta("/a", 4), 2).unwrap();
        assert!(!r.success);
        assert_eq!(r.current_version, 3);
        assert_eq!(ms.get("/a").unwrap().unwrap().version, 3);
    }

    #[test]
    fn local_rename_path_moves_entry_and_children() {
        let (_td, ms) = fresh_local();
        ms.put("/old", mk_meta("/old", 1)).unwrap();
        ms.put("/old/child", mk_meta("/old/child", 1)).unwrap();
        ms.put("/old/sub/deep", mk_meta("/old/sub/deep", 1))
            .unwrap();
        ms.set_file_metadata("/old/child", "tag", "value".to_string())
            .unwrap();

        ms.rename_path("/old", "/new", true).unwrap();

        assert!(ms.get("/old").unwrap().is_none());
        assert!(ms.get("/old/child").unwrap().is_none());
        assert!(ms.get("/old/sub/deep").unwrap().is_none());
        assert_eq!(ms.get("/new").unwrap().unwrap().path, "/new");
        assert_eq!(ms.get("/new/child").unwrap().unwrap().path, "/new/child");
        assert_eq!(
            ms.get("/new/sub/deep").unwrap().unwrap().path,
            "/new/sub/deep"
        );
        assert_eq!(
            ms.get_file_metadata("/new/child", "tag").unwrap(),
            Some("value".to_string())
        );
    }

    #[test]
    fn local_rename_path_replaces_an_existing_destination() {
        // `rename(2)` replaces. The main-table insert overwrites on its own;
        // this holds the part that does not — the destination's side-car
        // entries, whose keys embed the path and would otherwise survive under
        // the new path and look like they belong to the file that replaced it.
        let (_td, ms) = fresh_local();
        ms.put("/src", mk_meta("/src", 7)).unwrap();
        ms.set_file_metadata("/src", "from_src", "yes".to_string())
            .unwrap();
        ms.put("/dst", mk_meta("/dst", 1)).unwrap();
        ms.set_file_metadata("/dst", "from_dst", "stale".to_string())
            .unwrap();

        ms.rename_path("/src", "/dst", true).unwrap();

        assert!(ms.get("/src").unwrap().is_none());
        assert_eq!(ms.get("/dst").unwrap().unwrap().version, 7);
        assert_eq!(
            ms.get_file_metadata("/dst", "from_src").unwrap(),
            Some("yes".to_string())
        );
        assert_eq!(
            ms.get_file_metadata("/dst", "from_dst").unwrap(),
            None,
            "the replaced file's side-car entries must not survive under the new path"
        );
    }

    #[test]
    fn local_set_and_get_file_metadata() {
        let (_td, ms) = fresh_local();
        ms.set_file_metadata("/x", "parsed_text", "hello".to_string())
            .unwrap();
        assert_eq!(
            ms.get_file_metadata("/x", "parsed_text").unwrap(),
            Some("hello".to_string())
        );
        assert_eq!(ms.get_file_metadata("/x", "missing").unwrap(), None);
    }

    #[test]
    fn local_is_implicit_directory() {
        let (_td, ms) = fresh_local();
        ms.put("/dir/a", mk_meta("/dir/a", 1)).unwrap();
        assert!(ms.is_implicit_directory("/dir").unwrap());
        assert!(!ms.is_implicit_directory("/empty").unwrap());
    }

    #[test]
    fn local_list_paginated_slices_and_returns_cursor() {
        let (_td, ms) = fresh_local();
        for i in 0..5 {
            let p = format!("/{i:02}");
            ms.put(&p, mk_meta(&p, 1)).unwrap();
        }
        let page = ms.list_paginated("", true, 2, None).unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(page.has_more);
        assert_eq!(page.total_count, 5);
        let page2 = ms
            .list_paginated("", true, 2, page.next_cursor.as_deref())
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        assert!(page2.has_more);
    }

    #[test]
    fn local_delete_clears_file_metadata() {
        let (_td, ms) = fresh_local();
        ms.put("/x", mk_meta("/x", 1)).unwrap();
        ms.set_file_metadata("/x", "k", "v".to_string()).unwrap();
        ms.delete("/x").unwrap();
        assert_eq!(ms.get_file_metadata("/x", "k").unwrap(), None);
    }

    #[test]
    fn test_serialize_all_none() {
        let meta = FileMetadata {
            path: "/x".to_string(),
            size: 0,
            content_id: None,
            gen: 0,
            version: 1,
            entry_type: 0,
            zone_id: None,
            mime_type: None,
            created_at_ms: None,
            modified_at_ms: None,
            last_writer_address: None,
            target_zone_id: None,
            target_subtree: None,
            link_target: None,
            owner_id: None,
        };
        let data = serialize_metadata(&meta);
        let restored = deserialize_metadata(&data).unwrap();
        assert_eq!(restored.path, "/x");
        assert!(restored.content_id.is_none());
        assert!(restored.zone_id.is_none());
        assert!(restored.mime_type.is_none());
    }
}
