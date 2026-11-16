//! Persistent log replacement uses the same transaction for removal and append.

use super::*;

fn storage_error(error: impl std::fmt::Display) -> RaftError {
    RaftError::Storage(format!("append Raft log: {error}"))
}

fn decode_index(bytes: &[u8]) -> Result<u64> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| storage_error("invalid stored index"))
}

impl RaftStorage {
    pub(super) fn replace_suffix(&self, entries: &[Entry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].index.checked_add(1) != Some(pair[1].index))
        {
            return Err(storage_error("entries must have contiguous indices"));
        }

        let txn = self.state.raw_db().begin_write().map_err(storage_error)?;
        {
            let state = txn
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                    self.state.name(),
                ))
                .map_err(storage_error)?;
            let first_record = state.get(KEY_FIRST_INDEX).map_err(storage_error)?;
            let first = reader_format::LogBoundary::decode(
                first_record.as_ref().map(|value| value.value()),
            )?
            .index;
            if entries[0].index < first {
                return Err(storage_error("append would overwrite compacted entries"));
            }
            let hard_state: HardState = state
                .get(KEY_HARD_STATE)
                .map_err(storage_error)?
                .map(|value| protobuf::Message::parse_from_bytes(value.value()))
                .transpose()
                .map_err(storage_error)?
                .unwrap_or_default();
            let mut table = txn
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                    self.entries.name(),
                ))
                .map_err(storage_error)?;
            let last = table
                .last()
                .map_err(storage_error)?
                .map(|(key, _)| decode_index(key.value()))
                .transpose()?
                .unwrap_or(first.saturating_sub(1));
            if entries[0].index > last.saturating_add(1) {
                return Err(storage_error("append would leave a gap"));
            }
            let end = entries.last().expect("nonempty retained entries").index;
            if end < hard_state.commit {
                return Err(storage_error("append would truncate committed entries"));
            }
            for entry in entries
                .iter()
                .take_while(|entry| entry.index <= hard_state.commit)
            {
                let existing = table
                    .get(entry.index.to_be_bytes().as_slice())
                    .map_err(storage_error)?
                    .ok_or_else(|| storage_error("committed entry is absent"))?;
                let previous: Entry =
                    protobuf::Message::parse_from_bytes(existing.value()).map_err(storage_error)?;
                if previous != *entry {
                    return Err(storage_error("append would replace a committed entry"));
                }
            }

            // A shorter replacement must remove the old tail. Otherwise a
            // restart advertises entries the current leader already discarded.
            let start = entries[0].index.to_be_bytes();
            table
                .retain_in(start.as_slice().., |_, _| false)
                .map_err(storage_error)?;
            for entry in entries {
                let bytes = protobuf::Message::write_to_bytes(entry).map_err(storage_error)?;
                table
                    .insert(entry.index.to_be_bytes().as_slice(), bytes.as_slice())
                    .map_err(storage_error)?;
            }
        }
        txn.commit().map_err(storage_error)
    }
}

#[cfg(test)]
mod tests;
