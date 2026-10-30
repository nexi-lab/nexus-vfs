//! Namespace mutation, policy checks and revision changes share one SC transaction.

use super::*;

#[cfg(all(feature = "grpc", has_protos))]
#[inline(never)]
fn decode_rename_entry(
    image: &[u8],
    path: &str,
) -> std::result::Result<crate::transport::proto::nexus::core::FileMetadata, String> {
    use kernel::meta_store::{DT_DIR, DT_LINK, DT_REG};
    use prost::Message;

    let metadata = crate::transport::proto::nexus::core::FileMetadata::decode(image)
        .map_err(|error| format!("rename metadata decode({path}): {error}"))?;
    if ![i32::from(DT_REG), i32::from(DT_DIR), i32::from(DT_LINK)].contains(&metadata.entry_type) {
        return Err(format!(
            "rename metadata({path}) requires a file, directory or link entry"
        ));
    }
    Ok(metadata)
}

#[cfg(all(feature = "grpc", has_protos))]
impl FullStateMachine {
    pub(super) fn rename_metadata_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        old_key: &str,
        new_key: &str,
        is_pas: bool,
    ) -> Result<CommandResult> {
        use prost::Message;

        for path in [old_key, new_key] {
            if let Err(error) = kernel::kernel::validate_path_fast(path) {
                return Ok(CommandResult::Error(error.to_string()));
            }
        }
        if old_key == new_key {
            return Ok(CommandResult::Success);
        }
        let prefix = format!("{}/", old_key.trim_end_matches('/'));
        if old_key == "/" || new_key == "/" || new_key.starts_with(&prefix) {
            return Ok(CommandResult::Error(
                "invalid metadata rename destination".into(),
            ));
        }
        let rows = self.metadata_rename_rows(txn, old_key, &prefix)?;
        if let Some(refusal) = self.rename_target_refusal(txn, new_key)? {
            return Ok(CommandResult::Error(refusal));
        }
        let target_prefix = format!("{}/", new_key.trim_end_matches('/'));
        let mut changes = Vec::with_capacity(rows.len());
        for (source, image) in rows {
            let target = if source == old_key {
                new_key.to_owned()
            } else {
                format!("{target_prefix}{}", &source[prefix.len()..])
            };
            for path in [&source, &target] {
                if let Some(refusal) = self.ordinary_metadata_refusal(txn, path)? {
                    return Ok(refusal);
                }
            }
            let mut metadata = match decode_rename_entry(&image, &source) {
                Ok(metadata) => metadata,
                Err(error) => return Ok(CommandResult::Error(error)),
            };
            if let Some(refusal) = self.rename_target_refusal(txn, &target)? {
                return Ok(CommandResult::Error(refusal));
            }
            metadata.path = target.clone();
            if is_pas {
                if let Some(content_id) = kernel::abc::meta_store::renamed_pas_content_id(
                    &metadata.content_id,
                    &source,
                    &target,
                ) {
                    metadata.content_id = content_id;
                }
            }
            changes.push((source, target, metadata.encode_to_vec()));
        }
        // All logical refusals precede mutation. Storage errors abort this redb
        // transaction together with the enclosing last-applied marker.
        for (source, target, _) in &changes {
            let tracked = self.refresh_tracked_version(txn, source)?;
            if tracked && conditional_metadata::is_managed_key(target) {
                // The source image is already admitted. Its new path receives
                // a fresh revision in this same transaction, including when
                // no metadata has previously occupied the destination.
                self.allocate_revision(txn, target, None)?;
            } else {
                self.refresh_tracked_version(txn, target)?;
            }
        }
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
        for (source, _, _) in &changes {
            table
                .remove(source.as_bytes())
                .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
        }
        for (_, target, image) in &changes {
            table
                .insert(target.as_bytes(), image.as_slice())
                .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
        }
        Ok(CommandResult::Success)
    }

    fn rename_target_refusal(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<Option<String>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
        let image = table
            .get(path.as_bytes())
            .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
        Ok(image.and_then(|image| decode_rename_entry(image.value(), path).err()))
    }

    fn metadata_rename_rows(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
        prefix: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
        let mut rows = Vec::new();
        if let Some(image) = table
            .get(key.as_bytes())
            .map_err(|error| super::super::RaftError::Storage(error.to_string()))?
        {
            rows.push((key.to_owned(), image.value().to_vec()));
        }
        for item in table
            .range(prefix.as_bytes()..)
            .map_err(|error| super::super::RaftError::Storage(error.to_string()))?
        {
            let (key, value) =
                item.map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
            if !key.value().starts_with(prefix.as_bytes()) {
                break;
            }
            let key = std::str::from_utf8(key.value())
                .map_err(|error| super::super::RaftError::Storage(error.to_string()))?;
            rows.push((key.to_owned(), value.value().to_vec()));
        }
        Ok(rows)
    }
}

#[cfg(not(all(feature = "grpc", has_protos)))]
impl FullStateMachine {
    pub(super) fn rename_metadata_in_txn(
        &self,
        _: &redb::WriteTransaction,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<CommandResult> {
        Ok(CommandResult::Error(
            "metadata rename requires the metadata codec".into(),
        ))
    }
}
