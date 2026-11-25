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
        check_namespace: bool,
    ) -> Result<CommandResult> {
        use prost::Message;

        for path in [old_key, new_key] {
            if let Err(error) = kernel::kernel::validate_path_fast(path) {
                return Ok(CommandResult::Error(error.to_string()));
            }
        }
        if old_key == new_key && !check_namespace {
            return Ok(CommandResult::Success);
        }
        let prefix = format!("{}/", old_key.trim_end_matches('/'));
        if old_key == "/" || new_key == "/" || new_key.starts_with(&prefix) {
            return Ok(CommandResult::Error(
                "invalid metadata rename destination".into(),
            ));
        }
        let rows = self.metadata_rename_rows(txn, old_key, &prefix)?;
        if check_namespace && rows.is_empty() {
            return Ok(CommandResult::Error(format!(
                "rename source does not exist: {old_key}"
            )));
        }
        if old_key == new_key {
            return Ok(CommandResult::Success);
        }
        let target_prefix = format!("{}/", new_key.trim_end_matches('/'));
        if check_namespace {
            if rows.first().is_some_and(|(key, _)| key != old_key) {
                for path in [old_key, new_key] {
                    if let Some(refusal) = self.ordinary_metadata_refusal(txn, path)? {
                        return Ok(refusal);
                    }
                }
            }
            if let Some(refusal) =
                self.namespace_target_refusal(txn, old_key, new_key, &rows, &target_prefix)?
            {
                return Ok(CommandResult::Error(refusal));
            }
        } else if let Some(refusal) = self.rename_target_refusal(txn, new_key)? {
            return Ok(CommandResult::Error(refusal));
        }
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
            if target != new_key && !check_namespace {
                if let Some(refusal) = self.rename_target_refusal(txn, &target)? {
                    return Ok(CommandResult::Error(refusal));
                }
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

    /// Apply checks the current shape at the destination, including an implicit directory.
    /// A concurrent writer can change that shape after the syscall's access checks.
    fn namespace_target_refusal(
        &self,
        txn: &redb::WriteTransaction,
        old: &str,
        new: &str,
        rows: &[(String, Vec<u8>)],
        target_prefix: &str,
    ) -> Result<Option<String>> {
        use kernel::meta_store::DT_DIR;
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(conditional_metadata::storage_error)?;
        let has_children = table
            .range(target_prefix.as_bytes()..)
            .map_err(conditional_metadata::storage_error)?
            .next()
            .transpose()
            .map_err(conditional_metadata::storage_error)?
            .is_some_and(|(k, _)| k.value().starts_with(target_prefix.as_bytes()));
        if has_children {
            return Ok(Some("cannot replace a directory".into()));
        }
        let Some(target) = table
            .get(new.as_bytes())
            .map_err(conditional_metadata::storage_error)?
        else {
            return Ok(None);
        };
        match decode_rename_entry(target.value(), new) {
            Ok(meta) if meta.entry_type == i32::from(DT_DIR) => {
                return Ok(Some("cannot replace a directory".into()))
            }
            Err(error) => return Ok(Some(error)),
            _ => {}
        }
        if let Some((key, image)) = rows.first() {
            if key == old {
                return Ok(match decode_rename_entry(image, old) {
                    Ok(meta) if meta.entry_type != i32::from(DT_DIR) && rows.len() == 1 => None,
                    Ok(_) => Some("cannot rename a directory over a file".into()),
                    Err(error) => Some(error),
                });
            }
        }
        Ok(Some("cannot rename a directory over a file".into()))
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
        _: bool,
    ) -> Result<CommandResult> {
        Ok(CommandResult::Error(
            "metadata rename requires the metadata codec".into(),
        ))
    }
}

#[cfg(all(test, feature = "grpc", has_protos))]
mod namespace_tests {
    use super::*;
    use prost::Message;

    fn put(path: &str) -> Command {
        Command::SetMetadata {
            key: path.into(),
            value: crate::transport::proto::nexus::core::FileMetadata {
                path: path.into(),
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    #[test]
    fn namespace_checks_both_paths_at_apply_and_preserves_a_refused_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::storage::RedbStore::open(dir.path().join("sm")).unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let mut i = 0;
        for path in ["/file", "/tree/file", "/tree/second", "/occupied/child"] {
            i += 1;
            sm.apply(i, &put(path)).unwrap();
        }
        let previous = sm.list_metadata("/").unwrap();
        for (src, dst) in [
            ("/absent", "/file"),
            ("/absent", "/absent"),
            ("/tree", "/file"),
            ("/file", "/occupied"),
            ("/tree", "/tree/deeper"),
        ] {
            i += 1;
            let result = sm
                .apply(
                    i,
                    &Command::RenameNamespaceV1 {
                        old_key: src.into(),
                        new_key: dst.into(),
                        is_pas: false,
                    },
                )
                .unwrap();
            assert!(matches!(result, CommandResult::Error(_)), "{src} -> {dst}");
            assert_eq!(sm.list_metadata("/").unwrap(), previous);
        }
        i += 1;
        let image = sm.get_metadata("/tree/second").unwrap();
        let adopted = sm
            .apply(
                i,
                &Command::AdoptProtectedMetadata {
                    key: "/tree/second".into(),
                    expected_image: image,
                    incarnation: [9; 16],
                },
            )
            .unwrap();
        i += 1;
        assert!(matches!(
            adopted,
            CommandResult::ProtectedMetadata { protected: true }
        ));
        let refusal = sm
            .apply(
                i,
                &Command::RenameNamespaceV1 {
                    old_key: "/tree".into(),
                    new_key: "/moved".into(),
                    is_pas: false,
                },
            )
            .unwrap();
        assert!(matches!(refusal, CommandResult::Error(_)));
        assert_eq!(sm.list_metadata("/").unwrap(), previous);
    }
}
