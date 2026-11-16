//! Durable issuance of complete CRLs from the existing revocation authority.

use super::{generate_crl_at, read_revoked_serials_checked, RevocationGuard};
use lib::transport_primitives::{ca_spki_sha256, canonical_certificate_serial, verify_signed_crl};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};

const ISSUED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("issued_crls_v1");
const REUSE_SECONDS: i64 = 30;
// The previous signer emitted u64 entry counts. Starting above that whole
// range preserves ordering even when earlier pruning erased the largest count.
const FIRST_NUMBER: [u8; 9] = [1, 0, 0, 0, 0, 0, 0, 0, 0];

/// The signed snapshot is the durable issuance receipt and sequence authority.
/// Revoked certificate membership continues to come from `revoked_serials`.
pub(in crate::transport) struct CrlIssuer {
    database: Database,
    revoked_serials: PathBuf,
    ca: Vec<u8>,
    key: Vec<u8>,
    authority: [u8; 32],
}

impl CrlIssuer {
    pub(in crate::transport) fn open(path: &Path, ca: &[u8], key: &[u8]) -> Result<Self, String> {
        let authority = ca_spki_sha256(ca)?;
        let journal = path.with_extension("crl.redb");
        let mut builder = Database::builder();
        builder.set_cache_size(1024 * 1024);
        let database = lib::redb_storage::open_or_create(&journal, &builder)
            .map_err(|e| format!("CRL journal: {e}"))?;
        Ok(Self {
            database,
            revoked_serials: path.to_owned(),
            ca: ca.to_vec(),
            key: key.to_vec(),
            authority,
        })
    }

    pub(in crate::transport) fn issue(&self) -> Result<Vec<u8>, String> {
        self.issue_at(time::OffsetDateTime::now_utc())
    }

    fn issue_at(&self, now: time::OffsetDateTime) -> Result<Vec<u8>, String> {
        // Share the existing revoke/prune/credential-signing boundary. The
        // snapshot and its sequence commit before another writer can proceed.
        let _guard = RevocationGuard::acquire(&self.revoked_serials)?;
        let serials = canonical_serials(
            &read_revoked_serials_checked(&self.revoked_serials)
                .map_err(|e| format!("read current revocations: {e}"))?,
        )?;
        let mut transaction = self.database.begin_write().map_err(store_error)?;
        transaction
            .set_durability(redb::Durability::Immediate)
            .map_err(store_error)?;
        let mut table = transaction.open_table(ISSUED).map_err(store_error)?;
        let previous = table
            .get(self.authority.as_slice())
            .map_err(store_error)?
            .map(|value| value.value().to_vec());
        let number = if let Some(bytes) = &previous {
            let snapshot = verify_signed_crl(bytes, &self.ca)
                .map_err(|e| format!("stored CRL receipt: {e}"))?;
            if snapshot.number().len() < FIRST_NUMBER.len() {
                return Err("stored CRL receipt predates durable sequencing".into());
            }
            let age = now
                .unix_timestamp()
                .checked_sub(snapshot.this_update())
                .ok_or("stored CRL clock difference overflow")?;
            if age < 0 {
                return Err("current clock precedes the stored CRL receipt".into());
            }
            if age < REUSE_SECONDS
                && snapshot
                    .check_freshness(now.unix_timestamp(), REUSE_SECONDS as u32)
                    .is_ok()
                && canonical_serials(snapshot.revoked_serials())? == serials
            {
                // Re-serving the exact signed bytes issues no new snapshot.
                return Ok(bytes.clone());
            }
            next_number(snapshot.number())?
        } else {
            FIRST_NUMBER.to_vec()
        };
        let bytes = generate_crl_at(&serials, &number, &self.ca, &self.key, now)?;
        verify_signed_crl(&bytes, &self.ca)?.check_freshness(now.unix_timestamp(), 1)?;
        table
            .insert(self.authority.as_slice(), bytes.as_slice())
            .map_err(store_error)?;
        drop(table);
        transaction.commit().map_err(store_error)?;
        Ok(bytes)
    }
}

fn store_error(error: impl std::fmt::Display) -> String {
    format!("CRL issuance transaction: {error}")
}

fn canonical_serials(serials: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let mut canonical = serials
        .iter()
        .map(|serial| canonical_certificate_serial(serial).map(<[u8]>::to_vec))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

fn next_number(previous: &[u8]) -> Result<Vec<u8>, String> {
    if previous.is_empty() || previous.len() > 20 {
        return Err("invalid stored CRL number".into());
    }
    let mut number = previous.to_vec();
    for byte in number.iter_mut().rev() {
        let (value, overflow) = byte.overflowing_add(1);
        *byte = value;
        if !overflow {
            return Ok(number);
        }
    }
    if number.len() == 20 {
        return Err("CRL number exhausted".into());
    }
    number.insert(0, 1);
    Ok(number)
}

#[cfg(test)]
mod tests;
