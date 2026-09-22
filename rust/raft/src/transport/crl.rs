//! Agent-cert revocation via a CA-signed Certificate Revocation List.
//!
//! A valid CA chain does not settle revocation: a stolen agent key still chains
//! to the cluster CA, so `peer_identity` still resolves it. The CRL closes that,
//! and it rides the CA's own trust plane — NOT raft:
//!
//! * the founder holds the revoked-serial file ([`revoked_serials_path`]) and
//!   CA-signs a CRL over it on demand ([`generate_crl`]);
//! * every other node fetches that CRL and verifies it against the CA cert it
//!   already holds ([`crl_revoked_serials`]), so a forged CRL cannot un-revoke
//!   or falsely revoke;
//! * `auth revoke` appends a serial ([`add_revoked_serial`]); the running
//!   `GetCrl` endpoint reads it live, so revocation needs no restart.
//!
//! Because the CRL is self-authenticating (CA-signed), it can travel over the
//! plaintext enroll plane — the same plane that hands out the CA itself.

use std::path::{Path, PathBuf};

/// Validity window stamped into a CRL's `next_update`. Cosmetic to our own
/// verification (which trusts the CA signature, not the clock) but honest to
/// any standard CRL reader; nodes refresh far more often than this regardless.
const CRL_VALIDITY_DAYS: i64 = 30;

/// The raw serial-number bytes of a certificate (PEM in). An agent cert's
/// serial is what the CRL revokes and what `resolve` matches a presented cert
/// against, so the mint side (recording a serial) and the resolve side read it
/// back the same way here.
pub fn serial_from_cert_pem(cert_pem: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::*;
    let pem = ::pem::parse(cert_pem).map_err(|e| format!("cert PEM: {e}"))?;
    let (_, cert) =
        X509Certificate::from_der(pem.contents()).map_err(|e| format!("cert DER: {e}"))?;
    Ok(cert.raw_serial().to_vec())
}

/// Build a CA-signed X.509 Certificate Revocation List over `revoked_serials`
/// (each an agent cert's raw serial bytes, as from [`serial_from_cert_pem`]).
///
/// Because it is signed by the cluster CA, any node holding only the CA cert
/// can verify it and read the revoked set (see [`crl_revoked_serials`]) — so it
/// distributes like the CA itself, orthogonal to raft. `crl_number` must only
/// grow across successive CRLs so a stale one is detectable.
pub fn generate_crl(
    revoked_serials: &[Vec<u8>],
    crl_number: u64,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
) -> Result<Vec<u8>, String> {
    use rcgen::{
        CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber,
    };
    let ca_issuer = super::certgen::ca_issuer_from_pem(ca_cert_pem, ca_key_pem)?;
    let now = time::OffsetDateTime::now_utc();
    let revoked_certs = revoked_serials
        .iter()
        .map(|s| RevokedCertParams {
            serial_number: SerialNumber::from(s.clone()),
            revocation_time: now,
            reason_code: Some(RevocationReason::Unspecified),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(CRL_VALIDITY_DAYS),
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = params
        .signed_by(&ca_issuer)
        .map_err(|e| format!("Failed to sign CRL: {e}"))?;
    Ok(crl.pem().map_err(|e| format!("CRL PEM: {e}"))?.into_bytes())
}

/// Verify a CRL against the cluster CA and return the revoked serials (raw
/// bytes). A CRL not signed by the CA is rejected — that signature is exactly
/// what lets a node trust a CRL fetched over the plaintext CA plane, the same
/// way it trusts a cert.
pub fn crl_revoked_serials(crl_pem: &[u8], ca_cert_pem: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    use x509_parser::prelude::*;
    let ca = ::pem::parse(ca_cert_pem).map_err(|e| format!("CA PEM: {e}"))?;
    let (_, ca_cert) =
        X509Certificate::from_der(ca.contents()).map_err(|e| format!("CA DER: {e}"))?;
    let crl = ::pem::parse(crl_pem).map_err(|e| format!("CRL PEM: {e}"))?;
    let (_, crl) =
        CertificateRevocationList::from_der(crl.contents()).map_err(|e| format!("CRL DER: {e}"))?;
    crl.verify_signature(ca_cert.public_key())
        .map_err(|e| format!("CRL not signed by cluster CA: {e}"))?;
    Ok(crl
        .iter_revoked_certificates()
        .map(|rc| rc.raw_serial().to_vec())
        .collect())
}

/// The founder's revoked-serial file: one revoked agent-cert serial per line
/// (base64). SSOT for revocation state, and the seam between the offline
/// `auth revoke` (which appends here) and the running founder's `GetCrl` (which
/// reads here to build the CRL) — so a revocation takes effect without a
/// daemon restart. Founder-side only; joiners learn revocations via the CRL.
pub fn revoked_serials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls").join("revoked-serials")
}

/// One line of the revoked-serial file: a serial, and when the certificate it
/// names stops being able to authenticate anything.
///
/// `not_after_unix` is `None` for a line written before this field existed, and
/// for one recorded from a source that does not carry it (an X.509 CRL entry
/// has a revocation date, not the certificate's expiry). Unknown is never
/// treated as expired — see [`prune_expired_serials`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedEntry {
    pub serial: Vec<u8>,
    pub not_after_unix: Option<i64>,
}

/// Read the revoked entries from the founder's revoked-serial file.
///
/// A missing file is an empty list, and an unparseable line is skipped rather
/// than fatal — an unreadable line must not crash the CRL endpoint.
///
/// Line format is `<base64 serial>` optionally followed by a space and the
/// certificate's `notAfter` as a unix timestamp. A line without the timestamp
/// is a pre-existing entry and reads back with `not_after_unix: None`, which is
/// what makes adding the field a format extension rather than a migration.
pub fn read_revoked_entries(path: &Path) -> Vec<RevokedEntry> {
    use base64::Engine;
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let (b64, rest) = match l.split_once(' ') {
                Some((b64, rest)) => (b64, Some(rest.trim())),
                None => (l, None),
            };
            let serial = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            Some(RevokedEntry {
                serial,
                // A malformed timestamp reads as unknown rather than dropping
                // the line: losing the expiry costs a prune, losing the line
                // un-revokes a certificate.
                not_after_unix: rest.and_then(|r| r.parse::<i64>().ok()),
            })
        })
        .collect()
}

/// The revoked serials (raw bytes) — what the CRL is built from. Thin view over
/// [`read_revoked_entries`] so the file is parsed in one place.
pub fn read_revoked_serials(path: &Path) -> Vec<Vec<u8>> {
    read_revoked_entries(path)
        .into_iter()
        .map(|e| e.serial)
        .collect()
}

/// Serialise entries and replace the file atomically.
///
/// Write-temp-then-rename, because the previous `fs::write` truncated the live
/// revocation list before writing it: a crash in that window left an empty
/// file, which does not fail closed — it silently un-revokes every certificate
/// on it. A rename either happens or does not.
fn write_revoked_entries(path: &Path, entries: &[RevokedEntry]) -> Result<(), String> {
    use base64::Engine;
    let body = entries
        .iter()
        .map(|e| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&e.serial);
            match e.not_after_unix {
                Some(ts) => format!("{b64} {ts}"),
                None => b64,
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{body}\n"))
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

/// Record one revoked serial, with the certificate's `notAfter` when the caller
/// knows it. Idempotent on the serial; creates the file if absent.
///
/// Passing the expiry is what later lets the entry be pruned once it can no
/// longer authenticate anything — see [`prune_expired_serials`]. `None` is
/// honest when the source does not carry it, and costs only that the entry
/// stays forever.
pub fn add_revoked_serial_with_expiry(
    path: &Path,
    serial: &[u8],
    not_after_unix: Option<i64>,
) -> Result<(), String> {
    let mut entries = read_revoked_entries(path);
    if let Some(existing) = entries.iter_mut().find(|e| e.serial == serial) {
        // Re-revoking is a no-op except that a caller who knows the expiry
        // teaches it to an entry that did not have one.
        if existing.not_after_unix.is_none() && not_after_unix.is_some() {
            existing.not_after_unix = not_after_unix;
            return write_revoked_entries(path, &entries);
        }
        return Ok(());
    }
    entries.push(RevokedEntry {
        serial: serial.to_vec(),
        not_after_unix,
    });
    write_revoked_entries(path, &entries)
}

/// Record one revoked serial with no known expiry — the offline `auth revoke`
/// write, which reads a serial off a cert bundle on disk.
pub fn add_revoked_serial(path: &Path, serial: &[u8]) -> Result<(), String> {
    add_revoked_serial_with_expiry(path, serial, None)
}

/// Drop entries for certificates that expired more than `skew_margin_secs` ago.
///
/// A revocation entry answers "should this certificate be refused while it is
/// still otherwise valid". Once the certificate is past its own `notAfter`
/// every verifier refuses it anyway, so the entry has stopped deciding
/// anything — and keeping it means a list that grows without bound for
/// credentials that live minutes.
///
/// Three rules, each of which exists to avoid un-revoking something real:
///
/// * Prune by the certificate's own `notAfter`, never by when the entry was
///   written or by a store-level TTL. Those would drop serials for
///   certificates still inside their validity window, which is precisely the
///   case revocation exists for.
/// * Require `now > not_after + skew_margin_secs`. A verifier with a slow
///   clock may still be inside the window after we think it closed.
/// * An entry whose expiry is unknown is never pruned. Unknown is not expired.
///
/// Returns how many were dropped. Writes only when something was.
pub fn prune_expired_serials(
    path: &Path,
    now_unix: i64,
    skew_margin_secs: i64,
) -> Result<usize, String> {
    let entries = read_revoked_entries(path);
    let before = entries.len();
    let kept: Vec<RevokedEntry> = entries
        .into_iter()
        .filter(|e| match e.not_after_unix {
            Some(exp) => now_unix <= exp.saturating_add(skew_margin_secs),
            None => true,
        })
        .collect();
    let dropped = before - kept.len();
    if dropped > 0 {
        write_revoked_entries(path, &kept)?;
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::certgen::{generate_agent_cert, generate_zone_ca};

    /// Pruning drops only what can no longer decide anything, and the three
    /// rules that keep it from un-revoking something real are asserted one by
    /// one: expiry comes from the certificate, the skew margin is honoured, and
    /// an unknown expiry survives forever.
    #[test]
    fn pruning_drops_expired_entries_and_never_the_unknown_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tls").join("revoked-serials");
        let now = 1_000_000i64;
        let margin = 300i64;

        // Long expired; inside the margin; not yet expired; expiry unknown.
        add_revoked_serial_with_expiry(&path, b"old", Some(now - 10_000)).unwrap();
        add_revoked_serial_with_expiry(&path, b"recent", Some(now - 100)).unwrap();
        add_revoked_serial_with_expiry(&path, b"live", Some(now + 10_000)).unwrap();
        add_revoked_serial(&path, b"legacy").unwrap();

        let dropped = prune_expired_serials(&path, now, margin).unwrap();
        assert_eq!(dropped, 1, "only the long-expired entry is prunable");

        let kept: Vec<Vec<u8>> = read_revoked_serials(&path);
        assert!(
            !kept.contains(&b"old".to_vec()),
            "expired past the margin is dropped"
        );
        assert!(
            kept.contains(&b"recent".to_vec()),
            "inside the skew margin a slow clock may still be in the window"
        );
        assert!(
            kept.contains(&b"live".to_vec()),
            "still valid, still revoked"
        );
        assert!(
            kept.contains(&b"legacy".to_vec()),
            "unknown expiry is not expired — a pre-existing line must survive"
        );

        // Idempotent: nothing left to drop, and the file is untouched.
        assert_eq!(prune_expired_serials(&path, now, margin).unwrap(), 0);
        assert_eq!(read_revoked_serials(&path).len(), 3);
    }

    /// The file gained an optional field, so lines written before it must keep
    /// reading as revocations — losing one would silently un-revoke a cert.
    #[test]
    fn a_line_without_an_expiry_still_reads_as_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoked-serials");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Exactly what the previous format wrote: base64, one per line.
        std::fs::write(&path, "b2xk\nbmV3IA==\n").unwrap();

        let entries = read_revoked_entries(&path);
        assert_eq!(entries.len(), 2, "both legacy lines parse");
        assert!(
            entries.iter().all(|e| e.not_after_unix.is_none()),
            "a legacy line has no expiry, so it is never prunable"
        );
        assert_eq!(prune_expired_serials(&path, i64::MAX / 2, 0).unwrap(), 0);
    }

    /// Re-revoking a serial is a no-op, except that a caller who knows the
    /// expiry teaches it to an entry recorded without one — which is how a
    /// legacy entry becomes prunable instead of staying forever.
    #[test]
    fn re_revoking_with_an_expiry_fills_in_an_unknown_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoked-serials");

        add_revoked_serial(&path, b"s").unwrap();
        assert_eq!(read_revoked_entries(&path)[0].not_after_unix, None);

        add_revoked_serial_with_expiry(&path, b"s", Some(42)).unwrap();
        let entries = read_revoked_entries(&path);
        assert_eq!(entries.len(), 1, "still one entry, not a duplicate");
        assert_eq!(entries[0].not_after_unix, Some(42));

        // And a later write with no expiry does not erase what we learned.
        add_revoked_serial(&path, b"s").unwrap();
        assert_eq!(read_revoked_entries(&path)[0].not_after_unix, Some(42));
    }

    /// The revocation round-trip: an agent cert's serial is recoverable, a
    /// CA-signed CRL over it verifies against the CA and yields that serial
    /// back, and a CRL signed by a foreign CA is rejected — the CA signature is
    /// the whole trust of the CRL, exactly as it is for a cert.
    #[test]
    fn crl_over_an_agent_serial_verifies_only_under_its_ca() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert_pem, _key) = generate_agent_cert("win-ai", &ca, &ca_key).unwrap();
        let serial = serial_from_cert_pem(&cert_pem).expect("read the cert serial");
        assert!(!serial.is_empty(), "a cert carries a non-empty serial");

        let crl =
            generate_crl(std::slice::from_ref(&serial), 1, &ca, &ca_key).expect("sign the CRL");
        let revoked = crl_revoked_serials(&crl, &ca).expect("verify under the CA");
        assert!(
            revoked.iter().any(|s| s == &serial),
            "the revoked serial round-trips through the CRL"
        );

        // A CRL minted by a foreign CA claiming the same serial is rejected —
        // only the cluster CA can author a CRL a node will honor.
        let (evil_ca, evil_key) = generate_zone_ca("evil").unwrap();
        let forged = generate_crl(&[serial], 1, &evil_ca, &evil_key).unwrap();
        assert!(
            crl_revoked_serials(&forged, &ca).is_err(),
            "a foreign-CA CRL fails signature verification against the cluster CA"
        );
    }

    /// The revoked-serial file round-trips through base64, dedups on re-add, and
    /// reads empty when absent — the SSOT the founder's CRL is built from.
    #[test]
    fn revoked_serial_file_round_trips_and_dedups() {
        let tmp = tempfile::tempdir().unwrap();
        let path = revoked_serials_path(tmp.path());
        assert!(
            read_revoked_serials(&path).is_empty(),
            "absent file is empty"
        );

        add_revoked_serial(&path, &[1, 2, 3]).unwrap();
        add_revoked_serial(&path, &[4, 5, 6]).unwrap();
        add_revoked_serial(&path, &[1, 2, 3]).unwrap(); // idempotent

        let got = read_revoked_serials(&path);
        assert_eq!(got.len(), 2, "duplicate serial is not re-added");
        assert!(got.contains(&vec![1, 2, 3]) && got.contains(&vec![4, 5, 6]));
    }
}
