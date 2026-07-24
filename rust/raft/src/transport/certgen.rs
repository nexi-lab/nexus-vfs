//! Server-side node certificate generation for JoinCluster RPC, plus
//! Day-1 TLS bootstrap (CA + node cert + join token) for fresh clusters.
//!
//! Generates X.509 node certificates signed by the cluster CA, matching
//! the output of Python `certgen.py`: EC P-256, SHA-256, mTLS-ready SANs.
//!
//! The CA private key never leaves node-1 — this module is called server-side
//! during JoinCluster to sign certs for joining nodes.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Validity window for a node certificate.
///
/// 90 days follows the Let's Encrypt convention — short enough that an
/// expired-cert incident drives rotation discipline, long enough that
/// routine ops don't churn certs. The CA outlives node certs (see
/// `CA_VALIDITY_DAYS`); operators rotate node certs by redeploying the
/// daemon, which re-runs the Day-1 bootstrap.
const NODE_CERT_VALIDITY_DAYS: i64 = 90;

/// Validity window for the cluster CA. Long-lived by design — every
/// node cert in the cluster chains to this CA, so rotating it requires
/// reissuing all node certs. 10 years lines up with public-CA
/// long-lived-root conventions (DigiCert / ISRG Root X1 / Amazon Root
/// CA all sit at 10-20y).
const CA_VALIDITY_DAYS: i64 = 365 * 10;

/// Scheme + authority of the identity URI SAN. Certificates are the
/// only place a node's identity is stated in a way the far end can
/// verify, so the format lives here — next to the code that mints it —
/// and `transport::peer_identity` reads it back through
/// [`parse_node_identity_uri`] rather than re-spelling it.
const NODE_IDENTITY_URI_PREFIX: &str = "nexus://zone/";

/// Build the identity URI SAN pinned into a node certificate:
/// `nexus://zone/{zone_id}/node/{node_id}`.
pub fn node_identity_uri(zone_id: &str, node_id: u64) -> String {
    format!("{NODE_IDENTITY_URI_PREFIX}{zone_id}/node/{node_id}")
}

/// Inverse of [`node_identity_uri`] — `None` for any URI that is not
/// ours or is malformed (a foreign SAN must never resolve to a peer).
pub fn parse_node_identity_uri(uri: &str) -> Option<(String, u64)> {
    let rest = uri.strip_prefix(NODE_IDENTITY_URI_PREFIX)?;
    let (zone_id, node_id) = rest.split_once("/node/")?;
    if zone_id.is_empty() {
        return None;
    }
    Some((zone_id.to_string(), node_id.parse().ok()?))
}

/// Generate a node certificate signed by the cluster CA.
///
/// Returns `(node_cert_pem, node_key_pem)` as PEM-encoded bytes.
///
/// The certificate matches Python `certgen.py` output:
/// - Algorithm: EC P-256 (ECDSA with SHA-256)
/// - CN: `nexus-zone-{zone_id}-node-{node_id}`
/// - SANs: localhost, 127.0.0.1, ::1, plus the `nexus://` identity URI
/// - Extended Key Usage: serverAuth + clientAuth (mTLS)
/// - Validity: see `NODE_CERT_VALIDITY_DAYS`
///
/// ## The identity URI SAN
///
/// The CN names the *host* (`hostname` when supplied), which is a
/// display string, not an identity: two nodes can share a hostname and
/// a host can be renamed. The `nexus://zone/{zone_id}/node/{node_id}`
/// URI SAN is the machine-readable identity — it is what
/// `transport::peer_identity` parses to turn a verified mTLS handshake
/// into a named cluster peer. Pin it here or the identity is not
/// recoverable at the far end.
pub fn generate_node_cert(
    node_id: u64,
    zone_id: &str,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
    extra_hostnames: &[String],
    hostname: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Parse CA key pair
    let ca_key_str =
        std::str::from_utf8(ca_key_pem).map_err(|e| format!("CA key is not valid UTF-8: {e}"))?;
    let ca_key_pair =
        KeyPair::from_pem(ca_key_str).map_err(|e| format!("Failed to parse CA key: {e}"))?;

    // Parse CA certificate
    let ca_cert_str =
        std::str::from_utf8(ca_cert_pem).map_err(|e| format!("CA cert is not valid UTF-8: {e}"))?;
    let ca_issuer = Issuer::from_ca_cert_pem(ca_cert_str, ca_key_pair)
        .map_err(|e| format!("Failed to parse CA cert: {e}"))?;

    // Generate node key pair (EC P-256)
    let node_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("Failed to generate node key: {e}"))?;

    // Build node certificate parameters
    let mut params = CertificateParams::default();

    // Distinguished name: CN=nexus-zone-{zone_id}-node-{hostname_or_id}, O=Nexus
    let cn_node = hostname.unwrap_or(&node_id.to_string()).to_string();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Nexus");
    dn.push(
        DnType::CommonName,
        format!("nexus-zone-{zone_id}-node-{cn_node}"),
    );
    params.distinguished_name = dn;

    // SANs: localhost, 127.0.0.1, ::1, plus any extra hostnames from node_address
    // (CockroachDB pattern: cert SANs include all hostnames the node is reachable at)
    let mut sans = vec![
        // Fixed cluster server name every node presents + the mTLS client
        // verifies against (instead of the dialed IP) — see
        // `lib::transport_primitives::CLUSTER_TLS_SERVER_NAME`. Keeps certs free
        // of any deployment address; identity is the CA chain + the URI SAN.
        SanType::DnsName(
            lib::transport_primitives::TlsConfig::CLUSTER_SERVER_NAME
                .try_into()
                .map_err(|e| format!("cluster SAN error: {e}"))?,
        ),
        SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e| format!("SAN error: {e}"))?,
        ),
        SanType::IpAddress(Ipv4Addr::LOCALHOST.into()),
        SanType::IpAddress(Ipv6Addr::LOCALHOST.into()),
        // Machine-readable identity — see the fn docs. Not a
        // reachability SAN; rustls ignores URI SANs for hostname
        // verification, so this rides along harmlessly and is read back
        // by `transport::peer_identity::from_der`.
        SanType::URI(
            node_identity_uri(zone_id, node_id)
                .as_str()
                .try_into()
                .map_err(|e| format!("identity SAN error: {e}"))?,
        ),
    ];
    for hostname in extra_hostnames {
        // Try parsing as IP first, fall back to DNS name
        if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            sans.push(SanType::DnsName(
                hostname
                    .as_str()
                    .try_into()
                    .map_err(|e| format!("SAN error for '{hostname}': {e}"))?,
            ));
        }
    }
    params.subject_alt_names = sans;

    // Extended key usage: serverAuth + clientAuth (mTLS)
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Key usage
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    // Not a CA
    params.is_ca = IsCa::NoCa;

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(NODE_CERT_VALIDITY_DAYS);

    // Sign with CA
    let node_cert = params
        .signed_by(&node_key_pair, &ca_issuer)
        .map_err(|e| format!("Failed to sign node cert: {e}"))?;

    let cert_pem = node_cert.pem().into_bytes();
    let key_pem = node_key_pair.serialize_pem().into_bytes();

    Ok((cert_pem, key_pem))
}

/// Generate a self-signed root CA certificate for a zone.
///
/// Mirrors Python `nexus.security.tls.certgen.generate_zone_ca`:
/// - Algorithm: EC P-256
/// - CN: `nexus-zone-{zone_id}-ca`, O: Nexus
/// - basicConstraints: CA:TRUE, pathLenConstraint: 0 (single-tier hierarchy)
/// - Key usage: digitalSignature, keyCertSign, cRLSign
/// - Validity: 10 years (CA outlives node certs by design)
pub fn generate_zone_ca(zone_id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("Failed to generate CA key: {e}"))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Nexus");
    dn.push(DnType::CommonName, format!("nexus-zone-{zone_id}-ca"));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);

    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("Failed to self-sign CA: {e}"))?;

    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

/// Generate a K3s-style cluster join token plus its server-side hash.
///
/// Token format: `K10<password>::server:<ca_fingerprint>` (matches
/// Python `nexus.security.tls.join_token`). Returns `(token, sha256_hex_hash)`.
/// The token is given to operators; the hash is stored on the leader for
/// constant-time verification of incoming `JoinCluster` requests.
pub fn generate_join_token(ca_pem: &[u8]) -> Result<(String, String), String> {
    use rand::Rng;
    use sha2::{Digest, Sha256};

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let password: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let fingerprint = ca_fingerprint_from_pem(ca_pem)?;
    let token = format!("K10{password}::server:{fingerprint}");
    let hash = Sha256::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    Ok((token, hash))
}

/// On-disk PEM bundle that `bootstrap_tls` produces / discovers.
#[derive(Debug, Clone)]
pub struct BootstrapTls {
    pub ca_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub node_cert_path: PathBuf,
    pub node_key_path: PathBuf,
    pub join_token_hash: String,
}

/// Discover or generate the Day-1 TLS bundle under `<base_path>/tls/`.
///
/// On first call: generates CA + node cert + join token, writes
/// `ca.pem` / `ca-key.pem` / `node.pem` / `node-key.pem` / `join-token`
/// / `join-token-hash`. On subsequent calls: detects the existing
/// bundle and returns its paths. Mirrors Python
/// `ZoneManager._auto_generate_tls`.
///
/// `zone_id` is the root zone id (used in CA CN); `hostname` is the
/// node's hostname (used in node cert CN + SAN). `node_id` is the
/// hostname-derived numeric id used in node cert CN.
pub fn bootstrap_tls(
    base_path: &Path,
    zone_id: &str,
    hostname: &str,
    node_id: u64,
) -> Result<BootstrapTls, String> {
    let tls_dir = base_path.join("tls");
    let ca_path = tls_dir.join("ca.pem");
    let ca_key_path = tls_dir.join("ca-key.pem");
    let node_cert_path = tls_dir.join("node.pem");
    let node_key_path = tls_dir.join("node-key.pem");
    let join_token_hash_path = tls_dir.join("join-token-hash");

    let read_hash = || {
        std::fs::read_to_string(&join_token_hash_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };

    // Reuse a ready TLS IDENTITY: ca + node cert + node key. `ca-key.pem` and
    // `join-token-hash` are FOUNDER-only extras — a node ENROLLED via
    // NodeEnrollmentService.JoinCluster receives only ca + node + node-key (it
    // holds no CA key), so they must NOT be required here or the enrolled node
    // would discard its issued cert and self-sign a fresh (unrelated) CA.
    if ca_path.exists() && node_cert_path.exists() && node_key_path.exists() {
        return Ok(BootstrapTls {
            ca_path,
            ca_key_path,
            node_cert_path,
            node_key_path,
            join_token_hash: read_hash(),
        });
    }

    std::fs::create_dir_all(&tls_dir)
        .map_err(|e| format!("Failed to mkdir {}: {}", tls_dir.display(), e))?;

    // Reuse an existing cluster CA if present (e.g. minted by `enroll-token`
    // before first boot) — signing this node's cert with the SAME CA keeps its
    // identity chained to the CA that outstanding join tokens pin. Otherwise
    // generate a fresh CA (the very first founder boot).
    let (ca_pem, ca_key_pem) = if ca_path.exists() && ca_key_path.exists() {
        let ca_pem =
            std::fs::read(&ca_path).map_err(|e| format!("Failed to read existing CA: {e}"))?;
        let ca_key_pem = std::fs::read(&ca_key_path)
            .map_err(|e| format!("Failed to read existing CA key: {e}"))?;
        (ca_pem, ca_key_pem)
    } else {
        let (ca_pem, ca_key_pem) = generate_zone_ca(zone_id)?;
        write_pem(&ca_path, &ca_pem, false)?;
        write_pem(&ca_key_path, &ca_key_pem, true)?;
        (ca_pem, ca_key_pem)
    };

    let (node_cert_pem, node_key_pem) =
        generate_node_cert(node_id, zone_id, &ca_pem, &ca_key_pem, &[], Some(hostname))?;
    write_pem(&node_cert_path, &node_cert_pem, false)?;
    write_pem(&node_key_path, &node_key_pem, true)?;

    // Ensure a join-token-hash exists so this founder can accept enrollments —
    // reuse an `enroll-token`-minted one if present, else mint the day-1 token.
    let join_token_hash = if join_token_hash_path.exists() {
        read_hash()
    } else {
        let (token, hash) = generate_join_token(&ca_pem)?;
        std::fs::write(tls_dir.join("join-token"), &token)
            .map_err(|e| format!("Failed to write join-token: {e}"))?;
        std::fs::write(&join_token_hash_path, &hash)
            .map_err(|e| format!("Failed to write join-token-hash: {e}"))?;
        hash
    };

    Ok(BootstrapTls {
        ca_path,
        ca_key_path,
        node_cert_path,
        node_key_path,
        join_token_hash,
    })
}

fn write_pem(path: &Path, pem: &[u8], private: bool) -> Result<(), String> {
    std::fs::write(path, pem).map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    if private {
        // POSIX-only: tighten private-key file permissions to 0o600.
        // No-op on Windows where ACLs handle this differently.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .map_err(|e| format!("chmod 600 {}: {}", path.display(), e))?;
        }
    }
    Ok(())
}

/// Compute a SHA-256 fingerprint of a PEM-encoded CA certificate.
///
/// Returns the fingerprint in `SHA256:<base64-no-padding>` format,
/// matching the Python `cert_fingerprint()` output used in join tokens.
pub fn ca_fingerprint_from_pem(ca_pem: &[u8]) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    // Extract DER bytes from PEM
    let pem_str =
        std::str::from_utf8(ca_pem).map_err(|e| format!("CA PEM is not valid UTF-8: {e}"))?;
    let pem = pem::parse(pem_str).map_err(|e| format!("Failed to parse PEM: {e}"))?;
    let der = pem.contents();

    // SHA-256 hash of DER-encoded certificate
    let hash = Sha256::digest(der);

    // Base64-encode without padding (matching Python's rstrip("="))
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    let b64 = STANDARD_NO_PAD.encode(hash);

    Ok(format!("SHA256:{}", b64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_ca() -> (String, String) {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Nexus");
        dn.push(DnType::CommonName, "nexus-zone-root-ca");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_cert = params.self_signed(&ca_key).unwrap();
        (ca_cert.pem(), ca_key.serialize_pem())
    }

    #[test]
    fn test_generate_node_cert() {
        let (ca_cert_pem, ca_key_pem) = generate_test_ca();
        let (cert_pem, key_pem) = generate_node_cert(
            2,
            "root",
            ca_cert_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            &[],
            Some("nexus-2"),
        )
        .unwrap();

        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());
        assert!(String::from_utf8_lossy(&cert_pem).contains("BEGIN CERTIFICATE"));
        assert!(String::from_utf8_lossy(&key_pem).contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn node_identity_uri_round_trips() {
        let uri = node_identity_uri("sharedzone", 42);
        assert_eq!(uri, "nexus://zone/sharedzone/node/42");
        assert_eq!(
            parse_node_identity_uri(&uri),
            Some(("sharedzone".to_string(), 42u64))
        );
    }

    #[test]
    fn parse_node_identity_uri_rejects_foreign_and_malformed() {
        for uri in [
            "spiffe://other/node/1",               // foreign scheme
            "nexus://zone//node/1",                // empty zone
            "nexus://zone/root/node/not-a-number", // non-numeric id
            "nexus://zone/root",                   // no node segment
            "",
        ] {
            assert_eq!(parse_node_identity_uri(uri), None, "must reject {uri:?}");
        }
    }

    /// The identity SAN is the whole basis of the peer auth plane: if a
    /// minted cert does not carry it, a verified handshake cannot be
    /// turned into a named node.
    #[test]
    fn node_cert_pins_the_identity_uri_san() {
        use x509_parser::prelude::*;

        let (ca_cert_pem, ca_key_pem) = generate_test_ca();
        let (cert_pem, _) = generate_node_cert(
            7,
            "sharedzone",
            ca_cert_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            &[],
            Some("win-box"),
        )
        .unwrap();

        // `::pem` — x509_parser's prelude also exports a `pem` module.
        let pem = ::pem::parse(&cert_pem).unwrap();
        let (_, cert) = X509Certificate::from_der(pem.contents()).unwrap();

        let uris: Vec<&str> = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect();

        assert_eq!(uris, vec!["nexus://zone/sharedzone/node/7"]);
        assert_eq!(
            parse_node_identity_uri(uris[0]),
            Some(("sharedzone".to_string(), 7))
        );
    }

    /// Every node cert must carry the fixed cluster server name as a DNS SAN —
    /// it is what the mTLS client verifies against (instead of the dialed IP),
    /// so a cross-machine dial to an overlay IP succeeds without that IP being
    /// in the cert. Guards the SAN half of `TlsConfig::CLUSTER_SERVER_NAME`.
    #[test]
    fn node_cert_carries_the_fixed_cluster_server_name_san() {
        use x509_parser::prelude::*;

        let (ca_cert_pem, ca_key_pem) = generate_test_ca();
        let (cert_pem, _) = generate_node_cert(
            7,
            "sharedzone",
            ca_cert_pem.as_bytes(),
            ca_key_pem.as_bytes(),
            &[],
            Some("win-box"),
        )
        .unwrap();

        let pem = ::pem::parse(&cert_pem).unwrap();
        let (_, cert) = X509Certificate::from_der(pem.contents()).unwrap();
        let dns_names: Vec<&str> = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(d) => Some(*d),
                _ => None,
            })
            .collect();
        assert!(
            dns_names.contains(&lib::transport_primitives::TlsConfig::CLUSTER_SERVER_NAME),
            "node cert must carry the fixed cluster server-name SAN; got {dns_names:?}"
        );
    }

    #[test]
    fn test_invalid_ca_key() {
        let (ca_cert_pem, _) = generate_test_ca();
        let result = generate_node_cert(1, "root", ca_cert_pem.as_bytes(), b"not-a-key", &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_zone_ca() {
        let (cert_pem, key_pem) = generate_zone_ca("root").unwrap();
        let cert_str = String::from_utf8_lossy(&cert_pem);
        assert!(cert_str.contains("BEGIN CERTIFICATE"));
        assert!(String::from_utf8_lossy(&key_pem).contains("BEGIN PRIVATE KEY"));
        // CA must be usable to sign a node cert
        let result = generate_node_cert(1, "root", &cert_pem, &key_pem, &[], Some("host-1"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_join_token_format() {
        let (ca_pem, _) = generate_zone_ca("root").unwrap();
        let (token, hash) = generate_join_token(&ca_pem).unwrap();
        assert!(token.starts_with("K10"));
        assert!(token.contains("::server:SHA256:"));
        // password is 64 hex chars between "K10" and the separator
        let body = token.strip_prefix("K10").unwrap();
        let (password, _) = body.split_once("::server:").unwrap();
        assert_eq!(password.len(), 64);
        assert!(password.chars().all(|c| c.is_ascii_hexdigit()));
        // hash is 64-char lowercase hex (SHA-256)
        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_bootstrap_tls_first_run_then_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let first = bootstrap_tls(base, "root", "host-1", 42).unwrap();
        for p in [
            &first.ca_path,
            &first.ca_key_path,
            &first.node_cert_path,
            &first.node_key_path,
        ] {
            assert!(p.exists(), "{} missing after first bootstrap", p.display());
        }
        assert_eq!(first.join_token_hash.len(), 64);

        // Reuse path: hashes/paths must be identical and file mtime stable.
        let second = bootstrap_tls(base, "root", "host-1", 42).unwrap();
        assert_eq!(first.ca_path, second.ca_path);
        assert_eq!(first.join_token_hash, second.join_token_hash);
        // CA cert bytes unchanged (proves we did not regenerate)
        let ca_first = std::fs::read(&first.ca_path).unwrap();
        let ca_second = std::fs::read(&second.ca_path).unwrap();
        assert_eq!(ca_first, ca_second);
    }
}
