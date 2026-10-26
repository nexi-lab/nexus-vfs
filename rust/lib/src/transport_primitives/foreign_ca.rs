//! The cross-org authorship trust anchor — one registered foreign CA.
//!
//! A [`ForeignCaAnchor`] is the broker side of the cross-CA authorship bridge:
//! it says "certificates signed by THIS certificate authority are agents of the
//! named trust domain, and their signatures may be verified as cross-org
//! authorship." A broker admin registers one at customer onboarding, keyed by
//! the fingerprint of the foreign CA cert. (Design: `nexus-auth-architecture`
//! §5.4–5.6.)
//!
//! Sibling to [`super::tofu`] (pin a federation zone's CA on first contact) and
//! [`super::authorship`] (verify a cluster-CA agent signature): all three are
//! transport-layer CA-trust primitives, so this shares their home and their one
//! [`super::cert_fingerprint`].
//!
//! ## What it authorizes — and what it must never authorize
//!
//! An anchor grants **authorship recognition only**: a cert chaining to it
//! resolves to a *foreign agent* (a mailbox principal of another trust domain),
//! never to a cluster **member**. Cluster membership stays pinned to the single
//! `client_ca_root` and its node certs — a foreign CA is registered *here*, in a
//! table disjoint from the membership root, precisely so that onboarding a
//! customer can never make their box a voter in our raft.
//!
//! ## Why the fingerprint is the identity
//!
//! The trust-domain label is pinned **at registration**, bound to the CA's
//! fingerprint — NOT read from the cert. A nexus CA cert's CN is the generic
//! `nexus-zone-root-ca` (every customer's CA_B shares it, as the DGX dry-run
//! confirmed), so the CN cannot name an org; only the fingerprint distinguishes
//! one customer's root from another. The canonical trust domain is therefore
//! `f(verifying CA)`, and this record is where that binding lives. A foreign
//! holder cannot spoof its trust domain: it would need a CA whose fingerprint we
//! already registered under that domain.
//!
//! ## Not a secret
//!
//! The record holds a **public** CA certificate plus a label. It is safe to
//! replicate through the cluster-control state machine and to surface in an
//! audit view: possessing every anchor lets you *verify* foreign authorship,
//! never *mint* it — that needs the foreign CA's private key, which never leaves
//! the foreign box.

use serde::{Deserialize, Serialize};

use super::cert_fingerprint;

/// SHA-256 of a CA certificate's DER encoding — the registry key that a
/// presented agent cert's issuer is matched against.
pub type CaFingerprint = [u8; 32];

/// Cryptographic recognition does not grant every protocol's authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCaScope {
    #[default]
    LegacyMailbox,
    CollaborationOnlyV1,
}

// A distinct envelope intentionally omits the old decoder's required root
// fields. Old binaries must reject a scoped record, not ignore a new policy
// field and install its CA with legacy mailbox authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollaborationAnchorRecord {
    schema_version: u8,
    collaboration_anchor_v1: CollaborationAnchorMaterial,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollaborationAnchorMaterial {
    trust_domain_id: String,
    ca_cert_der: Vec<u8>,
}
#[derive(Serialize)]
struct LegacyAnchorRef<'a> {
    trust_domain_id: &'a str,
    ca_cert_der: &'a [u8],
}
#[derive(Deserialize)]
struct LegacyAnchorRecord {
    trust_domain_id: String,
    ca_cert_der: Vec<u8>,
}

/// The DER of every `CERTIFICATE` block in `pem` (one cert, or a chain). `what`
/// names the input in errors. The one PEM→DER cert-block decode for the
/// cross-org TLS primitives — used by [`first_certificate_der`],
/// [`ForeignCaAnchor::from_pem`], and `federated_tls::server_config` (the chain).
pub(crate) fn certificate_ders(pem: &[u8], what: &str) -> Result<Vec<Vec<u8>>, String> {
    Ok(::pem::parse_many(pem)
        .map_err(|e| format!("{what} PEM: {e}"))?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect())
}

/// The DER of the FIRST `CERTIFICATE` block — a single CA cert. Errors if none.
pub fn first_certificate_der(pem: &[u8], what: &str) -> Result<Vec<u8>, String> {
    certificate_ders(pem, what)?
        .into_iter()
        .next()
        .ok_or_else(|| format!("{what} PEM has no CERTIFICATE block"))
}

/// One registered foreign certificate authority: the root of another trust
/// domain whose agent certs the broker recognizes for cross-org authorship.
///
/// Stored DER-encoded because the fingerprint is defined over DER (matching
/// `openssl x509 -outform DER | dgst -sha256`, the form sudoedge exports).
/// PEM↔DER conversion happens at the registration boundary, above this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignCaAnchor {
    /// The trust domain this CA speaks for, e.g. `hospital-a`. Pinned by the
    /// registering admin and bound to [`Self::fingerprint`] — this, not the
    /// cert's CN, is the authoritative org identity (see the module docs).
    pub trust_domain_id: String,
    /// The foreign CA certificate, DER-encoded. The public root; verification
    /// checks that a presented agent cert chains to this. Never a private key.
    pub ca_cert_der: Vec<u8>,
    pub scope: ForeignCaScope,
}

// Serde and the store codec use exactly the same representation. A caller
// serializing the public type directly cannot accidentally emit a flat scope
// field that an old decoder would ignore.
impl Serialize for ForeignCaAnchor {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.scope {
            ForeignCaScope::LegacyMailbox => LegacyAnchorRef {
                trust_domain_id: &self.trust_domain_id,
                ca_cert_der: &self.ca_cert_der,
            }
            .serialize(serializer),
            ForeignCaScope::CollaborationOnlyV1 => CollaborationAnchorRecord {
                schema_version: 1,
                collaboration_anchor_v1: CollaborationAnchorMaterial {
                    trust_domain_id: self.trust_domain_id.clone(),
                    ca_cert_der: self.ca_cert_der.clone(),
                },
            }
            .serialize(serializer),
        }
    }
}
impl<'de> Deserialize<'de> for ForeignCaAnchor {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("collaboration_anchor_v1").is_some() {
            let record: CollaborationAnchorRecord =
                serde_json::from_value(value).map_err(D::Error::custom)?;
            if record.schema_version != 1 {
                return Err(D::Error::custom("unsupported collaboration anchor version"));
            }
            return Ok(Self::new(
                record.collaboration_anchor_v1.trust_domain_id,
                record.collaboration_anchor_v1.ca_cert_der,
            )
            .collaboration_only());
        }
        if value.get("scope").is_some() {
            return Err(D::Error::custom(
                "scoped anchor requires its versioned envelope",
            ));
        }
        let legacy: LegacyAnchorRecord = serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self::new(legacy.trust_domain_id, legacy.ca_cert_der))
    }
}

impl ForeignCaAnchor {
    pub fn new(trust_domain_id: impl Into<String>, ca_cert_der: Vec<u8>) -> Self {
        Self {
            trust_domain_id: trust_domain_id.into(),
            ca_cert_der,
            scope: ForeignCaScope::LegacyMailbox,
        }
    }

    /// The new collaboration service can recognize this root, while ordinary
    /// foreign VFS/session/control admission must refuse it. Store through
    /// encode(), whose versioned envelope also fails closed on older binaries.
    pub fn collaboration_only(mut self) -> Self {
        self.scope = ForeignCaScope::CollaborationOnlyV1;
        self
    }

    /// Build from the **PEM** form sudoedge exports in the onboarding triple
    /// (`ca_cert_pem`). Decodes the first `CERTIFICATE` block to DER — the form
    /// the anchor stores and fingerprints. The `RegisterForeignCa` handler uses
    /// this, then verifies [`Self::fingerprint_hex`] against the triple's
    /// `fingerprint` for the out-of-band bootstrap check.
    pub fn from_pem(
        trust_domain_id: impl Into<String>,
        ca_cert_pem: &[u8],
    ) -> Result<Self, String> {
        Ok(Self::new(
            trust_domain_id,
            first_certificate_der(ca_cert_pem, "foreign CA")?,
        ))
    }

    /// The registry key: SHA-256 over the CA cert's DER, via the shared
    /// [`super::cert_fingerprint`]. **Derived, never stored** — the cert bytes
    /// are the single source of truth, so a stored copy could only drift.
    pub fn fingerprint(&self) -> CaFingerprint {
        cert_fingerprint(&self.ca_cert_der)
    }

    /// `sha256:<hex>` — the openssl-compatible form carried in the onboarding
    /// triple `{ca_cert_pem, trust_domain_id, fingerprint}` and shown in the
    /// audit view. (Distinct from `tofu`'s `SHA256:{base64}`, which is a private
    /// pin-file detail; the canonical key is the raw [`CaFingerprint`].)
    pub fn fingerprint_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity("sha256:".len() + 64);
        s.push_str("sha256:");
        for b in self.fingerprint() {
            // `write!` into the buffer — no per-byte String allocation, and the
            // shape `raft::transport::server` already uses for hex.
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Encode for the control-state store. Infallible in practice (plain data)
    /// but surfaced as a `Result` so a future non-serialisable field cannot
    /// panic a registration.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> ForeignCaAnchor {
        ForeignCaAnchor::new("hospital-a", vec![1, 2, 3, 4])
    }

    #[test]
    fn roundtrips_through_the_store_encoding() {
        let restored = ForeignCaAnchor::decode(&anchor().encode().unwrap()).unwrap();
        assert_eq!(restored, anchor());
    }

    #[test]
    fn scoped_encoding_cannot_be_installed_by_the_legacy_decoder() {
        #[derive(Deserialize)]
        struct LegacyAnchor {
            trust_domain_id: String,
            ca_cert_der: Vec<u8>,
        }
        let legacy = anchor();
        let scoped = legacy.clone().collaboration_only();
        assert_eq!(scoped.fingerprint(), legacy.fingerprint());
        let old = serde_json::from_slice::<LegacyAnchor>(&legacy.encode().unwrap()).unwrap();
        assert_eq!(old.trust_domain_id, legacy.trust_domain_id);
        assert_eq!(old.ca_cert_der, legacy.ca_cert_der);
        let encoded = scoped.encode().unwrap();
        assert!(serde_json::from_slice::<LegacyAnchor>(&encoded).is_err());
        assert_eq!(ForeignCaAnchor::decode(&encoded).unwrap(), scoped);
        let mut future: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        future["schema_version"] = 2.into();
        assert!(ForeignCaAnchor::decode(&serde_json::to_vec(&future).unwrap()).is_err());
        future["schema_version"] = 1.into();
        future["collaboration_anchor_v1"]["unknown_policy"] = true.into();
        assert!(ForeignCaAnchor::decode(&serde_json::to_vec(&future).unwrap()).is_err());
        // Adding an ignorable root field to the old format is NOT a supported
        // way to publish a restrictive scope.
        let mut flat = serde_json::to_value(&legacy).unwrap();
        flat["scope"] = "collaboration_only_v1".into();
        let flat = serde_json::to_vec(&flat).unwrap();
        assert!(serde_json::from_slice::<LegacyAnchor>(&flat).is_ok());
        assert!(ForeignCaAnchor::decode(&flat).is_err());
        assert_eq!(serde_json::to_vec(&scoped).unwrap(), encoded);
    }

    /// The fingerprint is defined by the cert bytes alone, so two anchors that
    /// pin the SAME CA under DIFFERENT trust domains collide on the key — the
    /// registration layer relies on this to reject a conflicting re-pin.
    #[test]
    fn fingerprint_depends_only_on_the_cert_not_the_label() {
        let a = ForeignCaAnchor::new("hospital-a", vec![9, 9, 9]);
        let b = ForeignCaAnchor::new("hospital-b", vec![9, 9, 9]);
        assert_eq!(a.fingerprint(), b.fingerprint());

        let c = ForeignCaAnchor::new("hospital-a", vec![9, 9, 8]);
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    /// A node on an older build must not choke on an anchor a newer node wrote —
    /// the store replicates records verbatim, so a decode failure would take the
    /// whole trust anchor offline cluster-wide.
    #[test]
    fn unknown_fields_are_ignored() {
        let json = br#"{
            "trust_domain_id": "hospital-a",
            "ca_cert_der": [1, 2, 3, 4],
            "future_field": {"nested": true}
        }"#;
        let a = ForeignCaAnchor::decode(json).expect("forward-compatible decode");
        assert_eq!(a.trust_domain_id, "hospital-a");
        assert_eq!(a.ca_cert_der, vec![1, 2, 3, 4]);
    }

    /// Ties this code to a verified live artifact: the real CA_B produced by the
    /// 2026-08-06 DGX Spark dry-run (test domain `sudoedge-dgx-dev`). The
    /// fingerprint must equal what `openssl x509 -outform DER | dgst -sha256`
    /// reported on the box — proving our key IS the onboarding-triple
    /// fingerprint, so a registered anchor matches the presented issuer.
    #[test]
    fn fingerprint_matches_the_dgx_dry_run_anchor() {
        let der = include_bytes!("testdata/dgx_dev_ca_b.der").to_vec();
        let a = ForeignCaAnchor::new("sudoedge-dgx-dev", der);
        assert_eq!(
            a.fingerprint_hex(),
            "sha256:b2582dd5216bffd46cd423d18a831913f9bfe514ce99590e106713a0b6b61672"
        );
        // The trust domain is the registered label, not anything in the cert —
        // its CN is the generic `nexus-zone-root-ca`, which names no org.
        assert_eq!(a.trust_domain_id, "sudoedge-dgx-dev");
    }

    /// `from_pem` (the RegisterForeignCa path) yields the SAME anchor as `new`
    /// with the DER — i.e. the PEM→DER decode is inverse to the real DGX export,
    /// so the fingerprint the handler verifies against the triple matches. PEM is
    /// the form sudoedge actually ships in `ca_cert_pem`.
    #[test]
    fn from_pem_matches_the_der_anchor() {
        let der = include_bytes!("testdata/dgx_dev_ca_b.der");
        let pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.to_vec()));
        let from_pem = ForeignCaAnchor::from_pem("sudoedge-dgx-dev", pem.as_bytes())
            .expect("valid CA PEM decodes");
        assert_eq!(
            from_pem,
            ForeignCaAnchor::new("sudoedge-dgx-dev", der.to_vec())
        );
        assert_eq!(
            from_pem.fingerprint_hex(),
            "sha256:b2582dd5216bffd46cd423d18a831913f9bfe514ce99590e106713a0b6b61672"
        );
    }

    /// PEM with no CERTIFICATE block is a clear error, not a silent empty anchor.
    #[test]
    fn from_pem_rejects_non_certificate_pem() {
        let junk = ::pem::encode(&::pem::Pem::new("PRIVATE KEY", vec![1, 2, 3]));
        assert!(ForeignCaAnchor::from_pem("x", junk.as_bytes()).is_err());
    }
}
