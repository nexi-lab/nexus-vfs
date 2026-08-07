//! Federated mTLS for the cross-org authorship plane — a client-cert trust root
//! that carries **live** foreign CAs, hot-swapped as they are registered/revoked
//! without rebuilding the running server.
//!
//! ## Why this exists
//!
//! rustls enforces the client-cert trust root **at the handshake**, before any
//! gRPC handler runs. A foreign agent's cert chains to its org's CA (`CA_B`), not
//! the cluster CA, so unless that CA is in the server's trust root the handshake
//! is rejected and `peer_identity::classify_peer_cert` never runs. Foreign CAs
//! are registered at runtime (the raft control store), and tonic 0.14's
//! `ServerTlsConfig` bakes a single `client_ca_root` once at startup with no
//! hot-swap. So this module supplies the pieces server.rs uses instead:
//!
//! * [`FederatedClientCertVerifier`] — a `rustls::ClientCertVerifier` whose trust
//!   roots are `{cluster CA} ∪ {registered foreign CAs}`, atomically swapped by
//!   [`FederatedClientCertVerifier::set_foreign_cas`] (the foreign-CA apply
//!   observer's callback). It wraps rustls's own `WebPkiClientVerifier` — the
//!   X.509 path validation is rustls's, not hand-rolled.
//! * [`server_config`] — assembles the `rustls::ServerConfig` (keeps the rustls
//!   detail here, not smeared into server.rs).
//! * [`federated_tls_incoming`] — the TCP→TLS accept loop as the `Stream` that
//!   `tonic::Server::serve_with_incoming` consumes. It yields
//!   `tokio_rustls::server::TlsStream`, and **tonic's own** `Connected` impl for
//!   that type populates `TlsConnectInfo::peer_certs()` — so `peer_cert_der` /
//!   `from_request` keep seeing the client cert, with no custom bridge to get
//!   subtly wrong.
//!
//! ## Trust split (the invariant this preserves)
//!
//! This layer is only an **admission filter**: it lets a connection whose cert
//! chains to *any* current trust root reach a handler. The **authoritative**
//! local-vs-foreign + agent-only decision is `classify_peer_cert` at the app
//! layer, which reads the live anchor set. So a revoked foreign CA that still
//! lingers in a stale trust root is harmless — `classify` rejects it — and the
//! base path (no foreign CAs) is byte-for-byte the old `client_ca_root(cluster)`.

use std::io;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    client::danger::HandshakeSignatureValid, DigitallySignedStruct, DistinguishedName,
    Error as TlsError, RootCertStore, ServerConfig, SignatureScheme,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

use super::foreign_ca::{certificate_ders, first_certificate_der};
use super::ForeignCaAnchor;

/// Build a `WebPkiClientVerifier` over `cluster_ca_der` plus every foreign CA in
/// `foreign_cas`. Mandatory client auth (the default) — a caller must present a
/// cert that chains to one of these roots, exactly as `client_ca_root` required.
fn build_webpki(
    cluster_ca_der: &[u8],
    foreign_cas: &[Vec<u8>],
) -> Result<Arc<dyn ClientCertVerifier>, String> {
    // `WebPkiClientVerifier::builder().build()` enumerates the process-default
    // crypto provider's schemes, so it must be installed first — else it panics
    // ("no process-level CryptoProvider"). new()/set_foreign_cas both route here,
    // so installing it once at this chokepoint makes the verifier self-sufficient
    // (a caller that builds a verifier without server_config still works).
    super::ensure_crypto_provider();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cluster_ca_der.to_vec()))
        .map_err(|e| format!("cluster CA is not a valid root: {e}"))?;
    for (i, der) in foreign_cas.iter().enumerate() {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| format!("foreign CA #{i} is not a valid root: {e}"))?;
    }
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("client verifier build failed: {e}"))
}

/// A client-cert verifier whose trust roots track the live foreign-CA set.
///
/// Delegates all validation to an inner [`WebPkiClientVerifier`] held behind an
/// [`ArcSwap`]; [`Self::set_foreign_cas`] rebuilds and swaps it atomically. The
/// only non-delegated method is [`root_hint_subjects`](Self::root_hint_subjects),
/// which returns a stable, cluster-CA-only hint (see its doc).
#[derive(Debug)]
pub struct FederatedClientCertVerifier {
    /// Kept so every rebuild re-includes the cluster CA — membership trust is
    /// never dropped when the foreign set changes.
    cluster_ca_der: Vec<u8>,
    /// The CertificateRequest CA hint. Stable = the cluster CA's subject, exactly
    /// what `client_ca_root(cluster)` advertised, so the base path is unchanged.
    /// It deliberately does NOT grow with foreign CAs: the hint is advisory
    /// (rustls clients present their configured cert regardless), and a stable
    /// hint both sidesteps returning a borrow into the swapped inner AND avoids
    /// leaking the onboarded-org set into every handshake.
    base_hints: Vec<DistinguishedName>,
    inner: ArcSwap<VerifierCell>,
    /// The live foreign-anchor set, cached so the app-layer classifier
    /// (`transport::peer_identity::classify_peer_cert`) can name a foreign agent's
    /// trust domain without a store read per request. Kept in lock-step with
    /// `inner` by [`Self::set_foreign_cas`]: the WebPki verifier holds the parsed
    /// CA roots (admission), this holds the raw anchors WebPki does not expose
    /// (`trust_domain_id` + DER, for classification). Both derive from the same
    /// `set_foreign_cas` input, so this is a cache, not a second source of truth.
    anchors: ArcSwap<Vec<ForeignCaAnchor>>,
}

/// Sized wrapper so [`ArcSwap`] can atomically swap the trait-object verifier
/// (`ArcSwap` needs a `Sized` pointee).
#[derive(Debug)]
struct VerifierCell(Arc<dyn ClientCertVerifier>);

impl FederatedClientCertVerifier {
    /// Construct with only the cluster CA trusted — **byte-for-byte equivalent to
    /// the old `ServerTlsConfig::client_ca_root(cluster_ca)`** (same WebPki roots,
    /// same mandatory client auth, same hint). Foreign CAs are added later via
    /// [`Self::set_foreign_cas`].
    ///
    /// Takes the CA as **PEM** — the form `TlsConfig::ca_pem` holds — symmetric
    /// with [`server_config`], so the caller (zone_manager) never DER-decodes.
    pub fn new(cluster_ca_pem: &[u8]) -> Result<Arc<Self>, String> {
        let cluster_ca_der = first_certificate_der(cluster_ca_pem, "cluster CA")?;
        let inner = build_webpki(&cluster_ca_der, &[])?;
        let base_hints = inner.root_hint_subjects().to_vec();
        Ok(Arc::new(Self {
            cluster_ca_der,
            base_hints,
            inner: ArcSwap::from_pointee(VerifierCell(inner)),
            anchors: ArcSwap::from_pointee(Vec::new()),
        }))
    }

    /// The cluster CA (DER) — one input `classify_peer_cert` needs. `TlsConfig`
    /// holds PEM; the verifier already decoded it once at [`Self::new`], so this
    /// hands back the DER without re-decoding.
    #[inline]
    pub fn cluster_ca_der(&self) -> &[u8] {
        &self.cluster_ca_der
    }

    /// The live foreign-anchor set — the other input `classify_peer_cert` needs.
    /// O(1) `ArcSwap` read (an `Arc` clone); refreshed by [`Self::set_foreign_cas`].
    /// Bind the returned `Arc`, then pass `&arc` (deref-coerces to `&[ForeignCaAnchor]`).
    #[inline]
    pub fn foreign_anchors(&self) -> Arc<Vec<ForeignCaAnchor>> {
        self.anchors.load_full()
    }

    /// Atomically replace the trusted foreign CAs with `anchors` (cluster CA is
    /// always re-included). Called by the `CONTROL_NS_FOREIGN_CA` apply observer
    /// on register/revoke — off the handshake path, so the rebuild cost is free.
    /// A subsequent handshake sees the new set; an in-flight one is unaffected.
    pub fn set_foreign_cas(&self, anchors: &[ForeignCaAnchor]) -> Result<(), String> {
        let ders: Vec<Vec<u8>> = anchors.iter().map(|a| a.ca_cert_der.clone()).collect();
        let rebuilt = build_webpki(&self.cluster_ca_der, &ders)?;
        // Build WebPki first; only swap in the new admission roots + the classifier
        // cache once it succeeds, so a bad anchor never leaves the two out of sync.
        self.inner.store(Arc::new(VerifierCell(rebuilt)));
        self.anchors.store(Arc::new(anchors.to_vec()));
        Ok(())
    }
}

// Delegation to the current inner verifier. `#[inline]` throughout: these run on
// the per-handshake path, and the wrapper frame should vanish so this costs no
// more than calling WebPki directly.
impl ClientCertVerifier for FederatedClientCertVerifier {
    #[inline]
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Stable by design (see the field doc) — hence a plain borrow, not a
        // read into the swapped inner.
        &self.base_hints
    }

    #[inline]
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.inner
            .load()
            .0
            .verify_client_cert(end_entity, intermediates, now)
    }

    #[inline]
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner
            .load()
            .0
            .verify_tls12_signature(message, cert, dss)
    }

    #[inline]
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner
            .load()
            .0
            .verify_tls13_signature(message, cert, dss)
    }

    #[inline]
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.load().0.supported_verify_schemes()
    }

    #[inline]
    fn offer_client_auth(&self) -> bool {
        self.inner.load().0.offer_client_auth()
    }

    #[inline]
    fn client_auth_mandatory(&self) -> bool {
        self.inner.load().0.client_auth_mandatory()
    }
}

/// Assemble a `rustls::ServerConfig` presenting `cert_pem`/`key_pem` and gating
/// clients with `verifier`. Installs the process crypto provider first (see
/// [`super::ensure_crypto_provider`]).
pub fn server_config(
    verifier: Arc<FederatedClientCertVerifier>,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<ServerConfig, String> {
    super::ensure_crypto_provider();

    let certs: Vec<CertificateDer<'static>> = certificate_ders(cert_pem, "server cert")?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        return Err("server cert PEM has no CERTIFICATE block".into());
    }

    // certgen emits the key as a PKCS#8 `PRIVATE KEY` block.
    let key_pem = ::pem::parse(key_pem).map_err(|e| format!("server key PEM: {e}"))?;
    if key_pem.tag() != "PRIVATE KEY" {
        return Err(format!(
            "server key must be a PKCS#8 `PRIVATE KEY` block, found `{}`",
            key_pem.tag()
        ));
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem.into_contents()));

    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config: {e}"))?;
    // Advertise HTTP/2 in ALPN. tonic's built-in `ServerTlsConfig` sets this
    // automatically; a hand-built rustls `ServerConfig` does NOT, so without it
    // ALPN negotiation yields no `h2` and tonic's HTTP/2 client fails EVERY mTLS
    // dial (the whole cluster data plane goes dark). Caught only by a real tonic
    // handshake — the live federation e2e, not the verifier unit tests.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// Backpressure bound for accepted-but-not-yet-consumed connections. Small: tonic
/// drains this promptly, and a bound keeps a connection flood from unbounded
/// buffering.
const ACCEPT_BUFFER: usize = 1024;

/// Turn a listening `TcpListener` + a `ServerConfig` into the stream of
/// TLS-accepted connections `tonic::Server::serve_with_incoming` consumes.
///
/// Handshakes run **concurrently** — each accepted TCP connection is handshaken
/// on its own task — so one slow (or malicious) peer cannot head-of-line block
/// others' handshakes. Yields `tokio_rustls::server::TlsStream`, whose tonic
/// `Connected` impl surfaces the client cert as `TlsConnectInfo::peer_certs()`.
pub fn federated_tls_incoming(
    listener: TcpListener,
    cfg: Arc<ServerConfig>,
) -> impl Stream<Item = io::Result<TlsStream<TcpStream>>> {
    let acceptor = TlsAcceptor::from(cfg);
    let (tx, rx) = tokio::sync::mpsc::channel(ACCEPT_BUFFER);
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                biased;
                // Consumer (tonic) dropped the stream → stop accepting, so the
                // task and the listener fd are released rather than looping
                // forever. Checked first so shutdown wins a ready accept.
                _ = tx.closed() => break,
                r = listener.accept() => r,
            };
            let tcp = match accepted {
                Ok((stream, _peer)) => stream,
                // A listener-level error (fd exhaustion, etc.) is surfaced to the
                // consumer; keep accepting — a transient error must not kill serve.
                Err(e) => {
                    if tx.send(Err(e)).await.is_err() {
                        break; // consumer dropped → stop accepting
                    }
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                // A failed handshake (untrusted cert, garbage) is surfaced as an
                // Err item; tonic drops that one connection and keeps serving.
                let _ = tx.send(acceptor.accept(tcp).await).await;
            });
        }
    });
    ReceiverStream::new(rx)
}

/// One-shot: bind `addr` and produce the federated-mTLS accept stream that
/// `tonic::Server::serve_with_incoming` consumes — the whole mTLS server side
/// assembled HERE so callers (raft `server.rs`) name no rustls / tokio-rustls
/// types and every serve site is one line.
///
/// `verifier` is the shared hot-swappable client-cert verifier when the caller
/// owns one (so a runtime `set_foreign_cas` reaches this live socket); `None`
/// builds a cluster-only verifier from `tls.ca_pem` (base mTLS — e.g. the
/// witness bind, which never trusts foreign CAs). Mandatory client-auth, same
/// as the prior `client_ca_root(cluster_ca)`. `server_config` pins the crypto
/// provider internally, so no separate `ensure_crypto_provider` call is needed.
pub async fn federated_mtls_incoming(
    addr: std::net::SocketAddr,
    tls: &super::TlsConfig,
    verifier: Option<std::sync::Arc<FederatedClientCertVerifier>>,
) -> Result<impl Stream<Item = std::io::Result<TlsStream<TcpStream>>>, String> {
    let verifier = match verifier {
        Some(v) => v,
        None => FederatedClientCertVerifier::new(&tls.ca_pem)?,
    };
    let cfg = server_config(verifier, &tls.cert_pem, &tls.key_pem)?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    Ok(federated_tls_incoming(listener, std::sync::Arc::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
        PKCS_ECDSA_P256_SHA256,
    };

    // Mint test CAs/agents with rcgen directly — lib sits below the raft cert-gen
    // driver, so the crypto is validated without depending on it.
    fn mint_ca(cn: &str) -> (Vec<u8>, String) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        let ca = p.self_signed(&key).unwrap();
        (ca.der().to_vec(), key.serialize_pem())
    }

    fn mint_agent_der(name: &str, ca_der: &[u8], ca_key_pem: &str) -> Vec<u8> {
        let ca_pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", ca_der.to_vec()));
        let ca_key = KeyPair::from_pem(ca_key_pem).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![SanType::URI(
            crate::agent_identity::agent_identity_uri(name)
                .as_str()
                .try_into()
                .unwrap(),
        )];
        p.signed_by(&key, &issuer).unwrap().der().to_vec()
    }

    fn anchor(domain: &str, ca_der: &[u8]) -> ForeignCaAnchor {
        ForeignCaAnchor::new(domain, ca_der.to_vec())
    }

    /// DER → PEM `CERTIFICATE`, the form `new` / `server_config` take.
    fn pem_of(der: &[u8]) -> Vec<u8> {
        ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.to_vec())).into_bytes()
    }

    /// verify_client_cert accepts the cluster CA's own cert and rejects a
    /// foreign one — the base state, before any foreign CA is registered.
    #[test]
    fn base_verifier_trusts_only_the_cluster_ca() {
        let (cluster_der, cluster_key) = mint_ca("cluster");
        let (foreign_der, foreign_key) = mint_ca("hospital");
        let v = FederatedClientCertVerifier::new(&pem_of(&cluster_der)).unwrap();

        let local = mint_agent_der("win-ai", &cluster_der, &cluster_key);
        let foreign = mint_agent_der("cardio", &foreign_der, &foreign_key);
        let now = UnixTime::now();

        assert!(
            v.verify_client_cert(&CertificateDer::from(local), &[], now)
                .is_ok(),
            "a cluster-CA cert is admitted"
        );
        assert!(
            v.verify_client_cert(&CertificateDer::from(foreign), &[], now)
                .is_err(),
            "a foreign cert is NOT admitted before its CA is registered"
        );
    }

    /// After `set_foreign_cas`, the foreign cert is admitted (its CA is now a
    /// trust root) — and after clearing it, admission is withdrawn again. The
    /// hot-swap in both directions.
    #[test]
    fn set_foreign_cas_swaps_admission_live() {
        let (cluster_der, _cluster_key) = mint_ca("cluster");
        let (foreign_der, foreign_key) = mint_ca("hospital");
        let v = FederatedClientCertVerifier::new(&pem_of(&cluster_der)).unwrap();
        let foreign = mint_agent_der("cardio", &foreign_der, &foreign_key);
        let now = UnixTime::now();

        let der = || CertificateDer::from(foreign.clone());
        assert!(
            v.verify_client_cert(&der(), &[], now).is_err(),
            "rejected before register"
        );

        v.set_foreign_cas(&[anchor("hospital-a", &foreign_der)])
            .unwrap();
        assert!(
            v.verify_client_cert(&der(), &[], now).is_ok(),
            "admitted after register"
        );

        v.set_foreign_cas(&[]).unwrap();
        assert!(
            v.verify_client_cert(&der(), &[], now).is_err(),
            "admission withdrawn after the CA is cleared"
        );
    }

    /// The accessors expose exactly what `classify_peer_cert` consumes:
    /// `cluster_ca_der()` is the CA `new` decoded, and `foreign_anchors()` tracks
    /// `set_foreign_cas` in lock-step with admission — so the classifier and the
    /// TLS trust root can never disagree on the foreign set.
    #[test]
    fn accessors_expose_the_classifier_inputs() {
        let (cluster_der, _k) = mint_ca("cluster");
        let (foreign_der, _fk) = mint_ca("hospital");
        let v = FederatedClientCertVerifier::new(&pem_of(&cluster_der)).unwrap();

        assert_eq!(v.cluster_ca_der(), cluster_der.as_slice());
        assert!(v.foreign_anchors().is_empty(), "no anchors before register");

        let a = anchor("hospital-a", &foreign_der);
        v.set_foreign_cas(std::slice::from_ref(&a)).unwrap();
        assert_eq!(
            &*v.foreign_anchors(),
            &[a],
            "anchor set cached for the classifier"
        );

        v.set_foreign_cas(&[]).unwrap();
        assert!(
            v.foreign_anchors().is_empty(),
            "cache cleared with admission"
        );
    }

    /// The CertificateRequest hint stays the cluster CA's subject regardless of
    /// registered foreign CAs — stable (advisory) and unchanged from the old
    /// `client_ca_root(cluster)` path, so the base handshake is preserved.
    #[test]
    fn root_hints_are_stable_and_cluster_only() {
        let (cluster_der, _k) = mint_ca("cluster");
        let (foreign_der, _fk) = mint_ca("hospital");
        let v = FederatedClientCertVerifier::new(&pem_of(&cluster_der)).unwrap();

        // DistinguishedName isn't PartialEq — compare the raw DER bytes.
        let bytes = |v: &FederatedClientCertVerifier| -> Vec<Vec<u8>> {
            v.root_hint_subjects()
                .iter()
                .map(|d| d.as_ref().to_vec())
                .collect()
        };
        let before = bytes(&v);
        assert_eq!(before.len(), 1, "exactly the cluster CA subject");

        v.set_foreign_cas(&[anchor("hospital-a", &foreign_der)])
            .unwrap();
        assert_eq!(bytes(&v), before, "the hint does not grow with foreign CAs");
    }

    /// `server_config` assembles from a real certgen-shaped bundle (PKCS#8 key,
    /// PEM cert) — proving the PEM parsing accepts what the daemon actually holds.
    #[test]
    fn server_config_builds_from_a_pem_bundle() {
        let (cluster_der, _k) = mint_ca("cluster");
        let v = FederatedClientCertVerifier::new(&pem_of(&cluster_der)).unwrap();

        // A leaf server cert + its PKCS#8 key, PEM-encoded (the `tls.cert_pem` /
        // `tls.key_pem` shape).
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "node");
        let cert = p.self_signed(&key).unwrap();
        let cert_pem = cert.pem().into_bytes();
        let key_pem = key.serialize_pem().into_bytes();

        assert!(server_config(v, &cert_pem, &key_pem).is_ok());
    }

    /// A non-PKCS#8 key label is rejected with a clear error, not a silent
    /// mis-parse.
    #[test]
    fn server_config_rejects_a_non_pkcs8_key() {
        let (cluster_der, _k) = mint_ca("cluster");
        let v = FederatedClientCertVerifier::new(&pem_of(&cluster_der)).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "node");
        let cert = p.self_signed(&key).unwrap();
        let sec1_key = ::pem::encode(&::pem::Pem::new("EC PRIVATE KEY", vec![1, 2, 3]));

        let err = server_config(v, &cert.pem().into_bytes(), sec1_key.as_bytes()).unwrap_err();
        assert!(err.contains("PKCS#8"), "clear error, got: {err}");
    }
}
