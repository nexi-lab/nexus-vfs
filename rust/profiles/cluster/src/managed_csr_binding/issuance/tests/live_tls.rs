use super::*;
use lib::transport_primitives::TlsPolicy;
use nexus_raft::ca_issuer::{AgentBundle, SessionRenewal};
use nexus_raft::transport::proto::{
    AgentCsrCapabilitiesResponse, AgentCsrRequest, AgentCsrResponse,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct ReplaceAfterReply {
    inner: Arc<dyn CaIssuer>,
    credentials: SharedTlsConfig,
    replacement: Mutex<Option<TlsPolicy>>,
    calls: AtomicUsize,
}

#[tonic::async_trait]
impl CaIssuer for ReplaceAfterReply {
    fn csr_capabilities(&self) -> AgentCsrCapabilitiesResponse {
        self.inner.csr_capabilities()
    }
    async fn agent_csr_v1(
        &self,
        caller: Option<Vec<u8>>,
        request: AgentCsrRequest,
        query: bool,
    ) -> AgentCsrResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = self.inner.agent_csr_v1(caller, request, query).await;
        if let Some(policy) = self.replacement.lock().unwrap().take() {
            self.credentials.replace(policy);
        }
        reply
    }
    async fn mint(
        &self,
        _: Option<Vec<u8>>,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<AgentBundle, String> {
        Err("unselected fixture mint".into())
    }
    async fn mint_session(
        &self,
        _: Option<Vec<u8>>,
        _: &str,
        _: u64,
    ) -> Result<AgentBundle, String> {
        Err("unselected fixture mint_session".into())
    }
    async fn mint_user_runtime(
        &self,
        _: Option<Vec<u8>>,
        _: &str,
        _: u64,
    ) -> Result<AgentBundle, String> {
        Err("unselected fixture mint_user_runtime".into())
    }
    async fn renew_session(
        &self,
        _: Option<Vec<u8>>,
        _: SessionRenewal<'_>,
    ) -> Result<AgentBundle, String> {
        Err("unselected fixture renew_session".into())
    }
    async fn renew_node(&self, _: Option<Vec<u8>>, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("unselected fixture renew_node".into())
    }
    async fn revoke_cert(&self, _: Option<Vec<u8>>, _: &[u8]) -> Result<(), String> {
        Err("unselected fixture revoke_cert".into())
    }
}

fn withheld(value: &Value, attempted: bool) {
    assert_eq!(value["issuanceOutcome"], "unknown");
    assert_eq!(value["submissionAttempted"], attempted);
    assert_eq!(value["credentialPublished"], false);
    for field in [
        "issuerObservation",
        "certificateSha256",
        "localCredentialId",
    ] {
        assert!(
            value.get(field).is_none(),
            "withdrawn reply exposed {field}: {value}"
        );
    }
}

// Extends the existing real-mTLS + persistent-Raft journey. No mock successful
// CSR is supplied: the wrapper replaces TLS only after the actual issuer returns.
pub(super) struct LiveTlsFixture<'a> {
    pub(super) slot: &'a CaIssuerSlot,
    pub(super) credentials: &'a SharedTlsConfig,
    pub(super) tls: &'a TlsConfig,
    pub(super) tls_dir: &'a std::path::Path,
    pub(super) store: &'a Arc<LoseReply>,
}

impl LiveTlsFixture<'_> {
    pub(super) async fn exercise_withdrawn_reply(
        self,
        owner: &mut NexusVfsServiceClient<Channel>,
        original_pid: &str,
        original_op: &str,
    ) {
        let Self {
            slot,
            credentials,
            tls,
            tls_dir,
            store,
        } = self;
        use kernel::hal::auth_key_store::AuthKeyStore;
        let inner = slot.read().clone().unwrap();
        let wrapper = Arc::new(ReplaceAfterReply {
            inner: inner.clone(),
            credentials: credentials.clone(),
            replacement: Mutex::new(None),
            calls: AtomicUsize::new(0),
        });
        *slot.write() = Some(wrapper.clone());
        let native = NativeIssuer::from_shared_tls(
            slot.clone(),
            credentials.clone(),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        let admitted = native.admit(&tls.ca_pem).unwrap();
        *slot.write() = Some(inner.clone());
        assert!(
            native.with_current(&admitted, || Ok(())).is_err(),
            "replaced CA holder must withdraw admission"
        );
        *slot.write() = Some(wrapper.clone());
        credentials.replace(TlsPolicy::Rejected("fixture withdrawal"));
        for verb in ["issue_v1", "query_v1", "publish_v1"] {
            withheld(&call(owner, verb, original_pid, original_op).await, false);
        }
        assert_eq!(wrapper.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.list().unwrap().len(), 4);
        let (_, caps) = raw(owner, &format!("{NAME}.capabilities_v1"), json!({})).await;
        assert_eq!(caps["issuanceVersion"], 0);
        credentials.replace(TlsPolicy::Configured(tls.clone()));
        assert!(
            native.with_current(&admitted, || Ok(())).is_err(),
            "identical-byte replacement is a new installation"
        );
        let ca_key = std::fs::read(tls_dir.join("ca-key.pem")).unwrap();
        let (other_cert, other_key) =
            generate_node_cert(9, "root", &tls.ca_pem, &ca_key, &[], None).unwrap();
        credentials.replace(TlsPolicy::Configured(TlsConfig {
            ca_pem: tls.ca_pem.clone(),
            cert_pem: other_cert,
            key_pem: other_key,
        }));
        assert!(
            native.admit(&tls.ca_pem).is_err(),
            "another Node must not inherit this host's issuer"
        );
        let (renewed_cert, renewed_key) =
            generate_node_cert(1, "root", &tls.ca_pem, &ca_key, &[], None).unwrap();
        credentials.replace(TlsPolicy::Configured(TlsConfig {
            ca_pem: tls.ca_pem.clone(),
            cert_pem: renewed_cert,
            key_pem: renewed_key,
        }));
        assert!(
            native.admit(&tls.ca_pem).is_ok(),
            "a new call may admit the same Node's current renewal"
        );
        credentials.replace(TlsPolicy::Configured(tls.clone()));

        let pid = start(owner, "withdrawn-issuer-product-agent").await;
        let op = "native-original-operation-withdrawn-reply";
        let prepared = call(owner, "prepare_v1", &pid, op).await;
        let key = PreparationService::operation_key("withdrawn-issuer-product-agent", "alice", op);
        let pending = tls_dir.join(format!("managed-csr-{key}.json"));
        let bundle = tls_dir.join(format!("managed-agent-{key}"));
        let original_request = std::fs::read(&pending).unwrap();
        *wrapper.replacement.lock().unwrap() =
            Some(TlsPolicy::Rejected("after actual issuer completion"));
        let lost = call(owner, "issue_v1", &pid, op).await;
        withheld(&lost, true);
        assert_eq!(lost["operationId"], op);
        assert_eq!(
            wrapper.calls.load(Ordering::SeqCst),
            1,
            "no automatic mutation replay"
        );
        assert_eq!(
            store.list().unwrap().len(),
            6,
            "the original I/F may already exist"
        );
        assert!(!bundle.exists());
        assert_eq!(std::fs::read(&pending).unwrap(), original_request);

        credentials.replace(TlsPolicy::Configured(tls.clone()));
        let recovered = call(owner, "query_v1", &pid, op).await;
        assert_eq!(recovered["issuanceOutcome"], "finalized");
        assert_eq!(recovered["submissionAttempted"], false);
        assert_eq!(recovered["requestSha256"], prepared["requestSha256"]);
        assert_eq!(wrapper.calls.load(Ordering::SeqCst), 2);
        // Identical bytes installed anew still withdraw the captured installation.
        for verb in ["query_v1", "publish_v1"] {
            *wrapper.replacement.lock().unwrap() = Some(TlsPolicy::Configured(tls.clone()));
            withheld(&call(owner, verb, &pid, op).await, false);
            assert!(!bundle.exists());
            assert_eq!(std::fs::read(&pending).unwrap(), original_request);
            assert_eq!(store.list().unwrap().len(), 6);
        }
        assert_eq!(wrapper.calls.load(Ordering::SeqCst), 4);
        *slot.write() = Some(inner);
        let published = call(owner, "publish_v1", &pid, op).await;
        assert_eq!(published["credentialPublished"], true);
        assert_eq!(published["submissionAttempted"], false);
        assert_eq!(
            published["certificateSha256"],
            recovered["certificateSha256"]
        );
        assert_eq!(std::fs::read(&pending).unwrap(), original_request);
        assert_eq!(store.list().unwrap().len(), 6);
    }
}
