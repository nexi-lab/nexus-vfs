use super::*;

#[path = "tests/control.rs"]
mod control;
use contracts::replica_binding::{
    ReplicaAllocation, ReplicaBinding, ReplicaBindingChange, ReplicaBindingOutcome,
    ReplicaBindingRequest, ReplicaStorage,
};
use contracts::replica_credential::ReplicaIssuerAuthority;
use nexus_raft::{
    auth_key_store::RaftAuthKeyStore,
    transport::{
        add_revoked_serial, generate_agent_cert, generate_node_cert, generate_user_replica_cert,
        generate_zone_ca, prepare_replica_csr_intent,
        proto::zone_api_service_client::ZoneApiServiceClient, RaftGrpcServer, ServerConfig,
        TlsConfig,
    },
    ZoneManager,
};
use rcgen::{CertificateParams, KeyPair};
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use x509_parser::prelude::{FromDer, X509Certificate};

#[path = "../../tests/common/ports.rs"]
mod ports;

struct Fixture {
    manager: Arc<ZoneManager>,
    store: Arc<RaftReplicaBindingStore>,
    founder: Arc<FounderAgentMinter>,
    binding: ReplicaBinding,
    authority: ReplicaIssuerAuthority,
    ca: Vec<u8>,
    ca_key: Vec<u8>,
    caller: (Vec<u8>, Vec<u8>),
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let manager =
            ZoneManager::isolated(directory.path().join("raft").to_str().unwrap()).unwrap();
        let zone = manager.create_zone("root").unwrap();
        assert!(zone.wait_for_leader(Duration::from_secs(5)));
        let node = zone.consensus_node();
        let store = Arc::new(RaftReplicaBindingStore::new(
            node.clone(),
            manager.runtime_handle(),
        ));
        assert_eq!(store.issuer_authority().unwrap(), None);
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let tls = directory.path().join("tls");
        std::fs::create_dir(&tls).unwrap();
        std::fs::write(tls.join("ca.pem"), &ca).unwrap();
        std::fs::write(tls.join("ca-key.pem"), &ca_key).unwrap();
        let peer_verifier = Arc::new(OnceLock::new());
        peer_verifier
            .set(lib::transport_primitives::FederatedClientCertVerifier::new(&ca).unwrap())
            .unwrap();
        let replica_store = new_store_slot();
        assert!(replica_store.set(store.clone()).is_ok());
        let founder = Arc::new(FounderAgentMinter {
            store: RaftAuthKeyStore::new_arc(node, manager.runtime_handle()),
            tls_dir: tls,
            data_dir: directory.path().to_path_buf(),
            session_allow: nexus_raft::session_mint_allow_store::new_session_mint_allow_slot(),
            replica_store,
            peer_verifier,
        });
        let ReplicaBindingOutcome::Applied(binding) = store
            .apply(&ReplicaBindingRequest {
                operation_id: "observed-storage-allocation".into(),
                allocation: ReplicaAllocation {
                    owner_id: "owner-a".into(),
                    allocation_id: "existing-home".into(),
                },
                change: ReplicaBindingChange::Register {
                    storage: ReplicaStorage {
                        authority: "test-control-plane".into(),
                        uid: "actual-test-pvc".into(),
                    },
                    replica_id: 47,
                },
            })
            .unwrap()
        else {
            panic!("original allocation must commit");
        };
        let authority = ReplicaIssuerAuthority {
            revision: 1,
            issuer_sha256: Some(lib::transport_primitives::cert_fingerprint(
                pem::parse(&ca).unwrap().contents(),
            )),
        };
        store
            .issue(&ReplicaIssuanceRequest {
                operation_id: "original-ca-admission".into(),
                change: ReplicaIssuanceChange::Authority {
                    expected_revision: None,
                    issuer_sha256: authority.issuer_sha256,
                },
            })
            .unwrap();
        let caller = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
        Self {
            manager,
            store,
            founder,
            binding,
            authority,
            ca,
            ca_key,
            caller,
            _directory: directory,
        }
    }

    fn request(&self, operation: &str) -> ReplicaCsrRequest {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let intent = prepare_replica_csr_intent(
            &self.binding,
            &self.authority,
            "retained-replica",
            300,
            csr.as_bytes(),
            &self.ca,
        )
        .unwrap();
        ReplicaCsrRequest {
            preparation_json: serde_json::to_vec(&ReplicaIssuanceRequest {
                operation_id: operation.into(),
                change: ReplicaIssuanceChange::Prepare {
                    intent: Box::new(intent),
                    renews: None,
                },
            })
            .unwrap(),
            publication_operation_id: format!("publish-{operation}"),
            csr_pem: csr.into_bytes(),
            renewal: None,
        }
    }

    async fn start(
        &self,
    ) -> (
        String,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let address = format!("127.0.0.1:{}", ports::free_port());
        let (cert, key) = generate_node_cert(1, "root", &self.ca, &self.ca_key, &[], None).unwrap();
        let slot = nexus_raft::agent_minter::new_agent_minter_slot();
        *slot.write() = Some(self.founder.clone());
        let tls = TlsConfig {
            ca_pem: self.ca.clone(),
            cert_pem: cert,
            key_pem: key,
        };
        self.manager
            .registry()
            .shared_tls()
            .replace(lib::transport_primitives::TlsPolicy::Configured(tls.clone()));
        let server = RaftGrpcServer::new(
            self.manager.registry(),
            ServerConfig {
                bind_address: address.parse().unwrap(),
                tls: Some(tls),
                ..Default::default()
            },
        )
        .with_agent_minter_slot(slot)
        .with_foreign_ca_verifier(Some(self.founder.peer_verifier.get().unwrap().clone()));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .serve_with_shutdown(async { stopped.await.unwrap() })
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while tokio::net::TcpStream::connect(&address).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        (address, stop, task)
    }

    async fn connect(
        &self,
        address: &str,
        identity: &(Vec<u8>, Vec<u8>),
    ) -> ZoneApiServiceClient<Channel> {
        let channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .timeout(Duration::from_secs(5))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(Certificate::from_pem(&self.ca))
                    .identity(Identity::from_pem(&identity.0, &identity.1)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        ZoneApiServiceClient::new(channel)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.shutdown();
    }
}

fn require_state(reply: &ReplicaCsrResponse, state: ReplicaCsrState) {
    assert_eq!(
        reply.state, state as i32,
        "unexpected replica reply: {reply:?}"
    );
}

fn withdrawn_worker_reply(query_only: bool) {
    let fixture = Fixture::open();
    let caller = pem::parse(&fixture.caller.0).unwrap().into_contents();
    let original = fixture.request("withdrawn-worker-result");
    let issued = execute(
        &fixture.founder,
        Some(caller.clone()),
        original.clone(),
        false,
    );
    require_state(&issued, ReplicaCsrState::Published);
    let stored = fixture.store.credential("withdrawn-worker-result").unwrap();
    let authority = ReplyAuthority::capture(&fixture.founder, Some(&caller)).unwrap();
    let founder = fixture.founder.clone();
    let request = original.clone();
    let revocations = revoked_serials_path(&fixture.founder.data_dir);
    let serial = authority.serial.clone();
    let reply =
        fixture
            .manager
            .runtime_handle()
            .block_on(authority.release(query_only, async move {
                let completed = tokio::task::spawn_blocking(move || {
                    execute(&founder, Some(caller), request, query_only)
                })
                .await
                .unwrap();
                require_state(&completed, ReplicaCsrState::Published);
                // The original native operation has finished; withdraw the caller at
                // the actual worker-result await boundary, before response release.
                add_revoked_serial(&revocations, &serial).unwrap();
                completed
            }));
    require_state(
        &reply,
        if query_only {
            ReplicaCsrState::Refused
        } else {
            ReplicaCsrState::Unknown
        },
    );
    assert!(reply.certificate_der.is_empty() && reply.ca_pem.is_empty());
    assert_eq!(
        fixture.store.credential("withdrawn-worker-result").unwrap(),
        stored
    );
    // A different currently authorized Node reads the SAME original result;
    // late withdrawal did not erase the operation or authorize a replacement.
    let (recovery, _) =
        generate_node_cert(3, "root", &fixture.ca, &fixture.ca_key, &[], None).unwrap();
    let recovered = execute(
        &fixture.founder,
        Some(pem::parse(recovery).unwrap().into_contents()),
        original,
        true,
    );
    assert_eq!(recovered, issued);
}

#[test]
fn issue_withdrawn_after_worker_completion_retains_unknown_and_original_publication() {
    withdrawn_worker_reply(false);
}

#[test]
fn query_withdrawn_after_worker_completion_withholds_the_read_only_result() {
    withdrawn_worker_reply(true);
}

#[test]
fn real_mtls_replica_issuance_preserves_original_publication_and_current_revocation() {
    let fixture = Fixture::open();
    fixture.manager.runtime_handle().block_on(async {
        let (address, stop, task) = fixture.start().await;
        let mut controller = fixture.connect(&address, &fixture.caller).await;
        let original = fixture.request("original-credential");
        let missing = controller
            .query_replica_csr_v1(original.clone())
            .await
            .unwrap()
            .into_inner();
        require_state(&missing, ReplicaCsrState::NotObserved);
        assert!(missing.certificate_der.is_empty());
        let mut invalid = original.clone();
        invalid.csr_pem = fixture.request("another-key").csr_pem;
        let refused = controller
            .issue_replica_csr_v1(invalid)
            .await
            .unwrap()
            .into_inner();
        require_state(&refused, ReplicaCsrState::Refused);
        assert_eq!(
            fixture.store.credential("original-credential").unwrap(),
            None
        );

        // Lose signing after the real preparation has committed, then recover
        // that exact intent through the wire without another operation or key.
        let key_path = fixture.founder.tls_dir.join("ca-key.pem");
        let held_key = fixture.founder.tls_dir.join("held-key.pem");
        std::fs::rename(&key_path, &held_key).unwrap();
        std::fs::write(&key_path, b"invalid fixture signing key").unwrap();
        let unknown = controller
            .issue_replica_csr_v1(original.clone())
            .await
            .unwrap()
            .into_inner();
        require_state(&unknown, ReplicaCsrState::Unknown);
        let prepared = controller
            .query_replica_csr_v1(original.clone())
            .await
            .unwrap()
            .into_inner();
        require_state(&prepared, ReplicaCsrState::Prepared);
        assert!(prepared.certificate_der.is_empty());
        assert_eq!(prepared.preparation_json, original.preparation_json);
        std::fs::rename(&key_path, fixture.founder.tls_dir.join("fault-key.pem")).unwrap();
        std::fs::rename(&held_key, &key_path).unwrap();

        let issued = controller
            .issue_replica_csr_v1(original.clone())
            .await
            .unwrap()
            .into_inner();
        require_state(&issued, ReplicaCsrState::Published);
        assert_eq!(issued.preparation_json, original.preparation_json);
        assert_eq!(issued.operation_id, "original-credential");
        assert_eq!(
            fixture
                .store
                .credential("original-credential")
                .unwrap()
                .unwrap()
                .certificate_der
                .as_ref(),
            Some(&issued.certificate_der)
        );
        let replay = controller
            .issue_replica_csr_v1(original.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(replay, issued);

        // Readback uses the committed credential without access to the signer.
        std::fs::rename(&key_path, &held_key).unwrap();
        let queried = controller
            .query_replica_csr_v1(original.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(queried, issued);
        std::fs::rename(held_key, key_path).unwrap();
        let caller_der = pem::parse(&fixture.caller.0).unwrap().into_contents();
        let (_, caller) = X509Certificate::from_der(&caller_der).unwrap();
        add_revoked_serial(
            &revoked_serials_path(&fixture.founder.data_dir),
            caller.raw_serial(),
        )
        .unwrap();
        let revoked = controller
            .query_replica_csr_v1(original)
            .await
            .unwrap()
            .into_inner();
        require_state(&revoked, ReplicaCsrState::Refused);
        assert!(revoked.error.unwrap().contains("revoked"));
        assert!(revoked.certificate_der.is_empty());
        assert_eq!(
            fixture
                .store
                .credential("original-credential")
                .unwrap()
                .unwrap()
                .certificate_der
                .as_ref(),
            Some(&issued.certificate_der)
        );
        stop.send(()).unwrap();
        task.await.unwrap();
    });
}

#[test]
fn real_mtls_agents_and_owner_replicas_cannot_enter_replica_issuance() {
    let fixture = Fixture::open();
    fixture.manager.runtime_handle().block_on(async {
        let (address, stop, task) = fixture.start().await;
        let original = fixture.request("node-only-operation");
        let agent = generate_agent_cert("front-door-agent", &fixture.ca, &fixture.ca_key).unwrap();
        let replica = generate_user_replica_cert(
            "owner-replica",
            "owner-a",
            47,
            300,
            &fixture.ca,
            &fixture.ca_key,
        )
        .unwrap();
        for identity in [agent, replica] {
            let mut caller = fixture.connect(&address, &identity).await;
            let issue = caller
                .issue_replica_csr_v1(original.clone())
                .await
                .unwrap_err();
            assert_eq!(issue.code(), tonic::Code::PermissionDenied);
            let query = caller
                .query_replica_csr_v1(original.clone())
                .await
                .unwrap_err();
            assert_eq!(query.code(), tonic::Code::PermissionDenied);
        }
        assert_eq!(
            fixture.store.credential("node-only-operation").unwrap(),
            None
        );
        let mut controller = fixture.connect(&address, &fixture.caller).await;
        require_state(
            &controller
                .query_replica_csr_v1(original)
                .await
                .unwrap()
                .into_inner(),
            ReplicaCsrState::NotObserved,
        );
        stop.send(()).unwrap();
        task.await.unwrap();
    });
}

#[test]
fn readback_refuses_a_retired_allocation_and_cannot_submit_control_transitions() {
    let fixture = Fixture::open();
    fixture.manager.runtime_handle().block_on(async {
        let (address, stop, task) = fixture.start().await;
        let mut controller = fixture.connect(&address, &fixture.caller).await;
        let original = fixture.request("retired-original");
        require_state(
            &controller
                .issue_replica_csr_v1(original.clone())
                .await
                .unwrap()
                .into_inner(),
            ReplicaCsrState::Published,
        );
        let illegal = ReplicaCsrRequest {
            preparation_json: serde_json::to_vec(&ReplicaIssuanceRequest {
                operation_id: "cannot-disable-authority".into(),
                change: ReplicaIssuanceChange::Authority {
                    expected_revision: Some(1),
                    issuer_sha256: None,
                },
            })
            .unwrap(),
            ..original.clone()
        };
        require_state(
            &controller
                .query_replica_csr_v1(illegal)
                .await
                .unwrap()
                .into_inner(),
            ReplicaCsrState::Refused,
        );
        assert_eq!(
            fixture.store.issuer_authority().unwrap(),
            Some(fixture.authority.clone())
        );
        fixture
            .store
            .apply(&ReplicaBindingRequest {
                operation_id: "retire-original-storage".into(),
                allocation: fixture.binding.allocation.clone(),
                change: ReplicaBindingChange::Retire {
                    expected_revision: fixture.binding.revision,
                },
            })
            .unwrap();
        let retired = controller
            .query_replica_csr_v1(original)
            .await
            .unwrap()
            .into_inner();
        require_state(&retired, ReplicaCsrState::Refused);
        assert!(retired.certificate_der.is_empty());
        assert!(fixture
            .store
            .credential("retired-original")
            .unwrap()
            .unwrap()
            .authority_denial
            .is_some());
        stop.send(()).unwrap();
        task.await.unwrap();
    });
}
