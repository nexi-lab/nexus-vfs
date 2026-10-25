//! Real mTLS control-plane refusal, not an Agent/VFS mock. All CA keys and
//! consensus data are isolated; no fleet endpoint or model is used.
#![cfg(all(feature = "grpc", has_protos))]
mod common;

use lib::transport_primitives::{FederatedClientCertVerifier, ForeignCaAnchor};
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient,
    zone_transport_service_client::ZoneTransportServiceClient, MintSessionAgentRequest,
    ProposeRequest, StepMessageRequest,
};
use nexus_raft::{
    prelude::Command,
    raft::ZoneRaftRegistry,
    transport::{
        generate_agent_cert, generate_node_cert, generate_zone_ca, RaftGrpcServer, ServerConfig,
        TlsConfig,
    },
};
use std::{sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

async fn connect(address: &str, ca: &[u8], cert: Vec<u8>, key: Vec<u8>) -> Channel {
    Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .timeout(Duration::from_secs(5))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(cert, key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap()
}
fn put(key: &str) -> ProposeRequest {
    ProposeRequest {
        zone_id: "root".into(),
        request_id: format!("isolated-{key}"),
        command: None,
        forwarded: false,
        raw_command: bincode::serialize(&Command::PutControlState {
            namespace: "node-boundary-fixture".into(),
            key: key.into(),
            value: b"private fixture value".to_vec(),
            if_absent: true,
        })
        .unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_and_foreign_nodes_cannot_propose_or_step_but_local_nodes_can() {
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (foreign, foreign_key) = generate_zone_ca("root").unwrap();
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let verifier = FederatedClientCertVerifier::new(&ca).unwrap();
    verifier
        .set_foreign_cas(&[ForeignCaAnchor::from_pem("edge", &foreign).unwrap()])
        .unwrap();
    let private = tempfile::tempdir().unwrap();
    let registry = Arc::new(ZoneRaftRegistry::new(private.path().to_path_buf(), 1));
    let node = registry
        .create_zone("root", vec![], &tokio::runtime::Handle::current())
        .unwrap();
    node.campaign().await.unwrap();
    let address = common::node_bind_addr();
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: address.parse().unwrap(),
            tls: Some(TlsConfig {
                ca_pem: ca.clone(),
                cert_pem: server_cert,
                key_pem: server_key,
            }),
            ..ServerConfig::default()
        },
    )
    .with_foreign_ca_verifier(Some(verifier));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        server
            .serve_with_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    // Readiness only, before any data submission. No RPC/write is retried.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(&address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("isolated listener must bind");

    let (node_cert, node_key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let channel = connect(&address, &ca, node_cert, node_key).await;
    let mut local = ZoneApiServiceClient::new(channel);
    assert!(
        local
            .propose(put("local-node"))
            .await
            .unwrap()
            .into_inner()
            .success
    );
    let stored = node
        .read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", "local-node"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, Some(b"private fixture value".to_vec()));
    drop(local);

    let domestic = generate_agent_cert("domestic-agent", &ca, &ca_key).unwrap();
    let foreign_agent = generate_agent_cert("foreign-agent", &foreign, &foreign_key).unwrap();
    let foreign_node = generate_node_cert(2, "root", &foreign, &foreign_key, &[], None).unwrap();
    for (label, (cert, key)) in [
        ("domestic-agent", domestic),
        ("foreign-agent", foreign_agent),
        ("foreign-node", foreign_node),
    ] {
        let channel = connect(&address, &ca, cert, key).await;
        let mut api = ZoneApiServiceClient::new(channel.clone());
        let refusal = api
            .propose(put(label))
            .await
            .expect_err("Agent or foreign Node reached the Node-only Propose RPC");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
        let stored = node
            .read_linearizable(|sm| sm.get_control_state("node-boundary-fixture", label))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, None, "refusal must precede control-state mutation");
        let mut transport = ZoneTransportServiceClient::new(channel);
        let refusal = transport
            .step_message(StepMessageRequest {
                message: vec![0xff],
                zone_id: "root".into(),
                sender_address: String::new(),
            })
            .await
            .expect_err("unprivileged peer reached Raft message parsing");
        assert_eq!(refusal.code(), tonic::Code::PermissionDenied);
        if label != "foreign-node" {
            // This allowed door still reaches its own issuer gate. An empty
            // minter slot refuses minting; RPC acceptance confers no credential.
            let reply = api
                .mint_session_agent(MintSessionAgentRequest {
                    owner_id: "owner".into(),
                    validity_secs: 300,
                })
                .await
                .unwrap()
                .into_inner();
            assert!(!reply.success);
        }
    }
    stop.send(()).unwrap();
    running.await.unwrap();
    drop(node);
    registry.shutdown_all();
    drop(registry);
    tokio::time::sleep(Duration::from_millis(500)).await;
}
