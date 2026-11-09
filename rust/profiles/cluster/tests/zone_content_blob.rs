//! Actual mTLS and native CAS namespaces; every byte belongs to a test fixture.
#![cfg(all(feature = "driver-cas-local", target_os = "linux"))]

#[path = "common/ports.rs"]
mod ports;

use std::sync::Arc;
use std::time::Duration;

use backends::storage::cas_local::CasLocalBackend;
use backends::storage::zone_cas_local::ZoneCasLocalStores;
use kernel::abc::object_store::ObjectStore;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::{Kernel, OperationContext, WriteRequest};
use kernel::meta_store::{FileMetadata, DT_LINK};
use nexus_cluster::zone_content::ZoneContentBlobFetcher;
use nexus_raft::blob_fetcher_handler::KernelBlobFetcher;
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient, ReadBlobRequest, ReadZoneBlobRequest,
};
use nexus_raft::transport::{
    generate_node_cert, generate_user_runtime_cert, generate_zone_ca, TlsConfig,
};
use nexus_raft::zone_manager::TlsFiles;
use nexus_raft::ZoneManager;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

async fn connect(
    address: &str,
    ca: &[u8],
    cert: Vec<u8>,
    key: Vec<u8>,
) -> ZoneApiServiceClient<Channel> {
    let endpoint = Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .timeout(Duration::from_secs(5))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(TlsConfig::CLUSTER_SERVER_NAME)
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(cert, key)),
        )
        .unwrap();
    let channel = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(channel) = endpoint.connect().await {
                break channel;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("native mTLS listener starts");
    ZoneApiServiceClient::new(channel)
}

fn request(zone_id: &str, content_id: &str) -> ReadZoneBlobRequest {
    ReadZoneBlobRequest {
        zone_id: zone_id.into(),
        content_id: content_id.into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_blob_rpc_cannot_use_a_known_hash_or_forged_pointer_to_read_other_namespaces() {
    let root = tempfile::tempdir().unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (server_cert, server_key) = generate_node_cert(1, "root", &ca, &ca_key, &[], None).unwrap();
    let tls = TlsFiles {
        cert_path: root.path().join("node.pem"),
        key_path: root.path().join("node-key.pem"),
        ca_path: root.path().join("ca.pem"),
        ca_key_path: None,
        join_token_hash: None,
    };
    std::fs::write(&tls.cert_path, server_cert).unwrap();
    std::fs::write(&tls.key_path, server_key).unwrap();
    std::fs::write(&tls.ca_path, &ca).unwrap();
    let address = format!("127.0.0.1:{}", ports::free_port());
    let manager = ZoneManager::with_node_id(
        "zone-content-test",
        1,
        root.path().join("raft").to_str().unwrap(),
        vec![],
        &address,
        Some(tls),
        Some(format!("https://{address}")),
        None,
    )
    .unwrap();
    let kernel = Arc::new(Kernel::new());
    let global =
        Arc::new(CasLocalBackend::new_durable(&root.path().join("global-private")).unwrap());
    kernel
        .vfs_router_arc()
        .add_mount("/", "root", Some(global.clone()), false);
    let boot = OperationContext::new("system", "root", true, None, true);
    let global_bytes = b"cluster administrator secret";
    let global_hash = global
        .write_content(global_bytes, "", &boot, 0)
        .unwrap()
        .content_id;
    let legacy = Arc::new(KernelBlobFetcher::new(
        kernel.clone(),
        kernel.vfs_router_arc(),
        kernel.content_id_lookup_fn("root"),
    ));
    let fetcher = Arc::new(ZoneContentBlobFetcher::new(legacy));
    let stores = ZoneCasLocalStores::open(&root.path().join("zone-content")).unwrap();
    let mut namespaces = Vec::new();
    let mut metadata = Vec::new();
    for name in ["agent-alice", "conversation-alice-bob", "agent-charlie"] {
        let zone = manager.create_zone_async(name, vec![]).await.unwrap();
        assert!(zone.wait_for_leader(Duration::from_secs(10)));
        let objects = stores.prepare(name).unwrap();
        let source = fetcher.bind(&zone, objects.clone()).unwrap();
        kernel
            .mount(
                "/",
                MountOptions::new(&boot, "zone-cas")
                    .with_zone(name)
                    .with_backend(objects.backend())
                    .with_metastore(source.clone()),
            )
            .unwrap();
        namespaces.push(objects);
        metadata.push(source);
    }
    *manager.blob_fetcher_slot().write() = Some(fetcher.clone());
    let alice = OperationContext::new("owner-alice", "agent-alice", true, Some("alice"), false);
    let private_bytes = b"private Agent memory and progress";
    let written = kernel.sys_write(
        &[WriteRequest {
            path: "/memory.txt".into(),
            content: private_bytes.to_vec(),
            offset: 0,
        }],
        &alice,
    );
    let private_hash = written[0].as_ref().unwrap().content_id.clone().unwrap();
    // Even a forged metadata reference cannot move a private CAS object into
    // another namespace. The physical namespace remains the content boundary.
    metadata[1]
        .put(
            "/forged",
            FileMetadata {
                path: "/forged".into(),
                content_id: Some(private_hash.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    metadata[1]
        .put(
            "/alias",
            FileMetadata {
                path: "/alias".into(),
                entry_type: DT_LINK,
                link_target: Some("/memory.txt".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let (cert, key) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
    let mut client = connect(&address, &ca, cert, key).await;
    for address in [private_hash.as_str(), "/memory.txt"] {
        let response = client
            .read_zone_blob(request("agent-alice", address))
            .await
            .unwrap()
            .into_inner();
        assert!(response.error.is_empty(), "{}", response.error);
        assert_eq!(response.content, private_bytes);
    }
    for zone in ["agent-alice", "conversation-alice-bob", "agent-charlie"] {
        let response = client
            .read_zone_blob(request(zone, &global_hash))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.error.is_empty());
        assert!(response.content.is_empty());
    }
    for address in [private_hash.as_str(), "/forged", "/alias"] {
        let response = client
            .read_zone_blob(request("conversation-alice-bob", address))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.error.is_empty());
        assert!(response.content.is_empty());
    }
    let global = client
        .read_blob(ReadBlobRequest {
            content_id: global_hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(global.content, global_bytes);
    assert!(global.error.is_empty());
    for selector in ["", "root", "../agent-alice"] {
        assert_eq!(
            client
                .read_zone_blob(request(selector, &private_hash))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    for address in ["", "a", "é🦀", "../global-private"] {
        let response = client
            .read_zone_blob(request("agent-alice", address))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.error.is_empty());
        assert!(response.content.is_empty());
    }
    // The selector does not grant an authenticated user runtime Node authority.
    let (cert, key) =
        generate_user_runtime_cert("charlie-runtime", "owner-charlie", 300, &ca, &ca_key).unwrap();
    let mut charlie = connect(&address, &ca, cert, key).await;
    assert_eq!(
        charlie
            .read_zone_blob(request("agent-alice", &private_hash))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let target = tempfile::tempdir().unwrap();
    let target_stores = ZoneCasLocalStores::open(target.path()).unwrap();
    let local = target_stores.prepare("agent-alice").unwrap();
    let response = client
        .read_zone_blob(request("agent-alice", &private_hash))
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_empty());
    let retained = local
        .backend()
        .write_content(&response.content, "", &alice, 0)
        .unwrap();
    assert_eq!(retained.content_id, private_hash);
    let stopped = Arc::clone(&manager);
    tokio::task::spawn_blocking(move || stopped.shutdown())
        .await
        .unwrap();
    assert_eq!(local.read_blob(&private_hash).unwrap(), private_bytes);
    fetcher.unbind("agent-alice").unwrap();
    assert!(nexus_raft::blob_fetcher::BlobFetcher::read_in_zone(
        fetcher.as_ref(),
        "agent-alice",
        &private_hash
    )
    .await
    .is_err());
}
