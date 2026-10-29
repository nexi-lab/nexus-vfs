//! Raw immutable objects and logical file reads share the existing peer RPC.
#![cfg(feature = "driver-cas-local")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use backends::storage::cas_local::CasLocalBackend;
use kernel::abc::object_store::ObjectStore;
use kernel::kernel::{Kernel, OperationContext, WriteRequest};
use nexus_raft::blob_fetcher_handler::KernelBlobFetcher;
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient, ReadBlobRequest,
};
use nexus_raft::ZoneManager;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_blob_preserves_manifest_identity_and_logical_path_contents() {
    let root = tempfile::tempdir().unwrap();
    let backend = Arc::new(CasLocalBackend::new(&root.path().join("objects"), true).unwrap());
    let ctx = OperationContext::new("system", contracts::ROOT_ZONE_ID, true, None, true);
    let content = b"one immutable message";
    let chunk = backend
        .write_content(content, "", &ctx, 0)
        .unwrap()
        .content_id;
    let manifest = serde_json::to_vec(&serde_json::json!({
        "type": "chunked_manifest", "total_size": content.len(),
        "chunks": [{"chunk_hash": chunk, "offset": 0, "length": content.len()}]
    }))
    .unwrap();
    let hash = lib::hash::hash_content(&manifest);
    let kernel = Arc::new(Kernel::new());
    kernel
        .vfs_router_arc()
        .add_mount("/", contracts::ROOT_ZONE_ID, Some(backend.clone()), false);
    let written = kernel.sys_write(
        &[WriteRequest {
            path: "/published".into(),
            content: manifest.clone(),
            offset: 0,
        }],
        &ctx,
    );
    assert!(written[0].is_ok(), "{:?}", written[0].as_ref().err());
    let lookup = kernel.content_id_lookup_fn(contracts::ROOT_ZONE_ID);
    assert_eq!(lookup("/published"), Some(hash.clone()));
    assert_eq!(lookup(&hash), None);

    // This is an isolated plaintext test listener. Production Node admission
    // and owner mTLS are covered by the separate transport/runtime fixtures.
    let address = format!("127.0.0.1:{}", common::free_port());
    let manager = ZoneManager::with_node_id(
        "peer-blob-fixture",
        1,
        root.path().join("raft").to_str().unwrap(),
        vec![],
        &address,
        None,
        Some(format!("http://{address}")),
        None,
    )
    .unwrap();
    *manager.blob_fetcher_slot().write() = Some(Arc::new(KernelBlobFetcher::new(
        kernel.clone(),
        kernel.vfs_router_arc(),
        lookup.clone(),
    )));
    let until = Instant::now() + Duration::from_secs(10);
    let mut client = loop {
        match ZoneApiServiceClient::connect(format!("http://{address}")).await {
            Ok(client) => break client,
            Err(error) => {
                assert!(Instant::now() < until, "peer RPC did not start: {error}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    let raw = client
        .read_blob(ReadBlobRequest {
            content_id: hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(raw.error.is_empty(), "{}", raw.error);
    assert_eq!(
        raw.content, manifest,
        "a hash request must return the object with that exact hash"
    );
    assert_eq!(lib::hash::hash_content(&raw.content), hash);
    assert_eq!(
        lookup(&hash),
        None,
        "a blob read must not invent a logical file"
    );
    let logical = client
        .read_blob(ReadBlobRequest {
            content_id: "/published".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(logical.error.is_empty(), "{}", logical.error);
    assert_eq!(logical.content, content);
    assert_eq!(lookup("/published"), Some(hash.clone()));
    // Absolute file paths remain distinct from immutable addresses, including
    // a file whose name happens to be a hexadecimal content hash.
    let hex_path = format!("/{hash}");
    let named_file = b"a logical file with a hexadecimal name";
    let written = kernel.sys_write(
        &[WriteRequest {
            path: hex_path.clone(),
            content: named_file.to_vec(),
            offset: 0,
        }],
        &ctx,
    );
    assert!(written[0].is_ok(), "{:?}", written[0].as_ref().err());
    let addressed = client
        .read_blob(ReadBlobRequest {
            content_id: hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(addressed.error.is_empty(), "{}", addressed.error);
    assert_eq!(addressed.content, manifest);
    let named = client
        .read_blob(ReadBlobRequest {
            content_id: hex_path,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(named.error.is_empty(), "{}", named.error);
    assert_eq!(named.content, named_file);
    let raw_chunk = client
        .read_blob(ReadBlobRequest {
            content_id: chunk.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(raw_chunk.error.is_empty(), "{}", raw_chunk.error);
    assert_eq!(raw_chunk.content, content);
    assert_eq!(lookup(&chunk), None);
    let object_path = backend.as_cas().unwrap().transport().blob_path(&hash);
    std::fs::write(&object_path, b"damaged object").unwrap();
    let damaged = client
        .read_blob(ReadBlobRequest {
            content_id: hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!damaged.error.is_empty());
    assert!(damaged.content.is_empty());
    assert_eq!(std::fs::read(object_path).unwrap(), b"damaged object");
    drop(client);
    manager.shutdown();
}
