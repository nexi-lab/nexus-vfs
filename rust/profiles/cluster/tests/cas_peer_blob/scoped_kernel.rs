//! The default daemon fetcher serves only a captured data-zone storage pair.

use super::*;
use backends::storage::path_local::PathLocalBackend;
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::federation::ColdSegmentAddress;
use kernel::meta_store::{FileMetadata, MetaStore, DT_LINK, DT_REG, DT_STREAM};
use nexus_raft::blob_fetcher::BlobFetcher;
use nexus_raft::zone_meta_store::ZoneMetaStore;

#[test]
fn default_fetcher_resolves_scoped_files_and_indexed_segments_for_cas_and_pas() {
    let directory = tempfile::tempdir().unwrap();
    let manager = ZoneManager::isolated(directory.path().join("raft").to_str().unwrap()).unwrap();
    let alice = manager.create_zone("agent-alice", vec![]).unwrap();
    let bob = manager.create_zone("agent-bob", vec![]).unwrap();
    assert!(alice.wait_for_leader(Duration::from_secs(10)));
    assert!(bob.wait_for_leader(Duration::from_secs(10)));
    for cas in [false, true] {
        let label = if cas { "cas" } else { "pas" };
        let content_dir = directory.path().join(label);
        let backend: Arc<dyn ObjectStore> = if cas {
            Arc::new(CasLocalBackend::new_durable(&content_dir).unwrap())
        } else {
            Arc::new(PathLocalBackend::new(&content_dir, true).unwrap())
        };
        let kernel = Arc::new(Kernel::new());
        let store = Arc::new(ZoneMetaStore::new_with_subtree(
            alice.consensus_node(),
            manager.runtime_handle(),
            "/visible".into(),
            "/sessions".into(),
        ));
        let other_store = Arc::new(ZoneMetaStore::new_with_subtree(
            bob.consensus_node(),
            manager.runtime_handle(),
            "/other".into(),
            "/sessions".into(),
        ));
        kernel.vfs_router_arc().add_federation_mount(
            "/visible",
            "root",
            Some(backend.clone()),
            "agent-alice",
            "/sessions",
            false,
        );
        kernel.install_mount_metastore(
            Kernel::canonical_mount_key("/visible", "root"),
            store.clone(),
        );
        kernel.vfs_router_arc().add_federation_mount(
            "/other",
            "root",
            Some(backend.clone()),
            "agent-bob",
            "/sessions",
            false,
        );
        kernel.install_mount_metastore(
            Kernel::canonical_mount_key("/other", "root"),
            other_store.clone(),
        );
        let ctx = OperationContext::new("system", "agent-alice", true, None, true);
        let body = format!("original {label} content").into_bytes();
        let object = backend
            .write_content(&body, &format!("private-{label}"), &ctx, 0)
            .unwrap()
            .content_id;
        let visible = format!("/visible/file-{label}");
        let canonical = format!("/sessions/file-{label}");
        store
            .put(
                &visible,
                FileMetadata {
                    path: visible.clone(),
                    entry_type: DT_REG,
                    content_id: Some(object.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
        let bob_body = format!("independent Bob {label} content").into_bytes();
        let bob_object = backend
            .write_content(&bob_body, &format!("bob-{label}"), &ctx, 0)
            .unwrap()
            .content_id;
        let bob_visible = format!("/other/file-{label}");
        other_store
            .put(
                &bob_visible,
                FileMetadata {
                    path: bob_visible.clone(),
                    entry_type: DT_REG,
                    content_id: Some(bob_object),
                    ..Default::default()
                },
            )
            .unwrap();
        let link = format!("/visible/link-{label}");
        store
            .put(
                &link,
                FileMetadata {
                    path: link.clone(),
                    entry_type: DT_LINK,
                    link_target: Some(visible.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
        let stream = format!("/sessions/history-{label}");
        let stream_visible = format!("/visible/history-{label}");
        store
            .put(
                &stream_visible,
                FileMetadata {
                    path: stream_visible.clone(),
                    entry_type: DT_STREAM,
                    ..Default::default()
                },
            )
            .unwrap();
        let prefix = wal_stream_prefix(&stream);
        for item in [b"one", b"two"] {
            store.append_stream_entry(&prefix, item).unwrap();
        }
        let locator = ColdSegmentAddress {
            stream_path: &stream,
            base: 0,
        }
        .key("agent-alice");
        let segment_bytes = format!("sealed {label} bytes").into_bytes();
        let sealed_object = backend
            .write_content(&segment_bytes, &locator, &ctx, 0)
            .unwrap()
            .content_id;
        store
            .seal_stream_segment(
                &prefix,
                0,
                2,
                &sealed_object,
                "writer:2028",
                segment_bytes.len() as u64,
            )
            .unwrap();
        assert_eq!(store.stream_floor(&prefix).unwrap(), 2);
        let fetcher = KernelBlobFetcher::new(
            kernel.clone(),
            kernel.vfs_router_arc(),
            kernel.content_id_lookup_fn("root"),
        );
        let read = |zone: &str, key: &str| {
            manager
                .runtime_handle()
                .block_on(fetcher.read_in_zone(zone, key))
        };
        assert_eq!(read("agent-alice", &canonical).unwrap(), body);
        assert_eq!(read("agent-alice", &locator).unwrap(), segment_bytes);
        assert_eq!(read("agent-bob", &canonical).unwrap(), bob_body);
        assert!(read("agent-bob", &locator).is_err());
        assert!(read(
            "agent-bob",
            &ColdSegmentAddress {
                stream_path: &stream,
                base: 0
            }
            .key("agent-bob")
        )
        .is_err());
        assert!(
            read("agent-alice", &object).is_err(),
            "raw object IDs carry no file binding"
        );
        assert!(read("agent-alice", &format!("/sessions/link-{label}")).is_err());
        assert!(
            read(
                "agent-alice",
                &ColdSegmentAddress {
                    stream_path: &stream,
                    base: 1
                }
                .key("agent-alice")
            )
            .is_err(),
            "only the committed exact base identifies a segment"
        );
        assert!(read(
            "agent-alice",
            &format!("/__stream_segments__/agent-alice/sessions/../history-{label}/0")
        )
        .is_err());
        assert!(read(
            "agent-alice",
            &format!("/__stream_segments__/agent-alice{stream}/00")
        )
        .is_err());
        assert_eq!(read("agent-bob", &canonical).unwrap(), bob_body);
        assert_eq!(
            read("agent-alice", &canonical).unwrap(),
            body,
            "denied requests leave ordinary content readable"
        );
    }
    manager.shutdown();
}
