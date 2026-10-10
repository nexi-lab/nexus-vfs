//! Search reads preserve storage; admission rejects a whole batch before work.
mod common;

use nexus_search_plugin::embedder::MockEmbedder;
use nexus_search_plugin::index_manager::IndexManager;
use nexus_search_plugin::search_proto::{search_service_server::SearchService, *};
use nexus_search_plugin::service::SearchServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};

fn query(zone: &str, kind: QueryType) -> QueryRequest {
    QueryRequest {
        q: "gentian".into(),
        zone_id: zone.into(),
        query_type: kind as i32,
        ..Default::default()
    }
}

fn service(root: &std::path::Path) -> (SearchServiceImpl, Arc<IndexManager>) {
    let manager = Arc::new(IndexManager::with_root(root.to_owned()));
    let service = SearchServiceImpl::builder(Arc::new(common::poison_handle()))
        .manager(Arc::clone(&manager))
        .embedder(Arc::new(MockEmbedder::with_dim(8)))
        .no_expander()
        .no_peer_fanout()
        .title_arm(true)
        .build();
    (service, manager)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_read_paths_leave_unknown_corpora_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let (svc, manager) = service(tmp.path());
    for kind in [QueryType::Keyword, QueryType::Semantic, QueryType::Hybrid] {
        let response = svc
            .query(Request::new(query("unknown", kind)))
            .await
            .unwrap()
            .into_inner();
        assert!(response.error.is_none(), "{response:?}");
        assert!(response.results.is_empty());
    }
    let batch = svc
        .batch_query(Request::new(BatchQueryRequest {
            queries: vec![
                query("unknown", QueryType::Keyword),
                query("another", QueryType::Semantic),
            ],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(batch.responses.len(), 2);
    assert!(batch
        .responses
        .iter()
        .all(|r| r.error.is_none() && r.results.is_empty()));
    let locate = svc
        .locate(Request::new(LocateRequest {
            zone_id: "unknown".into(),
            path: "/docs/a.md".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!locate.indexed);
    let stats = svc
        .stats(Request::new(StatsRequest {
            zone_id: "unknown".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            stats.fts_doc_count,
            stats.ann_chunk_count,
            stats.parked_count,
            stats.last_index_seq
        ),
        (0, 0, 0, 0)
    );
    assert!(svc
        .parked_list(Request::new(ParkedListRequest {
            zone_id: "unknown".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .entries
        .is_empty());
    assert!(svc
        .list_indexed_directories(Request::new(ListIndexedDirectoriesRequest {
            zone_id: "unknown".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .directories
        .is_empty());
    assert!(svc
        .list_zone_indexing_modes(Request::new(ListZoneIndexingModesRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .modes
        .is_empty());
    assert!(manager.fts_writer_report().is_empty());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_indexed_rpc_rejects_unsafe_zone_before_creating_state() {
    let tmp = tempfile::tempdir().unwrap();
    let (svc, _) = service(tmp.path());
    macro_rules! rejects {
        ($call:expr) => {
            assert_eq!($call.await.unwrap_err().code(), Code::InvalidArgument);
        };
    }
    for zone in [
        "../escape",
        "a/b",
        "a\\b",
        ".",
        "..",
        "/tmp/escape",
        "C:escape",
        ".. ",
        "zone.",
        "zone ",
        "a\0b",
    ] {
        rejects!(svc.query(Request::new(query(zone, QueryType::Keyword))));
        rejects!(svc.batch_query(Request::new(BatchQueryRequest {
            queries: vec![
                query("valid", QueryType::Semantic),
                query(zone, QueryType::Semantic)
            ],
            ..Default::default()
        })));
        rejects!(svc.index(Request::new(IndexRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(svc.refresh(Request::new(RefreshRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(svc.index_documents(Request::new(IndexDocumentsRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(
            svc.notify_file_change(Request::new(NotifyFileChangeRequest {
                zone_id: zone.into(),
                ..Default::default()
            }))
        );
        rejects!(svc.locate(Request::new(LocateRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(svc.parked_list(Request::new(ParkedListRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(svc.parked_retry(Request::new(ParkedRetryRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(svc.parked_discard(Request::new(ParkedDiscardRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
        rejects!(
            svc.add_indexed_directory(Request::new(AddIndexedDirectoryRequest {
                zone_id: zone.into(),
                ..Default::default()
            }))
        );
        rejects!(
            svc.remove_indexed_directory(Request::new(RemoveIndexedDirectoryRequest {
                zone_id: zone.into(),
                ..Default::default()
            }))
        );
        rejects!(
            svc.list_indexed_directories(Request::new(ListIndexedDirectoriesRequest {
                zone_id: zone.into(),
                ..Default::default()
            }))
        );
        rejects!(
            svc.set_zone_indexing_mode(Request::new(SetZoneIndexingModeRequest {
                zone_id: zone.into(),
                ..Default::default()
            }))
        );
        rejects!(svc.stats(Request::new(StatsRequest {
            zone_id: zone.into(),
            ..Default::default()
        })));
    }
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_zone_batch_is_rejected_without_committing_its_valid_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let (svc, manager) = service(tmp.path());
    let response = svc
        .index_documents(Request::new(IndexDocumentsRequest {
            zone_id: "valid".into(),
            documents: vec![
                DocumentInput {
                    path: "/docs/a.md".into(),
                    text: "gentian".into(),
                    ..Default::default()
                },
                DocumentInput {
                    path: "/docs/b.md".into(),
                    text: "gentian".into(),
                    zone_id: "../../escape".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(response.code(), Code::InvalidArgument);
    assert!(manager.fts_writer_report().is_empty());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    let stats = svc
        .stats(Request::new(StatsRequest {
            zone_id: "valid".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            stats.last_index_seq,
            stats.pending,
            stats.indexing_in_progress
        ),
        (0, 0, 0)
    );
}
