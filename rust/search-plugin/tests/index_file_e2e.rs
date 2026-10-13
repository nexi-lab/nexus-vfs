mod common;

use nexus_search_plugin::embedder::MockEmbedder;
use nexus_search_plugin::index_manager::IndexManager;
use nexus_search_plugin::search_proto::{search_service_server::SearchService, *};
use nexus_search_plugin::service::SearchServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};

fn request(path: &str) -> Request<IndexFileRequest> {
    Request::new(IndexFileRequest {
        path: path.into(),
        ..Default::default()
    })
}

async fn paths(svc: &SearchServiceImpl) -> Vec<String> {
    let response = svc
        .query(Request::new(QueryRequest {
            q: "gentian".into(),
            query_type: QueryType::Keyword as i32,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_none(), "{response:?}");
    response.results.into_iter().map(|hit| hit.path).collect()
}

#[tokio::test]
async fn file_upserts_read_current_vfs_bytes_and_empty_content_commits_eviction() {
    let tmp = tempfile::tempdir().unwrap();
    let mut kernel = Box::new(common::MockKernel::new());
    kernel.add_file("/docs/a.md", b"gentian original document", 100);
    let manager = Arc::new(IndexManager::with_root(tmp.path().to_owned()));
    let svc = SearchServiceImpl::builder(Arc::new(common::handle_for(&*kernel)))
        .manager(manager)
        .embedder(Arc::new(MockEmbedder::with_dim(8)))
        .no_context_generator()
        .index_max_inflight(1)
        .build();
    let first = svc
        .index_file(request("/docs/a.md"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            first.status.as_str(),
            first.index_seq,
            first.zone_id.as_str()
        ),
        ("indexed", 1, "root")
    );
    assert!(first.reason.is_none());
    assert_eq!(paths(&svc).await, ["/docs/a.md"]);
    // Changing the source to binary preserves the old index and creates no
    // receipt. Empty text instead commits a real removal of prior chunks.
    kernel.add_file("/docs/a.md", &[0xff, 0xfe], 101);
    let binary = svc
        .index_file(request("/docs/a.md"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            binary.status.as_str(),
            binary.reason.as_deref(),
            binary.index_seq
        ),
        ("skipped", Some("non_text"), 0)
    );
    assert_eq!(paths(&svc).await, ["/docs/a.md"]);
    kernel.add_file("/docs/a.md", b" \n\t", 102);
    let empty = svc
        .index_file(request("/docs/a.md"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            empty.status.as_str(),
            empty.reason.as_deref(),
            empty.index_seq
        ),
        ("skipped", Some("empty"), 2)
    );
    assert!(paths(&svc).await.is_empty());
    let stats = svc
        .stats(Request::new(StatsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            stats.last_index_seq,
            stats.indexing_in_progress,
            stats.pending
        ),
        (2, 0, 0)
    );
    assert_eq!(stats.fts_path_count, 0);
}

#[tokio::test]
async fn rejected_sources_never_read_another_zone_or_allocate_an_index() {
    let tmp = tempfile::tempdir().unwrap();
    let mut kernel = Box::new(common::MockKernel::new());
    kernel.add_file("/docs/a.md", b"gentian", 100);
    let svc = SearchServiceImpl::builder(Arc::new(common::handle_for(&*kernel)))
        .manager(Arc::new(IndexManager::with_root(tmp.path().to_owned())))
        .embedder(Arc::new(MockEmbedder::with_dim(8)))
        .no_context_generator()
        .index_max_inflight(1)
        .build();
    assert_eq!(
        svc.index_file(Request::new(IndexFileRequest {
            path: "/docs/a.md".into(),
            zone_id: "other".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        kernel.io_counts().0,
        0,
        "wrong-zone bytes must never be read"
    );
    assert_eq!(
        svc.index_file(request("/docs/missing.md"))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        svc.index_file(request("/docs")).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        svc.index_file(request("relative.md"))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        svc.index_file(request("/docs/\0.md"))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        svc.index_documents(Request::new(IndexDocumentsRequest::default()))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert!(!tmp.path().join("root").exists());
    assert!(!tmp.path().join("other").exists());
    let accepted = svc
        .index_file(request("/docs/a.md"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        accepted.index_seq, 1,
        "rejections consume neither receipts nor capacity"
    );
}

#[tokio::test]
async fn storage_failure_is_an_rpc_error_and_releases_the_shared_slot() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("root"), b"blocks the FTS directory").unwrap();
    let mut kernel = Box::new(common::MockKernel::new());
    kernel.add_file("/docs/a.md", b"gentian", 100);
    let svc = SearchServiceImpl::builder(Arc::new(common::handle_for(&*kernel)))
        .manager(Arc::new(IndexManager::with_root(tmp.path().to_owned())))
        .embedder(Arc::new(MockEmbedder::with_dim(8)))
        .no_context_generator()
        .index_max_inflight(1)
        .build();
    for _ in 0..2 {
        assert_eq!(
            svc.index_file(request("/docs/a.md"))
                .await
                .unwrap_err()
                .code(),
            Code::Internal
        );
    }
    let stats = svc
        .stats(Request::new(StatsRequest {
            zone_id: "absent".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            stats.last_index_seq,
            stats.indexing_in_progress,
            stats.pending
        ),
        (0, 0, 0)
    );
}
