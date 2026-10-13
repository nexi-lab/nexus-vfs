//! Index capacity belongs to accepted work, including cancelled RPCs.
mod common;

use nexus_search_plugin::embedder::{EmbedError, Embedder, MockEmbedder};
use nexus_search_plugin::index_manager::IndexManager;
use nexus_search_plugin::search_proto::{search_service_server::SearchService, *};
use nexus_search_plugin::service::SearchServiceImpl;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tonic::{Code, Request};

#[derive(Default)]
struct EmbeddingGate {
    entered: Notify,
    released: Mutex<bool>,
    ready: Condvar,
}

impl EmbeddingGate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.ready.notify_all();
    }
}

struct ReleaseOnDrop(Arc<EmbeddingGate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl Embedder for EmbeddingGate {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.entered.notify_one();
        let (released, _) = self
            .ready
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(30),
                |r| !*r,
            )
            .unwrap();
        if !*released {
            return Err(EmbedError::Runtime("embedding gate timed out".into()));
        }
        MockEmbedder::with_dim(8).embed_batch(texts)
    }

    fn dim(&self) -> usize {
        8
    }
    fn tag(&self) -> &str {
        "mock"
    }
}

fn batch(path: &str) -> IndexDocumentsRequest {
    IndexDocumentsRequest {
        documents: vec![DocumentInput {
            path: path.into(),
            text: "gentian".into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_batch_retains_capacity_pending_and_commit_visibility() {
    let tmp = tempfile::tempdir().unwrap();
    let gate = Arc::new(EmbeddingGate::default());
    let _release = ReleaseOnDrop(Arc::clone(&gate));
    let svc = Arc::new(
        SearchServiceImpl::builder(Arc::new(common::poison_handle()))
            .manager(Arc::new(IndexManager::with_root(tmp.path().to_owned())))
            .embedder(gate.clone())
            .no_context_generator()
            .index_max_inflight(1)
            .build(),
    );
    let task_svc = Arc::clone(&svc);
    let task = tokio::spawn(async move {
        task_svc
            .index_documents(Request::new(batch("/accepted.md")))
            .await
    });
    tokio::time::timeout(Duration::from_secs(30), gate.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let before = svc
        .stats(Request::new(StatsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            before.indexing_in_progress,
            before.pending,
            before.last_index_seq
        ),
        (1, 1, 0)
    );
    // All three entry points share one gate. The poison VFS proves rejected
    // walks cannot reach a syscall, and the batch cannot commit a valid prefix.
    assert_eq!(
        svc.index(Request::new(IndexRequest::default()))
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        svc.refresh(Request::new(RefreshRequest::default()))
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        svc.index_documents(Request::new(batch("/rejected.md")))
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    let overloaded = svc
        .stats(Request::new(StatsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            overloaded.indexing_in_progress,
            overloaded.pending,
            overloaded.last_index_seq
        ),
        (1, 1, 0)
    );
    gate.release();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let stats = svc
                .stats(Request::new(StatsRequest::default()))
                .await
                .unwrap()
                .into_inner();
            if stats.indexing_in_progress == 0 {
                assert_eq!((stats.pending, stats.last_index_seq), (0, 1));
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
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
    assert_eq!(
        response
            .results
            .iter()
            .map(|r| r.path.as_str())
            .collect::<Vec<_>>(),
        ["/accepted.md"]
    );
    let recovered = svc
        .index_documents(Request::new(batch("/recovered.md")))
        .await
        .unwrap()
        .into_inner();
    assert!(recovered.error.is_none(), "{recovered:?}");
    assert_eq!((recovered.indexed_count, recovered.index_seq), (1, 2));
}

#[tokio::test]
async fn rejected_input_and_storage_failure_leave_capacity_reusable() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("root"), b"blocks index directory creation").unwrap();
    let svc = SearchServiceImpl::builder(Arc::new(common::poison_handle()))
        .manager(Arc::new(IndexManager::with_root(tmp.path().to_owned())))
        .embedder(Arc::new(MockEmbedder::with_dim(8)))
        .no_context_generator()
        .index_max_inflight(1)
        .build();
    let mut invalid = batch("/bad.md");
    invalid.zone_id = "../escape".into();
    assert_eq!(
        svc.index_documents(Request::new(invalid))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    for _ in 0..2 {
        let failed = svc
            .index_documents(Request::new(batch("/retry.md")))
            .await
            .unwrap()
            .into_inner();
        assert!(
            failed.error.is_some(),
            "storage failure must be explicit: {failed:?}"
        );
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
                stats.indexing_in_progress,
                stats.pending,
                stats.last_index_seq
            ),
            (0, 0, 0)
        );
    }
}
