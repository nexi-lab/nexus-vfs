//! Real HTTP and mTLS gRPC clients share signed-plugin index admission.
#![cfg(feature = "http-api")]
mod common;

use axum::{extract::State, routing::post, Json, Router};
use nexus_search_plugin::search_proto::{
    DocumentInput, IndexDocumentsRequest, IndexFileRequest, IndexRequest, NotifyFileChangeRequest,
    RefreshRequest,
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Notify;

const BUDGET: Duration = Duration::from_secs(120);

#[derive(Default)]
struct Provider {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}

async fn embed(State(provider): State<Arc<Provider>>, Json(body): Json<Value>) -> Json<Value> {
    if provider.calls.fetch_add(1, Ordering::SeqCst) == 0 {
        provider.entered.notify_one();
        tokio::time::timeout(Duration::from_secs(60), provider.release.notified())
            .await
            .unwrap();
    }
    let data: Vec<_> = body["input"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, _)| json!({"index":index, "embedding":[1.0,0.0,0.0,0.0]}))
        .collect();
    Json(json!({"data":data}))
}

async fn ok(request: reqwest::RequestBuilder) -> Value {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "{status}: {body}");
    serde_json::from_str(&body).unwrap()
}

fn batch(path: &str, token: &str) -> IndexDocumentsRequest {
    IndexDocumentsRequest {
        zone_id: "sharedzone".into(),
        auth_token: token.into(),
        documents: vec![DocumentInput {
            path: path.into(),
            text: "gentian".into(),
            ..Default::default()
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overload_and_cancellation_preserve_authority_capacity_and_committed_facts() {
    let provider = Arc::new(Provider::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let embedding_url = format!("http://{}/v1/embeddings", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/v1/embeddings", post(embed))
        .with_state(provider.clone());
    let provider_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let tmp = tempfile::tempdir().unwrap();
    let plugins = common::search_plugin::signed_plugin(tmp.path());
    let data = tmp.path().join("data");
    let identity = tmp.path().join("identity");
    let trust = tmp.path().join("trust");
    let (ca, ca_key) = nexus_raft::transport::generate_zone_ca("root").unwrap();
    let (_, hash) = nexus_raft::transport::generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let cert = std::fs::read(data.join("tls/node.pem")).unwrap();
    let key = std::fs::read(data.join("tls/node-key.pem")).unwrap();
    let port = common::free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let http = format!("127.0.0.1:{}", common::free_port());
    let base = format!("http://{http}");
    let env = [
        ("NEXUS_DATA_DIR", data.to_str().unwrap()),
        ("NEXUS_IDENTITY_DIR", identity.to_str().unwrap()),
        ("NEXUS_BIND_ADDR", address.as_str()),
        ("NEXUS_ADVERTISE_ADDR", address.as_str()),
        ("NEXUS_HTTP_ADDR", http.as_str()),
        ("NEXUS_REBAC_ENABLED", "true"),
        ("NEXUS_CLUSTER_INIT", "sharedzone"),
        ("NEXUS_CLUSTER_INIT_MOUNTS", "/docs=sharedzone"),
        ("NEXUS_API_KEY_SECRET", "index-admission-test-only"),
        ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
        ("NEXUS_SEARCH_INDEX_MAX_INFLIGHT", "1"),
        ("NEXUS_SEARCH_EMBED_API_URL", embedding_url.as_str()),
        ("NEXUS_SEARCH_EMBED_MODEL", "test-admission"),
        ("NEXUS_SEARCH_EMBED_DIM", "4"),
        ("NEXUS_SEARCH_EMBED_API_KEY", ""),
        ("NEXUS_SEARCH_EMBED_TIMEOUT_SECONDS", "60"),
        ("NEXUS_SEARCH_QUERY_EXPANSION", "false"),
        ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING", "false"),
        ("NEXUS_SEARCH_PEER_FANOUT_ZONES", ""),
        ("NO_PROXY", "127.0.0.1,localhost"),
        ("RUST_LOG", common::LOG_FILTER),
    ];
    let args = ["--plugin-dir", plugins.to_str().unwrap()];
    let mut daemon = common::Daemon::spawn(&args, &env);
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let (success, output, error) = common::cli(
        &env,
        &[
            "auth",
            "mint",
            "--subject-type",
            "user",
            "--subject-id",
            "operator",
            "--admin",
        ],
    );
    assert!(success, "admin mint failed: {error}");
    let admin = output.trim();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let reader = ok(client
        .post(format!("{base}/v2/auth/keys"))
        .bearer_auth(admin)
        .json(&json!({"subject_type":"user", "subject_id":"reader", "zones":["sharedzone:r"]})))
    .await;
    let reader = reader["key"].as_str().unwrap();
    let mut rpc = common::search_plugin::mtls_client(port, &ca, &cert, &key).await;
    let mut vfs = common::Vfs::connect_mtls(port, &ca, &cert, &key, BUDGET).await;
    for path in [
        "/docs/accepted.md",
        "/docs/rejected.md",
        "/docs/recovered.md",
    ] {
        vfs.write_file(path, b"gentian", "").await.unwrap();
    }
    let batch_url = format!("{base}/v2/documents/batch");
    let file_url = format!("{base}/v2/documents/file");
    let stats_url = format!("{base}/v2/documents/stats");
    let initial = ok(client
        .get(&stats_url)
        .bearer_auth(admin)
        .query(&[("zone_id", "sharedzone")]))
    .await;
    // The administrator has no tenant zone; the actual /docs mount owns the
    // input and the host must select sharedzone from that VFS route.
    let submitted = client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/accepted.md"}));
    let mut pending = tokio::spawn(async move { submitted.send().await });
    tokio::select! {
        entered = tokio::time::timeout(Duration::from_secs(30), provider.entered.notified()) => {
            assert!(entered.is_ok(), "accepted file never reached the embedding provider");
        }
        result = &mut pending => {
            let response = result.unwrap().unwrap();
            panic!("file indexing returned before embedding: {} {}\n{}", response.status(), response.text().await.unwrap(), daemon.drain());
        }
    }
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    // Cancellation of the HTTP caller leaves the plugin's accepted work alive.
    for (url, body) in [
        (
            &batch_url,
            json!({"zone_id":"sharedzone", "documents":[{"path":"/docs/rejected.md", "text":"gentian"}]}),
        ),
        (
            &format!("{base}/v2/documents/index"),
            json!({"zone_id":"sharedzone", "root_path":"/docs"}),
        ),
        (
            &format!("{base}/v2/documents/refresh"),
            json!({"zone_id":"sharedzone", "root_path":"/docs"}),
        ),
        (&file_url, json!({"path":"/docs/rejected.md"})),
    ] {
        let denied = client
            .post(url)
            .bearer_auth(reader)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(denied.headers().get("retry-after").is_none());
        let overloaded = client
            .post(url)
            .bearer_auth(admin)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(overloaded.headers()["retry-after"], "5");
        assert!(overloaded.json::<Value>().await.unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("backlog"));
    }
    for credential in [reader, admin] {
        let response = client
            .delete(&file_url)
            .bearer_auth(credential)
            .query(&[("path", "/docs/accepted.md")])
            .send()
            .await
            .unwrap();
        if credential == reader {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(response.headers().get("retry-after").is_none());
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers()["retry-after"], "5");
        }
    }
    assert_eq!(
        rpc.index_file(IndexFileRequest {
            path: "/docs/rejected.md".into(),
            auth_token: reader.into(),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        rpc.index_file(IndexFileRequest {
            path: "/docs/rejected.md".into(),
            auth_token: admin.into(),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(
        rpc.notify_file_change(NotifyFileChangeRequest {
            path: "/docs/accepted.md".into(),
            change_type: "delete".into(),
            zone_id: "sharedzone".into(),
            auth_token: admin.into(),
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::ResourceExhausted
    );
    let notification = rpc
        .notify_file_change(NotifyFileChangeRequest {
            path: "/docs/accepted.md".into(),
            change_type: "update".into(),
            zone_id: "sharedzone".into(),
            auth_token: admin.into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (notification.status.as_str(), notification.index_seq),
        ("skipped", 0)
    );
    assert_eq!(
        rpc.index_documents(batch("/docs/rejected.md", reader))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        rpc.index_documents(batch("/docs/rejected.md", admin))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(
        rpc.index(IndexRequest {
            root_path: "/docs".into(),
            zone_id: "sharedzone".into(),
            auth_token: admin.into(),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(
        rpc.refresh(RefreshRequest {
            root_path: "/docs".into(),
            zone_id: "sharedzone".into(),
            auth_token: admin.into(),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::ResourceExhausted
    );
    let busy = ok(client
        .get(&stats_url)
        .bearer_auth(admin)
        .query(&[("zone_id", "sharedzone")]))
    .await;
    assert_eq!(
        (
            busy["indexing_in_progress"].as_u64(),
            busy["pending"].as_u64()
        ),
        (Some(1), Some(1))
    );
    assert_eq!(busy["last_index_seq"], initial["last_index_seq"]);
    let health = ok(client
        .get(format!("{base}/v2/search/health"))
        .bearer_auth(admin))
    .await;
    assert_eq!(health["dispatch_panics"], 0);
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "rejected work reached the embedder"
    );
    provider.release.notify_one();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let stats = ok(client
                .get(&stats_url)
                .bearer_auth(admin)
                .query(&[("zone_id", "sharedzone")]))
            .await;
            if stats["indexing_in_progress"] == 0 {
                assert_eq!(stats["pending"], 0);
                assert_eq!(stats["last_index_seq"], 1);
                assert_eq!(stats["fts_path_count"], 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let recovered = rpc
        .index_documents(batch("/docs/recovered.md", admin))
        .await
        .unwrap()
        .into_inner();
    assert!(recovered.error.is_none(), "{recovered:?}");
    assert_eq!((recovered.indexed_count, recovered.index_seq), (1, 2));
    drop(rpc);
    drop(vfs);
    drop(daemon);
    let mut restarted = common::Daemon::spawn(&args, &env);
    restarted
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let stats = ok(client
        .get(&stats_url)
        .bearer_auth(admin)
        .query(&[("zone_id", "sharedzone")]))
    .await;
    assert_eq!(
        (
            stats["indexing_in_progress"].as_u64(),
            stats["pending"].as_u64(),
            stats["last_index_seq"].as_u64()
        ),
        (Some(0), Some(0), Some(2))
    );
    // A fresh service also initializes the remote client safely when its first
    // embedding operation is a query. Both durable indexes must serve the
    // cancelled-but-committed file and exclude every rejected document.
    for query_type in ["semantic", "keyword"] {
        let results = ok(client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(admin)
            .json(&json!({"q":"gentian", "zone_id":"sharedzone", "query_type":query_type})))
        .await;
        assert!(results["error"].is_null(), "{query_type}: {results}");
        let mut paths: Vec<_> = results["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["path"].as_str().unwrap())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            ["/docs/accepted.md", "/docs/recovered.md"],
            "{query_type}"
        );
    }
    let after_restart = ok(client.post(&batch_url).bearer_auth(admin)
        .json(&json!({"zone_id":"sharedzone", "documents":[{"path":"/docs/recovered.md", "text":"gentian"}]}))).await;
    assert_eq!(after_restart["index_seq"], 3);
    let mut rpc = common::search_plugin::mtls_client(port, &ca, &cert, &key).await;
    let mut vfs = common::Vfs::connect_mtls(port, &ca, &cert, &key, BUDGET).await;
    assert_eq!(
        rpc.index_file(IndexFileRequest {
            path: "/docs/accepted.md".into(),
            zone_id: "root".into(),
            auth_token: admin.into(),
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );
    let file = rpc
        .index_file(IndexFileRequest {
            path: "/docs/accepted.md".into(),
            auth_token: admin.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (file.status.as_str(), file.index_seq, file.zone_id.as_str()),
        ("indexed", 4, "sharedzone")
    );
    let deleted = ok(client
        .delete(&file_url)
        .bearer_auth(admin)
        .query(&[("path", "/docs/accepted.md")]))
    .await;
    assert_eq!(deleted["status"], "deleted");
    assert_eq!(deleted["index_seq"], 5);
    let located = ok(client
        .post(format!("{base}/v2/search/locate"))
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/accepted.md", "zone_id":"sharedzone"})))
    .await;
    assert_eq!(located["indexed"], false);
    let restored = ok(client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/accepted.md"})))
    .await;
    assert_eq!(restored["index_seq"], 6);
    let missing = client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/missing.md"}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    vfs.write_file("/docs/binary.md", &[0xff, 0xfe], "")
        .await
        .unwrap();
    let binary = client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/binary.md"}))
        .send()
        .await
        .unwrap();
    assert_eq!(binary.status(), StatusCode::CONFLICT);
    let binary: Value = binary.json().await.unwrap();
    assert_eq!(binary["reason"], "non_text");
    assert_eq!(binary["index_seq"], 0);
    vfs.write_file("/docs/accepted.md", b" \n\t", "")
        .await
        .unwrap();
    let empty = client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/accepted.md"}))
        .send()
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::CONFLICT);
    let empty: Value = empty.json().await.unwrap();
    assert_eq!(empty["reason"], "empty");
    assert_eq!(empty["index_seq"], 7);
    let located = ok(client
        .post(format!("{base}/v2/search/locate"))
        .bearer_auth(admin)
        .json(&json!({"path":"/docs/accepted.md", "zone_id":"sharedzone"})))
    .await;
    assert_eq!(located["indexed"], false);
    let escaped = if cfg!(windows) {
        "/docs/space & 虹.md"
    } else {
        "/docs/space & quote\" 虹.md"
    };
    vfs.write_file(escaped, b"gentian escaped path", "")
        .await
        .unwrap();
    let indexed = ok(client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":escaped})))
    .await;
    assert_eq!(indexed["index_seq"], 8);
    assert_eq!(indexed["zone_id"], "sharedzone");
    let stats = ok(client
        .get(&stats_url)
        .bearer_auth(admin)
        .query(&[("zone_id", "sharedzone")]))
    .await;
    assert_eq!(stats["last_index_seq"], 8);
    assert_eq!(stats["indexing_in_progress"], 0);
    assert_eq!(stats["pending"], 0);
    let located = ok(client
        .post(format!("{base}/v2/search/locate"))
        .bearer_auth(admin)
        .json(&json!({"path":escaped, "zone_id":"sharedzone"})))
    .await;
    assert_eq!(located["indexed"], true);
    let stream = "/docs/stream-facts/transcript";
    vfs.create_stream(stream, "").await.unwrap();
    let text = "primrose durable stream paragraph.\n\n".repeat(600);
    vfs.stream_write(stream, text.as_bytes(), "").await.unwrap();
    let indexed = ok(client
        .post(&file_url)
        .bearer_auth(admin)
        .json(&json!({"path":stream})))
    .await;
    assert_eq!(indexed["status"], "indexed");
    let located = ok(client
        .post(format!("{base}/v2/search/locate"))
        .bearer_auth(admin)
        .json(&json!({"path":stream,"zone_id":"sharedzone"})))
    .await;
    let initial_chunks = located["chunk_count"].as_u64().unwrap();
    assert!(initial_chunks > 1);
    vfs.stream_write(stream, b"freesia appended tail\n", "")
        .await
        .unwrap();
    let rebuilt = ok(client
        .post(format!("{base}/v2/documents/index"))
        .bearer_auth(admin)
        .json(&json!({"root_path":"/docs/stream-facts","zone_id":"sharedzone"})))
    .await;
    assert_eq!(rebuilt["indexed_count"], 1);
    let located = ok(client
        .post(format!("{base}/v2/search/locate"))
        .bearer_auth(admin)
        .json(&json!({"path":stream,"zone_id":"sharedzone"})))
    .await;
    assert!(
        located["chunk_count"].as_u64().unwrap() <= initial_chunks + 1,
        "directory indexing duplicated the stream's old chunks: {located}"
    );
    provider_task.abort();
}
