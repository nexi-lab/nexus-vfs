//! Real daemon, signed search cdylib, and mTLS clients: the plugin must receive
//! metadata and host-verified peer provenance, and return exact gRPC refusals.

mod common;

use common::search_plugin::{mtls_client as client, sign_plugin, signed_plugin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nexus_raft::transport::{generate_agent_cert, generate_join_token, generate_zone_ca};
use nexus_search_common::{SearchDelegation, DELEGATION_METADATA_KEY};
use nexus_search_plugin::internal_call::INTERNAL_CALL_HEADER;
use nexus_search_plugin::search_proto::{
    DocumentInput, IndexDocumentsRequest, QueryRequest, QueryType,
};
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const BUDGET: Duration = Duration::from_secs(120);

fn query(q: &str) -> QueryRequest {
    QueryRequest {
        q: q.into(),
        zone_id: "sharedzone".into(),
        query_type: QueryType::Keyword as i32,
        limit: 10,
        ..Default::default()
    }
}

fn stamp<T>(body: T, delegation: &SearchDelegation) -> Request<T> {
    let mut request = Request::new(body);
    request.metadata_mut().insert_bin(
        DELEGATION_METADATA_KEY,
        MetadataValue::from_bytes(&serde_json::to_vec(delegation).unwrap()),
    );
    request
}

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_and_delegation_survive_the_real_daemon_and_signed_cdylib() {
    let tmp = tempfile::tempdir().unwrap();
    let plugins = signed_plugin(tmp.path());
    let data = tmp.path().join("data");
    let id = tmp.path().join("identity");
    let trust = tmp.path().join("trust");
    let models = tmp.path().join("empty-models");
    std::fs::create_dir_all(&models).unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (_, hash) = generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let (agent_cert, agent_key) = generate_agent_cert("search-client", &ca, &ca_key).unwrap();
    let node_cert = std::fs::read(data.join("tls/node.pem")).unwrap();
    let node_key = std::fs::read(data.join("tls/node-key.pem")).unwrap();

    // A counted local LLM endpoint proves that the internal-call marker bypasses
    // expansion. Positive calls on both sides of the refusal cases bind the test.
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let app = axum::Router::new().route(
        "/chat",
        axum::routing::post(move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::Json(
                    serde_json::json!({"choices":[{"message":{"content":"{\"variants\":[]}"}}]}),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let llm_url = format!("http://{}/chat", listener.local_addr().unwrap());
    let _llm = Task(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap()
    }));
    let port = common::free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let mut daemon = common::Daemon::spawn(
        &[
            "--bind-addr",
            &address,
            "--plugin-dir",
            plugins.to_str().unwrap(),
        ],
        &[
            ("NEXUS_DATA_DIR", data.to_str().unwrap()),
            ("NEXUS_IDENTITY_DIR", id.to_str().unwrap()),
            ("NEXUS_ADVERTISE_ADDR", &address),
            ("NEXUS_CLUSTER_INIT", "sharedzone"),
            ("NEXUS_CLUSTER_INIT_MOUNTS", "/docs=sharedzone"),
            ("NEXUS_API_KEY_SECRET", "search-context-e2e-only"),
            ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
            ("NEXUS_SEARCH_MODEL_DIR", models.to_str().unwrap()),
            ("NEXUS_SEARCH_QUERY_EXPANSION", "true"),
            ("NEXUS_SEARCH_QUERY_EXPANSION_ENDPOINT", &llm_url),
            ("NEXUS_SEARCH_QUERY_EXPANSION_MODEL", "test-model"),
            ("NEXUS_SEARCH_QUERY_EXPANSION_API_KEY", "test-key"),
            // The constructor also uses blocking HTTP at index time. With no
            // embedder it initializes but sends no contextual-generation calls.
            ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING", "true"),
            ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING_ENDPOINT", &llm_url),
            ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING_MODEL", "test-model"),
            ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING_API_KEY", "test-key"),
            ("NEXUS_SEARCH_PEER_FANOUT_ZONES", ""),
            ("NEXUS_SEARCH_EMBED_API_URL", ""),
            ("NO_PROXY", "127.0.0.1,localhost"),
            ("RUST_LOG", common::LOG_FILTER),
        ],
    );
    daemon
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .unwrap();
    let mut node = client(port, &ca, &node_cert, &node_key).await;
    let mut agent = client(port, &ca, &agent_cert, &agent_key).await;
    let mut vfs = common::Vfs::connect_mtls(port, &ca, &node_cert, &node_key, BUDGET).await;
    vfs.write_file("/docs/needle.md", b"widget external internal after", "")
        .await
        .unwrap();
    let batch = IndexDocumentsRequest {
        zone_id: "sharedzone".into(),
        documents: vec![DocumentInput {
            path: "/docs/needle.md".into(),
            text: "widget external internal after".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let indexed = node
        .index_documents(batch.clone())
        .await
        .unwrap_or_else(|error| panic!("{error}\n{}", daemon.drain()))
        .into_inner();
    assert!(indexed.error.is_none(), "{indexed:?}\n{}", daemon.drain());
    assert_eq!(indexed.indexed_count, 1);
    let error = agent.index_documents(batch.clone()).await.unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    let response = node
        .query(query("widget external"))
        .await
        .unwrap_or_else(|error| panic!("{error}\n{}", daemon.drain()))
        .into_inner();
    assert!(
        response
            .results
            .iter()
            .any(|hit| hit.path == "/docs/needle.md"),
        "{response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "ordinary query must expand"
    );

    let delegation = SearchDelegation::new_from_now(
        "sd_e2e",
        "source",
        ["sharedzone".to_owned()],
        ("user".into(), "alice".into()),
    );
    let mut request = stamp(query("widget internal"), &delegation);
    request
        .metadata_mut()
        .insert(INTERNAL_CALL_HEADER, MetadataValue::from_static("1"));
    let response = node.query(request).await.unwrap().into_inner();
    assert!(response
        .results
        .iter()
        .any(|hit| hit.path == "/docs/needle.md"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "forwarded request must not expand again"
    );

    let mut forged = stamp(query("widget"), &delegation);
    forged.metadata_mut().insert(
        "x-nexus-is-cluster-node",
        MetadataValue::from_static("true"),
    );
    let err = agent.query(forged).await.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(err.message().contains("verified cluster node"), "{err}");

    let mut expired = delegation.clone();
    expired.created_at_unix_ms -= 60_000;
    for _ in 0..2 {
        let err = node
            .query(stamp(query("widget"), &expired))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        assert!(err.message().contains("expired"), "{err}");
    }
    let mut other_zone = query("widget");
    other_zone.zone_id = "finance%/\u{96ea}".into();
    let err = node
        .query(stamp(other_zone, &delegation))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(err.message().contains("finance%/\u{96ea}"), "{err}");
    let err = node
        .index_documents(stamp(batch, &delegation))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(err.message().contains("IndexDocuments"), "{err}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "refused requests must not reach expansion"
    );

    let response = node
        .query(query("widget after"))
        .await
        .unwrap()
        .into_inner();
    assert!(response
        .results
        .iter()
        .any(|hit| hit.path == "/docs/needle.md"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "ordinary calls keep expanding after refusals"
    );

    // This fixture leaves the Kernel's file policy open. Certificate agents
    // must have the same read access through VFS and Search; their lack of
    // zone tenancy does not impose a separate Search permission policy.
    let mut agent_vfs = common::Vfs::connect_mtls(port, &ca, &agent_cert, &agent_key, BUDGET).await;
    assert_eq!(
        agent_vfs.read_file("/docs/needle.md", "").await.unwrap(),
        b"widget external internal after"
    );
    let response = agent
        .query(query("widget external"))
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(
        response
            .results
            .iter()
            .map(|hit| hit.path.as_str())
            .collect::<Vec<_>>(),
        ["/docs/needle.md"]
    );
    let mut invalid = query("widget");
    invalid.auth_token = "sk-never-minted".into();
    assert_eq!(
        agent.query(invalid).await.unwrap_err().code(),
        Code::Unauthenticated
    );
}

#[tokio::test]
async fn advertised_grpc_without_dispatch_is_refused_before_plugin_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let plugins = tmp.path().join("plugins");
    let trust = tmp.path().join("trust");
    let data = tmp.path().join("data");
    let identity = tmp.path().join("identity");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::create_dir_all(&trust).unwrap();
    let library = plugins.join(format!(
        "{}incomplete{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let source = tmp.path().join("incomplete.rs");
    std::fs::write(&source, format!(r#"
use std::ffi::{{c_char, c_void}};
#[no_mangle] pub extern "C" fn nexus_plugin_api_version() -> u32 {{ {} }}
#[no_mangle] pub extern "C" fn nexus_plugin_kind() -> u32 {{ 1 }}
#[no_mangle] pub extern "C" fn nexus_plugin_name() -> *const c_char {{ c"incomplete".as_ptr() }}
#[no_mangle] pub extern "C" fn nexus_plugin_grpc_services() -> *const c_char {{ c"[\"test.Incomplete\"]".as_ptr() }}
#[no_mangle] pub extern "C" fn nexus_service_create(_: *const c_void) -> *mut c_void {{ std::process::abort() }}
#[no_mangle] pub extern "C" fn nexus_service_destroy(_: *mut c_void) {{}}
"#, nexus_plugin_abi::PLUGIN_API_VERSION)).unwrap();
    let build = std::process::Command::new("rustc")
        .args(["--crate-type", "cdylib", "--edition", "2021"])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    sign_plugin(&library, &trust);
    let address = format!("127.0.0.1:{}", common::free_port_pair());
    let mut daemon = common::Daemon::spawn(
        &[
            "--bind-addr",
            &address,
            "--plugin-dir",
            plugins.to_str().unwrap(),
        ],
        &[
            ("NEXUS_DATA_DIR", data.to_str().unwrap()),
            ("NEXUS_IDENTITY_DIR", identity.to_str().unwrap()),
            ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
        ],
    );
    let log = daemon
        .wait_exit(BUDGET)
        .await
        .expect("incomplete plugin must refuse daemon startup");
    assert!(log.contains("required gRPC dispatch symbol"), "{log}");
}
