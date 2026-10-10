//! Real certificate-agent RPCs preserve absent corpora and reload committed facts.
mod common;

use common::search_plugin::{mtls_client as client, signed_plugin};
use nexus_raft::transport::{generate_agent_cert, generate_join_token, generate_zone_ca};
use nexus_search_plugin::search_proto::{
    DocumentInput, IndexDocumentsRequest, QueryRequest, QueryType,
};
use std::time::Duration;
use tonic::Code;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_reads_preserve_storage_and_committed_index_survives_restart() {
    use nexus_search_plugin::search_proto::{
        BatchQueryRequest, ListIndexedDirectoriesRequest, ListZoneIndexingModesRequest,
        LocateRequest, ParkedListRequest, StatsRequest,
    };
    let tmp = tempfile::tempdir().unwrap();
    let plugins = signed_plugin(tmp.path());
    let data = tmp.path().join("data");
    let identity = tmp.path().join("identity");
    let trust = tmp.path().join("trust");
    let models = tmp.path().join("empty-models");
    std::fs::create_dir_all(&models).unwrap();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (_, hash) = generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let (agent_cert, agent_key) =
        generate_agent_cert("search-read-contract", &ca, &ca_key).unwrap();
    let node_cert = std::fs::read(data.join("tls/node.pem")).unwrap();
    let node_key = std::fs::read(data.join("tls/node-key.pem")).unwrap();
    let port = common::free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let args = [
        "--bind-addr",
        &address,
        "--plugin-dir",
        plugins.to_str().unwrap(),
    ];
    let env = [
        ("NEXUS_DATA_DIR", data.to_str().unwrap()),
        ("NEXUS_IDENTITY_DIR", identity.to_str().unwrap()),
        ("NEXUS_ADVERTISE_ADDR", &address),
        ("NEXUS_CLUSTER_INIT", "sharedzone"),
        ("NEXUS_CLUSTER_INIT_MOUNTS", "/docs=sharedzone"),
        ("NEXUS_API_KEY_SECRET", "search-read-contract-test-only"),
        ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
        ("NEXUS_SEARCH_MODEL_DIR", models.to_str().unwrap()),
        ("NEXUS_SEARCH_QUERY_EXPANSION", "false"),
        ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING", "false"),
        ("NEXUS_SEARCH_PEER_FANOUT_ZONES", ""),
        ("NEXUS_SEARCH_EMBED_API_URL", ""),
        ("RUST_LOG", common::LOG_FILTER),
    ];
    let mut daemon = common::Daemon::spawn(&args, &env);
    daemon
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .unwrap();
    let mut node = client(port, &ca, &node_cert, &node_key).await;
    let mut agent = client(port, &ca, &agent_cert, &agent_key).await;
    let mut vfs = common::Vfs::connect_mtls(port, &ca, &node_cert, &node_key, BUDGET).await;
    vfs.write_file("/docs/read-contract.md", b"gentian", "")
        .await
        .unwrap();
    let root = data.join("plugins/search");
    assert!(!root.exists());
    for i in 0..20 {
        let mut request = query("gentian");
        request.zone_id = format!("unindexed-{i}");
        let response = agent.query(request).await.unwrap().into_inner();
        assert!(
            response.error.is_none() && response.results.is_empty(),
            "{response:?}"
        );
    }
    let mut first = query("gentian");
    first.zone_id = "unindexed-first".into();
    let mut second = first.clone();
    second.zone_id = "unindexed-second".into();
    assert!(agent
        .batch_query(BatchQueryRequest {
            queries: vec![first, second],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .responses
        .iter()
        .all(|r| r.error.is_none() && r.results.is_empty()));
    assert!(
        !agent
            .locate(LocateRequest {
                zone_id: "sharedzone".into(),
                path: "/docs/read-contract.md".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .indexed
    );
    let before = node
        .stats(StatsRequest {
            zone_id: "sharedzone".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((before.fts_doc_count, before.last_index_seq), (0, 0));
    assert!(node
        .parked_list(ParkedListRequest {
            zone_id: "unindexed".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .entries
        .is_empty());
    assert!(node
        .list_indexed_directories(ListIndexedDirectoriesRequest {
            zone_id: "unindexed".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .directories
        .is_empty());
    assert!(node
        .list_zone_indexing_modes(ListZoneIndexingModesRequest::default())
        .await
        .unwrap()
        .into_inner()
        .modes
        .is_empty());
    for zone in [
        "../../agent-query-probe",
        "/tmp/agent-query-probe",
        "a/b",
        "a\\b",
        ".",
        "..",
        "C:escape",
        ".. ",
        "zone.",
        "zone ",
    ] {
        let mut request = query("gentian");
        request.zone_id = zone.into();
        assert_eq!(
            agent.query(request.clone()).await.unwrap_err().code(),
            Code::InvalidArgument
        );
        request.auth_token = "sk-never-minted".into();
        assert_eq!(
            agent.query(request).await.unwrap_err().code(),
            Code::Unauthenticated
        );
    }
    let good_doc = DocumentInput {
        path: "/docs/read-contract.md".into(),
        text: "gentian".into(),
        ..Default::default()
    };
    let bad_batch = IndexDocumentsRequest {
        zone_id: "sharedzone".into(),
        documents: vec![
            good_doc.clone(),
            DocumentInput {
                zone_id: "../../agent-query-probe".into(),
                ..good_doc.clone()
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        node.index_documents(bad_batch).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert!(
        !root.exists(),
        "reads and rejected batches must leave storage absent"
    );
    assert!(!data.join("agent-query-probe").exists());
    let response = node
        .index_documents(IndexDocumentsRequest {
            zone_id: "sharedzone".into(),
            documents: vec![good_doc],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.indexed_count, 1);
    let sequence = response.index_seq;
    assert!(sequence > 0);
    let hits = agent.query(query("gentian")).await.unwrap().into_inner();
    assert!(hits.error.is_none());
    assert_eq!(hits.results[0].path, "/docs/read-contract.md");
    drop(vfs);
    drop(agent);
    drop(node);
    drop(daemon);

    let mut restarted = common::Daemon::spawn(&args, &env);
    restarted
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .unwrap();
    let mut agent = client(port, &ca, &agent_cert, &agent_key).await;
    let hits = agent.query(query("gentian")).await.unwrap().into_inner();
    assert!(hits.error.is_none(), "{hits:?}\n{}", restarted.drain());
    assert_eq!(hits.results[0].path, "/docs/read-contract.md");
    let mut node = client(port, &ca, &node_cert, &node_key).await;
    let stats = node
        .stats(StatsRequest {
            zone_id: "sharedzone".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((stats.fts_path_count, stats.last_index_seq), (1, sequence));
    let mut request = query("gentian");
    request.zone_id = "still-unindexed".into();
    assert!(agent
        .query(request)
        .await
        .unwrap()
        .into_inner()
        .results
        .is_empty());
    assert!(!root.join("still-unindexed").exists());
}
