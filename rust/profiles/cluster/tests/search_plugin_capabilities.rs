//! Runtime capability discovery through the real daemon, signed plugin and mTLS.

mod common;

use common::search_plugin::signed_plugin;
use nexus_raft::transport::proto::{
    zone_api_service_client::ZoneApiServiceClient, GetSearchCapabilitiesRequest,
};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};
use nexus_search_plugin::search_proto::{
    search_service_client::SearchServiceClient, HealthRequest,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::Code;

const ZONE: &str = "sharedzone";
const BUDGET: Duration = Duration::from_secs(120);

async fn channel(port: u16, ca: &[u8], cert: &[u8], key: &[u8]) -> Channel {
    Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(cert, key))
                .domain_name("localhost"),
        )
        .unwrap()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .connect()
        .await
        .unwrap()
}

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capabilities_follow_the_loaded_plugin_without_disk_or_embedding_io() {
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
    let cert = std::fs::read(data.join("tls/node.pem")).unwrap();
    let key = std::fs::read(data.join("tls/node-key.pem")).unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let app = axum::Router::new().route(
        "/embeddings",
        axum::routing::post(move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({"data":[]}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/embeddings", listener.local_addr().unwrap());
    let _endpoint = Task(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap()
    }));
    let port = common::free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let stale_path = data.join(ZONE).join("search_caps.json");
    let stale = br#"{"device_tier":"phone","search_modes":["graph"],"embedding_model":"stale","embedding_dimensions":999,"has_graph":true}"#;

    // Reuse durable zone data, changing only the currently loaded service and
    // its configuration. Capability queries must not create any index or model.
    for (loaded, model, dimension) in [
        (false, "caps-one", "17"),
        (true, "caps-one", "17"),
        (true, "caps-two", "19"),
        (true, "caps-invalid", "invalid"),
        (true, "caps-overflow", "2147483648"),
    ] {
        let mut args = vec!["--bind-addr", address.as_str()];
        if loaded {
            args.extend(["--plugin-dir", plugins.to_str().unwrap()]);
        }
        let mut daemon = common::Daemon::spawn(
            &args,
            &[
                ("NEXUS_DATA_DIR", data.to_str().unwrap()),
                ("NEXUS_IDENTITY_DIR", identity.to_str().unwrap()),
                ("NEXUS_ADVERTISE_ADDR", &address),
                ("NEXUS_CLUSTER_INIT", ZONE),
                ("NEXUS_CLUSTER_INIT_MOUNTS", "/docs=sharedzone"),
                ("NEXUS_API_KEY_SECRET", "capabilities-e2e-only"),
                ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
                ("NEXUS_SEARCH_MODEL_DIR", models.to_str().unwrap()),
                ("NEXUS_SEARCH_EMBED_API_URL", &url),
                ("NEXUS_SEARCH_EMBED_MODEL", model),
                ("NEXUS_SEARCH_EMBED_DIM", dimension),
                ("NEXUS_SEARCH_EMBED_TAG", ""),
                ("NEXUS_SEARCH_PEER_FANOUT_ZONES", ""),
                ("NO_PROXY", "127.0.0.1,localhost"),
                ("RUST_LOG", common::LOG_FILTER),
            ],
        );
        daemon
            .wait_for_log("Static topology applied", BUDGET)
            .await
            .unwrap();
        std::fs::write(&stale_path, stale).unwrap();
        let conn = channel(port, &ca, &cert, &key).await;
        let mut peer = ZoneApiServiceClient::new(conn.clone());
        assert_eq!(
            peer.get_search_capabilities(GetSearchCapabilitiesRequest {
                zone_id: "unknown".into()
            })
            .await
            .unwrap_err()
            .code(),
            Code::NotFound
        );
        let result = peer
            .get_search_capabilities(GetSearchCapabilitiesRequest {
                zone_id: ZONE.into(),
            })
            .await;
        if !loaded {
            assert_eq!(result.unwrap_err().code(), Code::Unimplemented);
        } else if dimension == "2147483648" {
            assert_eq!(result.unwrap_err().code(), Code::FailedPrecondition);
        } else {
            let caps = result
                .unwrap_or_else(|error| panic!("{error}\n{}", daemon.drain()))
                .into_inner();
            assert_eq!(caps.zone_id, ZONE);
            assert_eq!(caps.device_tier, "server");
            assert!(!caps.has_graph);
            if dimension == "invalid" {
                assert_eq!(caps.search_modes, ["keyword"]);
                assert!(caps.embedding_model.is_empty());
                assert_eq!(caps.embedding_dimensions, 0);
            } else {
                assert_eq!(caps.search_modes, ["keyword", "semantic", "hybrid"]);
                assert_eq!(caps.embedding_model, format!("api-{model}-{dimension}"));
                assert_eq!(caps.embedding_dimensions.to_string(), dimension);
            }
            let health = SearchServiceClient::new(conn)
                .health(HealthRequest::default())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                health.status, "degraded",
                "capability discovery must not initialise the embedder"
            );
        }
        assert_eq!(std::fs::read(&stale_path).unwrap(), stale);
        assert!(!data.join("root/search_caps.json").exists());
        assert!(!data.join("plugins/search").exists());
        assert_eq!(std::fs::read_dir(&models).unwrap().count(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(daemon);
    }
}
