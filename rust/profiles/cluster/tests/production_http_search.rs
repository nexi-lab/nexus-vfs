//! HTTP bearer -> node mTLS -> signed Search plugin -> live Raft authorization.
#![cfg(feature = "http-api")]

mod common;

use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

const BUDGET: Duration = Duration::from_secs(120);

async fn json_ok(request: reqwest::RequestBuilder) -> Value {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "HTTP {status}: {body}");
    serde_json::from_str(&body).unwrap()
}

async fn query(client: &Client, base: &str, token: &str, zone: &str) -> Vec<String> {
    let body = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(token)
            .json(&json!({"q":"widget", "zone_id":zone, "limit":20})),
    )
    .await;
    assert!(body["error"].is_null(), "{body}");
    let mut paths: Vec<_> = body["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| hit["path"].as_str().unwrap().to_owned())
        .collect();
    paths.sort();
    paths
}

async fn grant(
    client: &Client,
    base: &str,
    token: &str,
    (zone, kind, object, subject): (&str, &str, &str, &str),
    method: Method,
) {
    json_ok(
        client
            .request(method, format!("{base}/v2/rebac/tuples"))
            .bearer_auth(token)
            .json(&json!({
                "zone":zone, "object_type":kind, "object_id":object,
                "relation":"viewer", "subject_type":"user", "subject_id":subject,
            })),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_grants_filter_http_search_and_survive_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let plugins = common::search_plugin::signed_plugin(tmp.path());
    let data = tmp.path().join("data");
    let id = tmp.path().join("identity");
    let trust = tmp.path().join("trust");
    let models = tmp.path().join("empty-models");
    std::fs::create_dir_all(&models).unwrap();
    let (ca, ca_key) = nexus_raft::transport::generate_zone_ca("root").unwrap();
    let (_, hash) = nexus_raft::transport::generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let node_cert = std::fs::read(data.join("tls/node.pem")).unwrap();
    let node_key = std::fs::read(data.join("tls/node-key.pem")).unwrap();
    let port = common::free_port_pair();
    let grpc = format!("127.0.0.1:{port}");
    let http = format!("127.0.0.1:{}", common::free_port());
    let base = format!("http://{http}");
    // Exercise the remote delegation leg against a real mTLS listener too.
    let remote = format!("legal=https://{grpc}");
    let env = [
        ("NEXUS_DATA_DIR", data.to_str().unwrap()),
        ("NEXUS_IDENTITY_DIR", id.to_str().unwrap()),
        ("NEXUS_BIND_ADDR", grpc.as_str()),
        ("NEXUS_ADVERTISE_ADDR", grpc.as_str()),
        ("NEXUS_HTTP_ADDR", http.as_str()),
        ("NEXUS_REBAC_ENABLED", "true"),
        ("NEXUS_CLUSTER_INIT", "sharedzone,legal"),
        ("NEXUS_CLUSTER_INIT_MOUNTS", "/docs=sharedzone,/legal=legal"),
        ("NEXUS_API_KEY_SECRET", "production-http-test-only"),
        ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
        ("NEXUS_SEARCH_REMOTE_ZONE_TARGETS", remote.as_str()),
        ("NEXUS_SEARCH_MODEL_DIR", models.to_str().unwrap()),
        ("NEXUS_SEARCH_QUERY_EXPANSION", "false"),
        ("NEXUS_SEARCH_CONTEXTUAL_CHUNKING", "false"),
        ("NEXUS_SEARCH_PEER_FANOUT_ZONES", ""),
        ("NEXUS_SEARCH_EMBED_API_URL", ""),
        ("NO_PROXY", "127.0.0.1,localhost"),
        ("RUST_LOG", common::LOG_FILTER),
    ];
    let args = ["--plugin-dir", plugins.to_str().unwrap()];
    let mut daemon = common::Daemon::spawn(&args, &env);
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let mut vfs = common::Vfs::connect_mtls(port, &ca, &node_cert, &node_key, BUDGET).await;
    let (ok, out, err) = common::cli(
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
    assert!(ok, "admin mint failed: {err}");
    let admin = out.trim();
    assert!(admin.starts_with("sk-"));
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let alice = json_ok(client.post(format!("{base}/v2/auth/keys")).bearer_auth(admin)
        .json(&json!({"subject_type":"user", "subject_id":"alice", "zones":["sharedzone:r", "legal:r"]}))).await;
    let alice = alice["key"].as_str().unwrap();
    let bob = json_ok(
        client
            .post(format!("{base}/v2/auth/keys"))
            .bearer_auth(admin)
            .json(&json!({"subject_type":"user", "subject_id":"bob", "zones":["sharedzone:r"]})),
    )
    .await;
    let bob = bob["key"].as_str().unwrap();
    let narrow = json_ok(client.post(format!("{base}/v2/auth/keys")).bearer_auth(admin)
        .json(&json!({"subject_type":"user", "subject_id":"alice", "zones":["sharedzone:r"], "allow_existing":true}))).await;
    let narrow = narrow["key"].as_str().unwrap();

    for (zone, path) in [
        ("sharedzone", "/docs/public.md"),
        ("sharedzone", "/docs/private.md"),
        ("legal", "/legal/contract.md"),
    ] {
        vfs.write_file(path, b"widget document", "").await.unwrap();
        let result = json_ok(
            client
                .post(format!("{base}/v2/documents/batch"))
                .bearer_auth(admin)
                .json(
                    &json!({"zone_id":zone, "documents":[{"path":path,"text":"widget document"}]}),
                ),
        )
        .await;
        assert_eq!(result["indexed_count"], 1, "{result}");
    }
    assert!(query(&client, &base, alice, "sharedzone").await.is_empty());
    for (zone, path, subject) in [
        ("sharedzone", "/docs", "alice"),
        ("sharedzone", "/docs/public.md", "alice"),
        ("sharedzone", "/docs/private.md", "bob"),
        ("legal", "/legal/contract.md", "alice"),
    ] {
        grant(
            &client,
            &base,
            admin,
            (zone, "file", path, subject),
            Method::POST,
        )
        .await;
    }
    assert_eq!(
        query(&client, &base, alice, "sharedzone").await,
        ["/docs/public.md"]
    );
    assert_eq!(
        query(&client, &base, bob, "sharedzone").await,
        ["/docs/private.md"]
    );
    let globs = json_ok(
        client
            .get(format!(
                "{base}/v2/search/glob?root_path=/docs&pattern=*.md"
            ))
            .bearer_auth(alice),
    )
    .await;
    assert_eq!(globs["paths"], json!(["/docs/public.md"]));
    let greps = json_ok(
        client
            .get(format!(
                "{base}/v2/search/grep?root_path=/docs&pattern=widget"
            ))
            .bearer_auth(alice),
    )
    .await;
    assert_eq!(greps["matches"].as_array().unwrap().len(), 1, "{greps}");
    assert_eq!(greps["matches"][0]["path"], "/docs/public.md");
    assert_eq!(
        client
            .get(format!("{base}/v2/documents/stats"))
            .bearer_auth(alice)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .post(format!("{base}/v2/documents/batch"))
            .bearer_auth(alice)
            .json(&json!({"zone_id":"sharedzone","documents":[]}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(alice)
            .json(&json!({"q":"widget","auth_token":admin}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        client
            .get(format!(
                "{base}/v2/search/glob?pattern=*&auth_token={admin}"
            ))
            .bearer_auth(alice)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(format!("{base}/v2/search/query"))
            .header("Authorization", format!("Bearer {alice}"))
            .header("Authorization", format!("Bearer {admin}"))
            .json(&json!({"q":"widget"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(format!("{base}/v2/search/query"))
            .json(&json!({"q":"widget"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    for zone in ["sharedzone", "legal"] {
        grant(
            &client,
            &base,
            admin,
            (zone, "zone", zone, "alice"),
            Method::POST,
        )
        .await;
    }
    assert_eq!(
        query(&client, &base, alice, "").await,
        ["/docs/public.md", "/legal/contract.md"]
    );
    assert_eq!(query(&client, &base, narrow, "").await, ["/docs/public.md"]);
    grant(
        &client,
        &base,
        admin,
        ("sharedzone", "file", "/docs/public.md", "alice"),
        Method::DELETE,
    )
    .await;
    assert!(query(&client, &base, alice, "sharedzone").await.is_empty());
    assert_eq!(
        query(&client, &base, alice, "").await,
        ["/legal/contract.md"]
    );

    drop(vfs);
    drop(client);
    drop(daemon);
    let mut daemon = common::Daemon::spawn(&args, &env);
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    // Persisted grants AND revocations remain effective after process restart.
    assert!(query(&client, &base, alice, "sharedzone").await.is_empty());
    assert_eq!(
        query(&client, &base, bob, "sharedzone").await,
        ["/docs/private.md"]
    );
    grant(
        &client,
        &base,
        admin,
        ("sharedzone", "file", "/docs/public.md", "alice"),
        Method::POST,
    )
    .await;
    assert_eq!(
        query(&client, &base, alice, "sharedzone").await,
        ["/docs/public.md"]
    );
}
