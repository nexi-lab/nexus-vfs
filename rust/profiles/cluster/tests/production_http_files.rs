//! Actual HTTP -> typed VFS gRPC -> Kernel/Raft file and authorization journeys.
#![cfg(feature = "http-api")]

mod common;

use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

async fn json_ok(request: reqwest::RequestBuilder) -> Value {
    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "HTTP {status}: {body}");
    serde_json::from_str(&body).unwrap()
}

async fn grant(client: &Client, base: &str, admin: &str, path: &str, method: Method) {
    json_ok(
        client
            .request(method, format!("{base}/v2/rebac/tuples"))
            .bearer_auth(admin)
            .json(&json!({
                "zone":"sharedzone", "object_type":"file", "object_id":path,
                "relation":"viewer", "subject_type":"user", "subject_id":"file-reader",
            })),
    )
    .await;
}

async fn content(client: &Client, base: &str, token: &str, path: &str) -> reqwest::Response {
    client
        .get(format!("{base}/v2/files"))
        .bearer_auth(token)
        .query(&[("path", path)])
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_bytes_metadata_rename_and_live_permissions_use_the_native_node() {
    const BUDGET: Duration = Duration::from_secs(120);
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let identity = tmp.path().join("identity");
    let plugins = tmp.path().join("plugins");
    let trust = tmp.path().join("trust");
    let models = tmp.path().join("models");
    for path in [&plugins, &trust, &models] {
        std::fs::create_dir_all(path).unwrap();
    }
    let (ca, ca_key) = nexus_raft::transport::generate_zone_ca("root").unwrap();
    let (_, hash) = nexus_raft::transport::generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let port = common::free_port_pair();
    let grpc = format!("127.0.0.1:{port}");
    let http = format!("127.0.0.1:{}", common::free_port());
    let base = format!("http://{http}");
    let env = [
        ("NEXUS_DATA_DIR", data.to_str().unwrap()),
        ("NEXUS_IDENTITY_DIR", identity.to_str().unwrap()),
        ("NEXUS_BIND_ADDR", grpc.as_str()),
        ("NEXUS_ADVERTISE_ADDR", grpc.as_str()),
        ("NEXUS_HTTP_ADDR", http.as_str()),
        ("NEXUS_REBAC_ENABLED", "true"),
        ("NEXUS_CLUSTER_INIT", "sharedzone"),
        ("NEXUS_CLUSTER_INIT_MOUNTS", "/=sharedzone"),
        ("NEXUS_API_KEY_SECRET", "native-http-files-test-only"),
        ("NEXUS_LOCAL_TRUSTED_KEYS_DIR", trust.to_str().unwrap()),
        ("NEXUS_SEARCH_MODEL_DIR", models.to_str().unwrap()),
        ("NEXUS_SEARCH_EMBED_API_URL", ""),
        ("DATABASE_URL", ""),
        ("NO_PROXY", "127.0.0.1,localhost"),
        ("RUST_LOG", common::LOG_FILTER),
    ];
    let args = ["--plugin-dir", plugins.to_str().unwrap()];
    let binary =
        std::env::var("NEXUS_HTTP_FILES_TEST_BINARY").unwrap_or_else(|_| common::bin().to_owned());
    let mut daemon = common::Daemon::spawn_binary(&binary, &args, &env);
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let (ok, output, error) = common::cli(
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
    assert!(ok, "test administrator mint failed: {error}");
    let admin = output.trim();
    assert!(admin.starts_with("sk-"));
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();

    let directory = format!("{base}/v2/directories");
    let mkdir = json_ok(client.post(&directory).bearer_auth(admin).json(&json!({
        "path":"/docs/nested", "parents":true,
    })))
    .await;
    assert_eq!(mkdir["hit"], true);
    json_ok(client.post(&directory).bearer_auth(admin).json(&json!({
        "path":"/docs/nested", "parents":true, "exist_ok":true,
    })))
    .await;
    let original = "/docs/nested/报告 & sample.bin";
    let renamed = "/docs/nested/renamed & 报告.bin";
    for payload in [Vec::new(), br#"{"error":"actual file content"}"#.to_vec()] {
        let receipt = json_ok(
            client
                .put(format!("{base}/v2/files"))
                .bearer_auth(admin)
                .query(&[("path", original)])
                .body(payload.clone()),
        )
        .await;
        assert_eq!(receipt["size"], payload.len());
        assert_eq!(
            content(&client, &base, admin, original)
                .await
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            payload
        );
    }
    let bytes: Vec<u8> = (0u8..=255).cycle().take(1024 * 1024).collect();
    let write = json_ok(
        client
            .put(format!("{base}/v2/files"))
            .bearer_auth(admin)
            .query(&[("path", original)])
            .header("content-type", "application/octet-stream")
            .body(bytes.clone()),
    )
    .await;
    assert_eq!(write["size"], bytes.len());
    assert!(write["gen"].as_u64().unwrap() > 0);
    let response = content(&client, &base, admin, original).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.bytes().await.unwrap().as_ref(), bytes);
    let before = json_ok(
        client
            .get(format!("{base}/v2/files/metadata"))
            .bearer_auth(admin)
            .query(&[("path", original)]),
    )
    .await;
    assert_eq!(before["path"], original);
    assert_eq!(before["size"], bytes.len());
    assert_eq!(before["is_directory"], false);
    let moved = json_ok(
        client
            .post(format!("{base}/v2/files/rename"))
            .bearer_auth(admin)
            .json(&json!({
                "path":original,"new_path":renamed,
            })),
    )
    .await;
    assert_eq!(moved["success"], true);
    assert_eq!(
        content(&client, &base, admin, original).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        content(&client, &base, admin, renamed)
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    let writer = json_ok(
        client
            .post(format!("{base}/v2/auth/keys"))
            .bearer_auth(admin)
            .json(&json!({
                "subject_type":"user", "subject_id":"file-writer", "zones":["sharedzone:rw"],
            })),
    )
    .await;
    let writer_key = writer["key"].as_str().unwrap();
    for path in [
        "/docs",
        "/docs/written.txt",
        "/docs/writer-renamed.txt",
        "/docs/writer-dir",
    ] {
        json_ok(
            client
                .post(format!("{base}/v2/rebac/tuples"))
                .bearer_auth(admin)
                .json(&json!({
                    "zone":"sharedzone", "object_type":"file", "object_id":path,
                    "relation":"writer", "subject_type":"user", "subject_id":"file-writer",
                })),
        )
        .await;
    }
    json_ok(
        client
            .put(format!("{base}/v2/files"))
            .bearer_auth(writer_key)
            .query(&[("path", "/docs/written.txt")])
            .body("written by a non-admin"),
    )
    .await;
    json_ok(
        client
            .post(&directory)
            .bearer_auth(writer_key)
            .json(&json!({"path":"/docs/writer-dir","parents":true})),
    )
    .await;
    json_ok(
        client
            .post(format!("{base}/v2/files/rename"))
            .bearer_auth(writer_key)
            .json(&json!({"path":"/docs/written.txt","new_path":"/docs/writer-renamed.txt"})),
    )
    .await;
    assert_eq!(
        content(&client, &base, admin, "/docs/writer-renamed.txt")
            .await
            .text()
            .await
            .unwrap(),
        "written by a non-admin"
    );
    json_ok(
        client
            .delete(format!("{base}/v2/files"))
            .bearer_auth(writer_key)
            .query(&[("path", "/docs/writer-dir")]),
    )
    .await;
    json_ok(
        client
            .delete(format!("{base}/v2/rebac/tuples"))
            .bearer_auth(admin)
            .json(&json!({
                "zone":"sharedzone", "object_type":"file", "object_id":"/docs/writer-renamed.txt",
                "relation":"writer", "subject_type":"user", "subject_id":"file-writer",
            })),
    )
    .await;
    assert_eq!(
        client
            .put(format!("{base}/v2/files"))
            .bearer_auth(writer_key)
            .query(&[("path", "/docs/writer-renamed.txt")])
            .body("after revocation")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    json_ok(
        client
            .put(format!("{base}/v2/files"))
            .bearer_auth(admin)
            .query(&[("path", "/docs/nested/private.txt")])
            .body("private bytes"),
    )
    .await;

    let reader = json_ok(
        client
            .post(format!("{base}/v2/auth/keys"))
            .bearer_auth(admin)
            .json(&json!({
                "subject_type":"user","subject_id":"file-reader","zones":["sharedzone:r"],
            })),
    )
    .await;
    let key = reader["key"].as_str().unwrap();
    for request in [
        client
            .post(format!("{base}/v2/files/rename"))
            .json(&json!({"path":renamed,"new_path":"/docs/stolen.bin"})),
        client
            .post(&directory)
            .json(&json!({"path":"/docs/forbidden","parents":true})),
    ] {
        assert_eq!(
            request.bearer_auth(key).send().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    for path in ["/docs", "/docs/nested", renamed] {
        grant(&client, &base, admin, path, Method::POST).await;
    }
    let listed = json_ok(
        client
            .get(&directory)
            .bearer_auth(key)
            .query(&[("path", "/docs"), ("recursive", "true")]),
    )
    .await;
    let entries = listed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{listed}");
    assert!(entries
        .iter()
        .any(|entry| entry["path"] == renamed && entry["size"] == bytes.len()));
    assert!(entries
        .iter()
        .any(|entry| entry["path"] == "/docs/nested" && entry["is_directory"] == true));
    assert_eq!(
        content(&client, &base, key, renamed).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        content(&client, &base, key, "/docs/nested/private.txt")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .put(format!("{base}/v2/files"))
            .bearer_auth(key)
            .query(&[("path", renamed)])
            .body("unauthorized overwrite")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .delete(format!("{base}/v2/files"))
            .bearer_auth(key)
            .query(&[("path", renamed)])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        content(&client, &base, admin, renamed)
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    assert_eq!(
        content(&client, &base, "sk-never-minted", renamed)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(format!("{base}/v2/files/metadata"))
            .bearer_auth(admin)
            .query(&[("path", renamed), ("is_admin", "true")])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    grant(&client, &base, admin, renamed, Method::DELETE).await;
    assert_eq!(
        content(&client, &base, key, renamed).await.status(),
        StatusCode::FORBIDDEN
    );
    grant(&client, &base, admin, renamed, Method::POST).await;
    assert_eq!(
        content(&client, &base, key, renamed).await.status(),
        StatusCode::OK
    );
    let second_reader = json_ok(client.post(format!("{base}/v2/auth/keys")).bearer_auth(admin).json(&json!({
        "subject_type":"user", "subject_id":"file-reader", "zones":["sharedzone:r"], "allow_existing":true,
    }))).await;
    let second_key = second_reader["key"].as_str().unwrap();
    json_ok(
        client
            .delete(format!(
                "{base}/v2/auth/keys/{}",
                reader["key_hash"].as_str().unwrap()
            ))
            .bearer_auth(admin),
    )
    .await;
    assert_eq!(
        content(&client, &base, key, renamed).await.status(),
        StatusCode::UNAUTHORIZED
    );

    drop(daemon);
    let mut restarted = common::Daemon::spawn_binary(&binary, &args, &env);
    restarted
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    assert_eq!(
        content(&client, &base, second_key, renamed).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        content(&client, &base, admin, renamed)
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    assert_eq!(
        content(&client, &base, key, renamed).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let nonrecursive = client
        .delete(format!("{base}/v2/files"))
        .bearer_auth(admin)
        .query(&[("path", "/docs"), ("recursive", "false")])
        .send()
        .await
        .unwrap();
    assert!(!nonrecursive.status().is_success());
    assert_eq!(
        content(&client, &base, admin, renamed).await.status(),
        StatusCode::OK
    );
    let deleted = json_ok(
        client
            .delete(format!("{base}/v2/files"))
            .bearer_auth(admin)
            .query(&[("path", "/docs"), ("recursive", "true")]),
    )
    .await;
    assert_eq!(deleted["deleted"], true);
    assert_eq!(
        content(&client, &base, admin, renamed).await.status(),
        StatusCode::NOT_FOUND
    );
    let absent = json_ok(
        client
            .delete(format!("{base}/v2/files"))
            .bearer_auth(admin)
            .query(&[("path", renamed)]),
    )
    .await;
    assert_eq!(absent["deleted"], false);
}
