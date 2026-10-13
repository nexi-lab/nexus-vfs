//! HTTP bearer -> node mTLS -> signed Search plugin -> live Raft authorization.
#![cfg(feature = "http-api")]

mod common;

use nexus_search_plugin::search_proto::{
    BatchQueryRequest, ListPathContextsRequest, PutPathContextRequest, QueryRequest,
};
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
    let database_path = tmp.path().join("configuration.db");
    let database_url = format!(
        "sqlite:///{}",
        database_path.to_string_lossy().replace('\\', "/")
    );
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&database_path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::query("CREATE TABLE path_contexts (id INTEGER PRIMARY KEY, zone_id VARCHAR(255) NOT NULL DEFAULT 'root', path_prefix VARCHAR(1024) NOT NULL, description TEXT NOT NULL, weight FLOAT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, UNIQUE(zone_id, path_prefix))")
        .execute(&pool).await.unwrap();
    // Existing database facts must work without a migration to another store.
    sqlx::query("INSERT INTO path_contexts (zone_id, path_prefix, description, weight, created_at, updated_at) VALUES ('legal', 'legal', 'existing configuration', 5.0, '2026-01-01 00:00:00.000000', '2026-01-01 00:00:00.000000')")
        .execute(&pool).await.unwrap();
    pool.close().await;
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
        ("DATABASE_URL", database_url.as_str()),
        ("NEXUS_PATH_CONTEXT_FRESHNESS_SECONDS", "3600"),
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
    for token in [None, Some(admin), Some("sk-never-minted")] {
        let request = client.get(format!("{base}/v2/status"));
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let status = json_ok(request).await;
        assert_eq!(status["status"], "ok");
        assert!(status["version"].is_string(), "{status}");
    }
    assert_eq!(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth("sk-never-minted")
            .json(&json!({"q":"widget"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
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
    let writer = json_ok(client.post(format!("{base}/v2/auth/keys")).bearer_auth(admin)
        .json(&json!({"subject_type":"user", "subject_id":"alice", "zones":["sharedzone:w", "legal:w"], "allow_existing":true}))).await;
    let writer = writer["key"].as_str().unwrap();

    let modified_at_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
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
                    &json!({"zone_id":zone, "documents":[{"path":path,"text":"widget document", "mtime_ms":modified_at_ms}]}),
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
    let health = json_ok(
        client
            .get(format!("{base}/v2/search/health"))
            .bearer_auth(admin),
    )
    .await;
    assert_eq!(health["status"], "degraded", "{health}");
    assert_eq!(health["fts_writer_faults"], 0);
    assert_eq!(health["fts_writer_unavailable"], 0);
    assert_eq!(health["dispatch_panics"], 0);
    assert!(
        health["last_verified_commit_age_ms"].is_number(),
        "{health}"
    );
    let located = json_ok(
        client
            .post(format!("{base}/v2/search/locate"))
            .bearer_auth(alice)
            .json(&json!({"path":"/docs/public.md", "zone_id":"sharedzone"})),
    )
    .await;
    assert_eq!(located["indexed"], true);
    assert_eq!(located["chunk_count"], 1);
    assert_eq!(located["mtime_ms"], modified_at_ms);
    assert_eq!(located["zone_id"], "sharedzone");
    assert_eq!(
        client
            .post(format!("{base}/v2/search/locate"))
            .bearer_auth(alice)
            .json(&json!({"path":"/docs/private.md", "zone_id":"sharedzone"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let directories_url = format!("{base}/v2/documents/directories");
    let modes_url = format!("{base}/v2/documents/indexing-modes");
    let directory = json!({"path":"/docs", "zone_id":"sharedzone"});
    for expected_added in [true, false] {
        let added = json_ok(
            client
                .post(&directories_url)
                .bearer_auth(admin)
                .json(&directory),
        )
        .await;
        assert_eq!(added, json!({"added":expected_added}));
    }
    let directories = json_ok(
        client
            .get(&directories_url)
            .bearer_auth(admin)
            .query(&[("zone_id", "sharedzone")]),
    )
    .await;
    let saved_directory = directories["directories"][0].clone();
    assert_eq!(saved_directory["path"], "/docs");
    assert_eq!(saved_directory["zone_id"], "sharedzone");
    assert!(saved_directory["added_at_ms"].as_i64().unwrap() > 0);
    assert!(directories.get("indexing_mode").is_none());
    let mut registrations = tokio::task::JoinSet::new();
    for number in 0..16 {
        let client = client.clone();
        let url = directories_url.clone();
        let token = admin.to_owned();
        registrations.spawn(async move {
            let result = json_ok(client.post(url).bearer_auth(token).json(&json!({
                "path":format!("/docs/concurrent-{number}"), "zone_id":"sharedzone",
            })))
            .await;
            assert_eq!(result, json!({"added":true}));
        });
    }
    while let Some(result) = registrations.join_next().await {
        result.unwrap();
    }
    let concurrent = json_ok(
        client
            .get(&directories_url)
            .bearer_auth(admin)
            .query(&[("zone_id", "sharedzone")]),
    )
    .await;
    let entries = concurrent["directories"].as_array().unwrap();
    assert_eq!(entries.len(), 17);
    for number in 0..16 {
        let path = format!("/docs/concurrent-{number}");
        assert!(
            entries.iter().any(|entry| entry["path"] == path),
            "{concurrent}"
        );
        assert_eq!(
            json_ok(
                client
                    .delete(&directories_url)
                    .bearer_auth(admin)
                    .query(&[("path", path.as_str()), ("zone_id", "sharedzone")])
            )
            .await,
            json!({"removed":true})
        );
    }
    assert_eq!(
        json_ok(
            client
                .put(&modes_url)
                .bearer_auth(admin)
                .json(&json!({"zone_id":"sharedzone", "mode":"sandbox"}))
        )
        .await,
        json!({})
    );
    let modes = json_ok(client.get(&modes_url).bearer_auth(admin)).await;
    assert!(modes["modes"]
        .as_array()
        .unwrap()
        .contains(&json!({"zone_id":"sharedzone", "mode":"sandbox"})));

    for (method, route, body) in [
        (Method::GET, "/v2/search/health", None),
        (Method::GET, "/v2/documents/stats?zone_id=sharedzone", None),
        (
            Method::POST,
            "/v2/documents/directories",
            Some(directory.clone()),
        ),
        (
            Method::DELETE,
            "/v2/documents/directories",
            Some(directory.clone()),
        ),
        (
            Method::GET,
            "/v2/documents/directories?zone_id=sharedzone",
            None,
        ),
        (
            Method::PUT,
            "/v2/documents/indexing-modes",
            Some(json!({"zone_id":"sharedzone", "mode":"off"})),
        ),
        (Method::GET, "/v2/documents/indexing-modes", None),
    ] {
        for (credential, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some("sk-never-minted"), StatusCode::UNAUTHORIZED),
            (Some(alice), StatusCode::FORBIDDEN),
            (Some(bob), StatusCode::FORBIDDEN),
            (Some(writer), StatusCode::FORBIDDEN),
        ] {
            let mut request = client.request(method.clone(), format!("{base}{route}"));
            if let Some(token) = credential {
                request = request.bearer_auth(token);
            }
            if let Some(body) = &body {
                request = if method == Method::DELETE {
                    request.query(body)
                } else {
                    request.json(body)
                };
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), expected, "{method} {route}");
        }
    }
    for (method, route, mut body) in [
        (
            Method::POST,
            "/v2/search/locate",
            json!({"path":"/docs/public.md"}),
        ),
        (Method::POST, "/v2/documents/directories", directory.clone()),
        (
            Method::DELETE,
            "/v2/documents/directories",
            directory.clone(),
        ),
        (
            Method::PUT,
            "/v2/documents/indexing-modes",
            json!({"mode":"on"}),
        ),
    ] {
        body["auth_token"] = json!(admin);
        let request = client
            .request(method.clone(), format!("{base}{route}"))
            .bearer_auth(admin);
        let request = if method == Method::DELETE {
            request.query(&body)
        } else {
            request.json(&body)
        };
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            if method == Method::DELETE {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            "{method} {route}"
        );
    }
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
    // Bob has an exact file grant, with no root-directory grant. Bounded
    // discovery authorizes those candidates; it cannot walk the directory.
    assert_eq!(
        client
            .get(format!("{base}/v2/search/glob?root_path=/docs&pattern=*"))
            .bearer_auth(bob)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    for (operation, pattern, field) in [("glob", "*.md", "paths"), ("grep", "widget", "matches")] {
        for files in [json!(["/docs/public.md", "/docs/private.md"]), json!([])] {
            let bounded = json_ok(
                client
                    .post(format!("{base}/v2/search/{operation}"))
                    .bearer_auth(bob)
                    .json(&json!({"root_path":"/docs", "pattern":pattern, "files":files, "max_results":1})),
            )
            .await;
            let hits = bounded[field].as_array().unwrap();
            assert_eq!(
                hits.len(),
                usize::from(!files.as_array().unwrap().is_empty())
            );
            if let Some(hit) = hits.first() {
                let path = if operation == "glob" {
                    hit
                } else {
                    &hit["path"]
                };
                assert_eq!(path, "/docs/private.md");
            }
        }
    }
    let mut legal_paths = vfs.readdir_names("/legal", "").await.unwrap();
    legal_paths.retain(|path| path.ends_with(".md"));
    legal_paths.sort();
    assert!(legal_paths.iter().any(|path| path == "/legal/contract.md"));
    assert_eq!(
        vfs.stat_zone("/legal/contract.md", "").await.as_deref(),
        Some("legal")
    );
    for (operation, pattern, field) in [("glob", "*.md", "paths"), ("grep", "widget", "matches")] {
        let legal = json_ok(
            client
                .post(format!("{base}/v2/search/{operation}"))
                .bearer_auth(alice)
                .json(
                    &json!({"root_path":"/legal", "zone_id":"legal", "pattern":pattern,
                          "files":["/legal/contract.md"]}),
                ),
        )
        .await;
        let hits = legal[field].as_array().unwrap();
        assert_eq!(hits.len(), 1, "{legal}");
        let path = if operation == "glob" {
            &hits[0]
        } else {
            &hits[0]["path"]
        };
        assert_eq!(path, "/legal/contract.md");
        assert_eq!(
            client
                .post(format!("{base}/v2/search/{operation}"))
                .bearer_auth(bob)
                .json(&json!({"root_path":"/legal", "pattern":pattern,
                          "files":["/legal/contract.md"]}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{base}/v2/search/{operation}"))
                .bearer_auth(admin)
                .json(&json!({"root_path":"/docs", "zone_id":"legal", "pattern":pattern}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let admin_legal = json_ok(
            client
                .post(format!("{base}/v2/search/{operation}"))
                .bearer_auth(admin)
                .json(&json!({"root_path":"/legal", "zone_id":"legal", "pattern":pattern})),
        )
        .await;
        let mut admin_paths: Vec<_> = admin_legal[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| {
                if operation == "glob" {
                    hit
                } else {
                    &hit["path"]
                }
            })
            .map(|path| path.as_str().unwrap().to_owned())
            .collect();
        admin_paths.sort();
        assert_eq!(admin_paths, legal_paths, "{admin_legal}");
    }
    grant(
        &client,
        &base,
        admin,
        ("sharedzone", "file", "/docs/private.md", "bob"),
        Method::DELETE,
    )
    .await;
    let revoked = json_ok(
        client
            .post(format!("{base}/v2/search/grep"))
            .bearer_auth(bob)
            .json(&json!({"root_path":"/docs", "pattern":"widget", "files":["/docs/private.md"]})),
    )
    .await;
    assert!(revoked["matches"].as_array().unwrap().is_empty());
    grant(
        &client,
        &base,
        admin,
        ("sharedzone", "file", "/docs/private.md", "bob"),
        Method::POST,
    )
    .await;
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

    let contexts_url = format!("{base}/v2/search/path-contexts");
    assert_eq!(client.put(&contexts_url).bearer_auth(alice)
        .json(&json!({"zone_id":"sharedzone", "path_prefix":"docs", "description":"documents", "weight":4.0}))
        .send().await.unwrap().status(), StatusCode::FORBIDDEN);
    assert_eq!(
        client
            .get(&contexts_url)
            .bearer_auth(narrow)
            .query(&[("zone_id", "legal")])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .put(&contexts_url)
            .bearer_auth(admin)
            .json(&json!({"path_prefix":"../escape", "description":"invalid"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let saved = json_ok(client.put(&contexts_url).bearer_auth(admin)
        .json(&json!({"zone_id":"sharedzone", "path_prefix":"/docs/", "description":"documents", "weight":4.0}))).await;
    assert_eq!(saved["path_prefix"], "docs");
    let scoped = json_ok(client.get(&contexts_url).bearer_auth(narrow)).await;
    assert_eq!(scoped["contexts"].as_array().unwrap().len(), 1, "{scoped}");
    assert_eq!(scoped["contexts"][0]["zone_id"], "sharedzone");
    let configured = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(alice)
            .json(&json!({"q":"widget", "limit":20})),
    )
    .await;
    let configured_hits = configured["results"].as_array().unwrap();
    assert_eq!(configured_hits.len(), 2, "{configured}");
    for hit in configured_hits {
        let expected = if hit["zone_id"] == "legal" { 5.0 } else { 4.0 };
        assert_eq!(hit["tier_boost"].as_f64(), Some(expected), "{hit}");
    }
    let mut grpc_search =
        common::search_plugin::mtls_client(port, &ca, &node_cert, &node_key).await;
    assert_eq!(
        grpc_search
            .put_path_context(PutPathContextRequest {
                zone_id: "sharedzone".into(),
                path_prefix: "docs".into(),
                description: "forbidden".into(),
                weight: Some(9.0),
                auth_token: narrow.into()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        grpc_search
            .list_path_contexts(ListPathContextsRequest {
                zone_id: Some("legal".into()),
                auth_token: narrow.into()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let grpc_hits = grpc_search
        .query(QueryRequest {
            q: "widget".into(),
            zone_id: "sharedzone".into(),
            auth_token: narrow.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grpc_hits.results.len(), 1);
    assert_eq!(grpc_hits.results[0].tier_boost, Some(4.0));
    let batch = grpc_search
        .batch_query(BatchQueryRequest {
            auth_token: alice.into(),
            queries: ["sharedzone", "legal"]
                .into_iter()
                .map(|zone| QueryRequest {
                    q: "widget".into(),
                    zone_id: zone.into(),
                    ..Default::default()
                })
                .collect(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(batch.responses.len(), 2);
    assert_eq!(batch.responses[0].results[0].tier_boost, Some(4.0));
    assert_eq!(batch.responses[1].results[0].tier_boost, Some(5.0));
    let batch_url = format!("{base}/v2/search/query/batch");
    let batch_body = json!({"queries": [
        {"q":"widget", "zone_id":"sharedzone"},
        {"q":"widget", "zone_id":"legal"},
        {"q":"", "zone_id":"sharedzone"}
    ]});
    assert_eq!(
        client
            .post(&batch_url)
            .bearer_auth(writer)
            .json(&batch_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(writer)
            .json(&json!({"q":"widget", "zone_id":"sharedzone"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let http_batch = json_ok(client.post(&batch_url).bearer_auth(alice).json(&batch_body)).await;
    assert_eq!(http_batch["responses"].as_array().unwrap().len(), 3);
    assert_eq!(
        http_batch["responses"][0]["results"][0]["path"],
        "/docs/public.md"
    );
    assert_eq!(http_batch["responses"][0]["results"][0]["tier_boost"], 4.0);
    assert_eq!(
        http_batch["responses"][1]["results"][0]["path"],
        "/legal/contract.md"
    );
    assert_eq!(http_batch["responses"][1]["results"][0]["tier_boost"], 5.0);
    assert!(http_batch["responses"][2]["error"].is_string());
    assert_eq!(
        client
            .post(&batch_url)
            .bearer_auth(narrow)
            .json(&batch_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .post(&batch_url)
            .bearer_auth("sk-unknown")
            .json(&batch_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(&batch_url)
            .json(&batch_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let oversized = BatchQueryRequest {
        auth_token: alice.into(),
        queries: vec![QueryRequest::default(); nexus_search_common::query::MAX_BATCH_QUERIES + 1],
    };
    assert_eq!(
        grpc_search.batch_query(oversized).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    // A weightless child exempts itself from a weighted parent, even with a
    // warm candidate cache and a one-hour configuration refresh window.
    json_ok(client.put(&contexts_url).bearer_auth(admin).json(
        &json!({"zone_id":"sharedzone", "path_prefix":"docs/public.md", "description":"plain"}),
    ))
    .await;
    let plain = grpc_search
        .query(QueryRequest {
            q: "widget".into(),
            zone_id: "sharedzone".into(),
            auth_token: narrow.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(plain.results[0].tier_boost, Some(1.0));
    let ranked = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(admin)
            .json(&json!({"q":"widget", "zone_id":"sharedzone", "limit":1})),
    )
    .await;
    assert_eq!(ranked["results"][0]["path"], "/docs/private.md", "{ranked}");
    json_ok(client.put(&contexts_url).bearer_auth(admin)
        .json(&json!({"zone_id":"sharedzone", "path_prefix":"docs/public.md", "description":"promoted", "weight":9.0}))).await;
    let promoted = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(admin)
            .json(&json!({"q":"widget", "zone_id":"sharedzone", "limit":1})),
    )
    .await;
    assert_eq!(
        promoted["results"][0]["path"], "/docs/public.md",
        "{promoted}"
    );
    json_ok(client.delete(&contexts_url).bearer_auth(admin).query(&[
        ("zone_id", "sharedzone"),
        ("path_prefix", "/docs/public.md/"),
    ]))
    .await;
    let boosted = grpc_search
        .query(QueryRequest {
            q: "widget".into(),
            zone_id: "sharedzone".into(),
            auth_token: narrow.into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(boosted.results[0].tier_boost, Some(4.0));
    assert_eq!(
        client
            .delete(&contexts_url)
            .bearer_auth(admin)
            .query(&[("zone_id", "sharedzone"), ("path_prefix", "docs/public.md")])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    drop(grpc_search);
    // Real signed plugin and Raft-backed file grants on both the local leg and
    // the mTLS delegation leg. Tuning must still preserve the caller's scope.
    let options = json!({
        "q":"widget", "query_type":"keyword", "limit":20,
        "alpha":0.4, "fusion_method":"rrf_weighted", "rrf_k":20,
        "chunks_per_page":1, "expand":"macro", "recency_mode":"on",
        "recency_weight":0.5, "recency_half_life_days":7.0,
        "path_prefix_boosts":{"/docs/":2.0,"/legal/":3.0},
        "path_filters":["/docs","/legal"]
    });
    let tuned = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(alice)
            .json(&options),
    )
    .await;
    assert!(tuned["error"].is_null(), "{tuned}");
    let hits = tuned["results"].as_array().unwrap();
    assert_eq!(hits.len(), 2, "{tuned}");
    for hit in hits {
        let expected_boost = match hit["path"].as_str().unwrap() {
            "/docs/public.md" => 2.0,
            "/legal/contract.md" => 3.0,
            path => panic!("unexpected authorized hit {path}"),
        };
        assert_eq!(hit["tier_boost"].as_f64(), Some(expected_boost), "{hit}");
        assert!(hit["recency_boost"].as_f64().unwrap() >= 1.0, "{hit}");
    }
    let mut narrowed = options.clone();
    narrowed["path_filters"] = json!(["/legal"]);
    let filtered = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(alice)
            .json(&narrowed),
    )
    .await;
    assert!(filtered["error"].is_null(), "{filtered}");
    assert_eq!(
        filtered["results"].as_array().unwrap().len(),
        1,
        "{filtered}"
    );
    assert_eq!(filtered["results"][0]["path"], "/legal/contract.md");
    let ceiling = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(narrow)
            .json(&options),
    )
    .await;
    assert_eq!(ceiling["results"].as_array().unwrap().len(), 1, "{ceiling}");
    assert_eq!(ceiling["results"][0]["path"], "/docs/public.md");
    grant(
        &client,
        &base,
        admin,
        ("sharedzone", "file", "/docs/public.md", "alice"),
        Method::DELETE,
    )
    .await;
    assert!(query(&client, &base, alice, "sharedzone").await.is_empty());
    let revoked_batch = json_ok(client.post(&batch_url).bearer_auth(alice).json(&batch_body)).await;
    assert!(revoked_batch["responses"][0]["results"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        revoked_batch["responses"][1]["results"][0]["path"],
        "/legal/contract.md"
    );
    assert_eq!(
        query(&client, &base, alice, "").await,
        ["/legal/contract.md"]
    );
    let revoked = json_ok(
        client
            .post(format!("{base}/v2/search/query"))
            .bearer_auth(alice)
            .json(&options),
    )
    .await;
    assert!(revoked["error"].is_null(), "{revoked}");
    assert_eq!(revoked["results"].as_array().unwrap().len(), 1, "{revoked}");
    assert_eq!(revoked["results"][0]["path"], "/legal/contract.md");

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
    let directories = json_ok(
        client
            .get(&directories_url)
            .bearer_auth(admin)
            .query(&[("zone_id", "sharedzone")]),
    )
    .await;
    assert_eq!(directories["directories"], json!([saved_directory]));
    let modes = json_ok(client.get(&modes_url).bearer_auth(admin)).await;
    assert!(modes["modes"]
        .as_array()
        .unwrap()
        .contains(&json!({"zone_id":"sharedzone", "mode":"sandbox"})));
    for expected_removed in [true, false] {
        let removed = json_ok(
            client
                .delete(&directories_url)
                .bearer_auth(admin)
                .query(&directory),
        )
        .await;
        assert_eq!(removed, json!({"removed":expected_removed}));
    }
    let directories = json_ok(
        client
            .get(&directories_url)
            .bearer_auth(admin)
            .query(&[("zone_id", "sharedzone")]),
    )
    .await;
    assert_eq!(directories["directories"], json!([]));
    assert_eq!(
        client
            .post(format!("{base}/v2/search/locate"))
            .bearer_auth(alice)
            .json(&json!({"path":"/docs/public.md", "zone_id":"sharedzone"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let persisted = json_ok(client.get(&contexts_url).bearer_auth(admin)).await;
    assert_eq!(persisted["contexts"].as_array().unwrap().len(), 2);
    assert_eq!(persisted["contexts"][1]["created_at"], saved["created_at"]);
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
