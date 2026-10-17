//! Browser identity uses the daemon's live credential policy and Raft store.

#![cfg(feature = "http-api")]

mod common;

use std::time::Duration;

use nexus_http_api::handlers::identity::IdentityResponse;
use reqwest::{Client, StatusCode};
use serde_json::json;

const BUDGET: Duration = Duration::from_secs(90);
const BROWSER_ORIGIN: &str = "https://console.example.test";

fn http_client() -> Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::ORIGIN, BROWSER_ORIGIN.parse().unwrap());
    Client::builder()
        .default_headers(headers)
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}

async fn identity(client: &Client, url: &str, key: &str) -> IdentityResponse {
    let response = client.get(url).bearer_auth(key).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        BROWSER_ORIGIN
    );
    let bytes = response.bytes().await.unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(key));
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_identity_follows_native_grants_revocation_and_restart() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let credentials = root.path().join("identity");
    let (ca, ca_key) = nexus_raft::transport::generate_zone_ca("root").unwrap();
    let (_, hash) = nexus_raft::transport::generate_join_token(&ca).unwrap();
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    let grpc = format!("127.0.0.1:{}", common::free_port_pair());
    let http = format!("127.0.0.1:{}", common::free_port());
    let base = format!("http://{http}");
    let url = format!("{base}/v2/auth/whoami");
    let env = [
        ("NEXUS_DATA_DIR", data.to_str().unwrap()),
        ("NEXUS_IDENTITY_DIR", credentials.to_str().unwrap()),
        ("NEXUS_BIND_ADDR", grpc.as_str()),
        ("NEXUS_ADVERTISE_ADDR", grpc.as_str()),
        ("NEXUS_HTTP_ADDR", http.as_str()),
        ("NEXUS_HTTP_ALLOWED_ORIGINS", BROWSER_ORIGIN),
        ("NEXUS_API_KEY_SECRET", "synthetic-browser-identity-secret"),
        ("NEXUS_REBAC_ENABLED", "true"),
        ("NEXUS_CLUSTER_INIT", "sharedzone"),
        ("RUST_LOG", common::LOG_FILTER),
    ];
    let mut daemon = common::Daemon::spawn(&[], &env);
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let (ok, admin, error) = common::cli(
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
    assert!(ok, "administrator fixture mint failed: {error}");
    let admin = admin.trim();
    let client = http_client();

    let preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .send()
        .await
        .unwrap();
    assert!(preflight.status().is_success());
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        BROWSER_ORIGIN
    );
    assert_eq!(
        preflight.headers()["access-control-allow-credentials"],
        "true"
    );

    let untrusted = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "https://unconfigured.example.test")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "authorization")
        .send()
        .await
        .unwrap();
    assert!(!untrusted
        .headers()
        .contains_key("access-control-allow-origin"));

    for token in [None, Some("sk-unknown-browser-key")] {
        let request = client.get(&url);
        let request = match token {
            Some(key) => request.bearer_auth(key),
            None => request,
        };
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            BROWSER_ORIGIN
        );
    }
    assert_eq!(
        client
            .get(&url)
            .query(&[("auth_token", admin)])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST,
    );

    let operator = identity(&client, &url, admin).await;
    assert_eq!(operator.subject_type, "user");
    assert_eq!(operator.subject_id, "operator");
    assert_eq!(operator.user_id, "operator");
    assert_eq!(operator.agent_id, None);
    assert!(operator.is_admin);

    let mut issued = Vec::new();
    for (kind, name, zones) in [
        ("user", "alice", vec!["sharedzone:r"]),
        ("service", "reporter", vec!["sharedzone:r", "legal:r"]),
    ] {
        let response = client
            .post(format!("{base}/v2/auth/keys"))
            .bearer_auth(admin)
            .json(&json!({"subject_type":kind,"subject_id":name,"zones":zones}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let minted: serde_json::Value = response.json().await.unwrap();
        let key = minted["key"].as_str().unwrap().to_owned();
        let resolved = identity(&client, &url, &key).await;
        assert_eq!(resolved.subject_type, kind);
        assert_eq!(resolved.subject_id, name);
        assert_eq!(resolved.user_id, name);
        assert_eq!(resolved.agent_id, None);
        assert!(!resolved.is_admin);
        assert_eq!(
            resolved.zone_id,
            if kind == "user" { "sharedzone" } else { "root" }
        );
        assert_eq!(resolved.zone_perms.len(), zones.len());
        assert!(resolved
            .zone_perms
            .contains(&("sharedzone".into(), "r".into())));
        let forged_url = format!("{url}?subject_id=operator&is_admin=true&zone_id=root");
        assert_eq!(identity(&client, &forged_url, &key).await, resolved);
        issued.push((
            key,
            minted["key_hash"].as_str().unwrap().to_owned(),
            resolved,
        ));
    }

    // The lookup above warmed the real provider cache. Native apply observers
    // must revoke that exact identity without a TTL wait or HTTP-side cache.
    let revoked = client
        .delete(format!("{base}/v2/auth/keys/{}", issued[0].1))
        .bearer_auth(admin)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&issued[0].0)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(identity(&client, &url, &issued[1].0).await, issued[1].2);
    drop(client);
    drop(daemon);

    let mut daemon = common::Daemon::spawn(&[], &env);
    daemon
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let client = http_client();
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&issued[0].0)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(identity(&client, &url, &issued[1].0).await, issued[1].2);
    drop(daemon);

    let mut invalid_env = env.to_vec();
    invalid_env.push((
        "NEXUS_HTTP_ALLOWED_ORIGINS",
        "https://console.example.test,invalid",
    ));
    let mut invalid = common::Daemon::spawn(&[], &invalid_env);
    assert!(
        invalid.wait_exit(BUDGET).await.is_some(),
        "invalid browser configuration did not stop boot"
    );
    assert!(invalid
        .drain_settled()
        .contains("NEXUS_HTTP_ALLOWED_ORIGINS must contain"));
}
