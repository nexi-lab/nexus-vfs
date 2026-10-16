//! Browser preflight and readable failures over the actual HTTP listener.

use nexus_http_api::{browser::BrowserOrigins, router, AppState};
use reqwest::{Client, Method, StatusCode};

async fn start(origins: BrowserOrigins) -> (String, tokio::task::JoinHandle<()>) {
    let mut state = AppState::for_tests("http://127.0.0.1:1");
    state.browser_origins = origins;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    (base, task)
}

#[tokio::test]
async fn configured_origins_can_preflight_and_read_status_and_errors() {
    let (base, task) = start(
        "https://console.example.test,http://localhost:5173"
            .parse()
            .unwrap(),
    )
    .await;
    let client = Client::builder().no_proxy().build().unwrap();
    for origin in ["https://console.example.test", "http://localhost:5173"] {
        let response = client
            .request(Method::OPTIONS, format!("{base}/v2/auth/keys/a-key-hash"))
            .header("origin", origin)
            .header("access-control-request-method", "DELETE")
            .header(
                "access-control-request-headers",
                "authorization,x-nexus-min-revision",
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["access-control-allow-origin"], origin);
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
        assert!(response.headers()["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .contains("DELETE"));
        assert_eq!(
            response.headers()["access-control-allow-headers"],
            "authorization,x-nexus-min-revision"
        );

        let response = client
            .get(format!("{base}/v2/status"))
            .header("origin", origin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["access-control-allow-origin"], origin);
        assert_eq!(
            response.headers()["access-control-expose-headers"],
            "x-nexus-revision"
        );
        assert!(response.headers()["vary"]
            .to_str()
            .unwrap()
            .to_lowercase()
            .contains("origin"));

        let response = client
            .post(format!("{base}/v2/search/query"))
            .header("origin", origin)
            .header("content-type", "application/json")
            .body("{bad")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["access-control-allow-origin"], origin);
    }
    for origin in [
        "https://console.example.test.attacker.test",
        "https://unknown.example.test",
        "null",
    ] {
        let response = client
            .request(Method::OPTIONS, format!("{base}/v2/auth/whoami"))
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "authorization")
            .send()
            .await
            .unwrap();
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
    task.abort();
}

#[tokio::test]
async fn cross_origin_access_is_disabled_without_configuration() {
    let (base, task) = start(BrowserOrigins::default()).await;
    let client = Client::builder().no_proxy().build().unwrap();
    for method in [Method::GET, Method::OPTIONS] {
        let response = client
            .request(method, format!("{base}/v2/status"))
            .header("origin", "https://console.example.test")
            .header("access-control-request-method", "GET")
            .send()
            .await
            .unwrap();
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
        assert!(!response
            .headers()
            .contains_key("access-control-allow-credentials"));
    }
    task.abort();
}
