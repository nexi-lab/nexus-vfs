//! A token that can use a zone cannot administer its authorization graph.
//! Real HTTP, the production key resolver, and one live Raft consensus shared
//! by the credential and tuple stores exercise grant -> list -> revoke.

#![cfg(feature = "rebac")]

use std::sync::Arc;
use std::time::Duration;

use auth::record::{AuthKeyRecord, SubjectType};
use auth::{mint_key, ApiKeyAuthProvider};
use kernel::hal::auth_key_store::AuthKeyStore;
use nexus_http_api::{bind_and_serve, AppState};
use nexus_raft::auth_key_store::RaftAuthKeyStore;
use nexus_raft::raft::ZoneRaftRegistry;
use nexus_rebac::RaftReBACTupleStore;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};

const SECRET: &str = "rebac-http-e2e-only";

fn mint(store: &Arc<dyn AuthKeyStore>, subject: &str, admin: bool) -> String {
    mint_key(
        store,
        SECRET,
        AuthKeyRecord {
            key_id: subject.into(),
            name: subject.into(),
            subject_type: SubjectType::User,
            subject_id: subject.into(),
            is_admin: admin,
            revoked: false,
            expires_at_ms: None,
            zone_perms: if admin {
                vec![]
            } else {
                vec![("eng".into(), "rw".into())]
            },
        },
        false,
    )
    .expect("mint a real credential into Raft")
    .key
}

// A dropped JoinHandle detaches; abort it when the test exits, including panic.
struct Server(tokio::task::JoinHandle<()>);

impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_an_admin_can_manage_tuples_even_with_a_valid_zone_key() {
    let tmp = tempfile::tempdir().unwrap();
    let registry = ZoneRaftRegistry::new(tmp.path().to_path_buf(), 1);
    let runtime = tokio::runtime::Handle::current();
    let consensus = registry.create_zone("control", vec![], &runtime).unwrap();
    consensus.campaign().await.unwrap();
    let keys = RaftAuthKeyStore::new_arc(consensus.clone(), runtime.clone());
    let tuples = RaftReBACTupleStore::new_arc(consensus, runtime);
    let admin = mint(&keys, "operator", true);
    let user = mint(&keys, "alice", false);
    let mut state = AppState::for_tests("http://127.0.0.1:1");
    state.auth = Arc::new(ApiKeyAuthProvider::new(Arc::clone(&keys), SECRET));
    state.auth_key_store = keys;
    state.api_key_secret = Some(Arc::from(SECRET));
    state.rebac_store = Arc::clone(&tuples);
    let (bound, serving) = bind_and_serve("127.0.0.1:0".parse().unwrap(), state)
        .await
        .unwrap();
    let _server = Server(tokio::spawn(async move { serving.await.unwrap() }));
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://{bound}");
    let url = format!("{base}/v2/rebac/tuples");
    let grant = json!({
        "zone": "eng", "object_type": "file", "object_id": "/private.md",
        "relation": "owner", "subject_type": "user", "subject_id": "alice",
    });

    // The management endpoints reject an unknown identity before authorization.
    for method in [Method::GET, Method::POST, Method::DELETE] {
        let response = client
            .request(method.clone(), format!("{url}?zone=eng"))
            .json(&grant)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method}");
    }

    // A real, valid rw key is still not grant authority. Trying another zone
    // must not provide a second path around the same gate.
    for zone in ["eng", "finance"] {
        let mut attempted = grant.clone();
        attempted["zone"] = json!(zone);
        for method in [Method::GET, Method::POST, Method::DELETE] {
            let response = client
                .request(method.clone(), format!("{url}?zone={zone}"))
                .bearer_auth(&user)
                .json(&attempted)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {zone}");
            assert!(tuples.list().unwrap().is_empty(), "denial must not write");
        }
    }

    // Positive control: the very same request is admitted for the admin, and
    // its committed tuple is the one the following listing returns.
    let response = client
        .post(&url)
        .bearer_auth(&admin)
        .json(&grant)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await.unwrap()
    );
    let listed: Value = client
        .get(format!("{url}?zone=eng"))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed, json!({"tuples": [grant.clone()]}));
    let committed = tuples.list().unwrap();
    assert_eq!(committed.len(), 1);

    // Denial is checked with an existing grant too: a user cannot enumerate
    // it or revoke it, including when the grant names that very user.
    for method in [Method::GET, Method::DELETE] {
        let response = client
            .request(method.clone(), format!("{url}?zone=eng"))
            .bearer_auth(&user)
            .json(&grant)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
        assert_eq!(
            tuples.list().unwrap(),
            committed,
            "denial must preserve the grant"
        );
    }
    let response: Value = client
        .delete(&url)
        .bearer_auth(&admin)
        .json(&grant)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response, json!({"existed": true}));
    assert!(tuples.list().unwrap().is_empty());

    // Credential management and tuple management share the same admin gate.
    assert_eq!(
        client
            .get(format!("{base}/v2/auth/keys"))
            .bearer_auth(&user)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(format!("{base}/v2/auth/keys"))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
