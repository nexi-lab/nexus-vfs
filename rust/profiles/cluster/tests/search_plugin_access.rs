//! Signed Search DLL + real gRPC + Raft credential/relationship stores.
//! Two users share a warm index cache; grants and revocations must still apply.

mod common;

use std::sync::Arc;
use std::time::Duration;

use auth::{ApiKeyAuthProvider, AuthKeyRecord, SubjectType};
use kernel::hal::auth_key_store::AuthKeyStore;
use kernel::kernel::Kernel;
use nexus_raft::auth_key_store::RaftAuthKeyStore;
use nexus_raft::raft::ZoneRaftRegistry;
use nexus_rebac::{RaftReBACTupleStore, ReBACGraphCache, ReBACTupleStore, RebacPermissionProvider};
use nexus_search_plugin::search_proto::{search_service_client::SearchServiceClient, *};
use prost::Message;
use tonic::{Code, Request};
use transport::grpc::DataPlaneReady;
use transport::grpc_plugin_access::PluginGrpcPolicy;
use transport::grpc_plugin_proxy::extend_routes_with_plugin_endpoints;
use transport::grpc_search_access::SearchGrpcPolicy;

const ZONE: &str = "sharedzone";
const SECRET: &str = "search-access-test-only";

fn mint(
    store: &Arc<dyn AuthKeyStore>,
    name: &str,
    zone: &str,
    perms: &str,
    admin: bool,
) -> auth::MintedKey {
    auth::mint_key(
        store,
        SECRET,
        AuthKeyRecord {
            key_id: name.into(),
            name: name.into(),
            subject_type: SubjectType::User,
            subject_id: name.into(),
            is_admin: admin,
            revoked: false,
            expires_at_ms: None,
            zone_perms: vec![(zone.into(), perms.into())],
        },
        false,
    )
    .unwrap()
}

fn grant(store: &dyn ReBACTupleStore, path: &str, subject: &str) -> String {
    let tuple = lib::types::ReBACTuple {
        object_type: "file".into(),
        object_id: path.into(),
        relation: "viewer".into(),
        subject_type: "user".into(),
        subject_id: subject.into(),
        subject_relation: None,
    };
    let key = nexus_rebac::tuple_key::encode(ZONE, &tuple).unwrap();
    store.put(&key, b"").unwrap();
    key
}

fn query(token: &str) -> QueryRequest {
    QueryRequest {
        q: "widget".into(),
        zone_id: ZONE.into(),
        auth_token: token.into(),
        query_type: QueryType::Keyword as i32,
        limit: 10,
        ..Default::default()
    }
}

fn paths(response: QueryResponse) -> Vec<String> {
    assert!(response.error.is_none(), "{:?}", response.error);
    let mut paths: Vec<_> = response.results.into_iter().map(|hit| hit.path).collect();
    paths.sort();
    paths
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credentials_and_live_permissions_survive_signed_plugin_and_cached_search() {
    let tmp = tempfile::tempdir().unwrap();
    let plugins = common::search_plugin::signed_plugin(tmp.path());
    let models = tmp.path().join("empty-models");
    std::fs::create_dir_all(&models).unwrap();
    // This process has a single plugin test. Environment is sampled at plugin
    // construction; the shared harness's utility tests do not read these vars.
    std::env::set_var("NEXUS_DATA_DIR", tmp.path().join("plugin-data"));
    std::env::set_var("NEXUS_LOCAL_TRUSTED_KEYS_DIR", tmp.path().join("trust"));
    std::env::set_var("NEXUS_SEARCH_MODEL_DIR", &models);
    std::env::set_var("NEXUS_SEARCH_QUERY_EXPANSION", "false");
    std::env::set_var("NEXUS_SEARCH_CONTEXTUAL_CHUNKING", "false");
    std::env::set_var("NEXUS_SEARCH_EMBED_API_URL", "");
    std::env::set_var("NEXUS_SEARCH_PEER_FANOUT_ZONES", "");

    let registry = ZoneRaftRegistry::new(tmp.path().join("raft"), 1);
    let runtime = tokio::runtime::Handle::current();
    let node = registry.create_zone("root", vec![], &runtime).unwrap();
    node.campaign().await.unwrap();
    let keys = RaftAuthKeyStore::new_arc(node.clone(), runtime.clone());
    let tuples = Arc::new(RaftReBACTupleStore::new(node, runtime));
    let admin = mint(&keys, "admin", ZONE, "rw", true);
    let alice = mint(&keys, "alice", ZONE, "r", false);
    let bob = mint(&keys, "bob", ZONE, "r", false);
    let other = mint(&keys, "other", "otherzone", "r", false);
    let writer = mint(&keys, "writer", ZONE, "w", false);
    let auth = Arc::new(ApiKeyAuthProvider::new(keys.clone(), SECRET));

    let kernel = Arc::new(Kernel::new());
    let docs = tmp.path().join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    for name in ["public.md", "private.md"] {
        std::fs::write(docs.join(name), format!("widget {name}")).unwrap();
    }
    let backend = backends::storage::path_local::PathLocalBackend::new(&docs, false).unwrap();
    kernel.vfs_router_arc().add_federation_mount(
        "/docs",
        "root",
        Some(Arc::new(backend)),
        ZONE,
        // The whole zone: this is the only mount of it, and the backend's files
        // sit at its root.
        "/",
        true,
    );
    let other_backend = backends::storage::path_local::PathLocalBackend::new(&docs, false).unwrap();
    kernel.vfs_router_arc().add_federation_mount(
        "/other-docs",
        "root",
        Some(Arc::new(other_backend)),
        "otherzone",
        "/",
        true,
    );
    let alice_grant = grant(tuples.as_ref(), "/docs/public.md", "alice");
    grant(tuples.as_ref(), "/docs/private.md", "bob");
    grant(tuples.as_ref(), "/docs", "alice");
    kernel.set_permission_provider(Arc::new(Box::new(RebacPermissionProvider::new(Arc::new(
        ReBACGraphCache::new(tuples.clone()),
    )))));
    let loading = kernel.clone();
    tokio::task::spawn_blocking(move || loading.load_plugin_dir(&plugins).unwrap())
        .await
        .unwrap();
    let policy = Arc::new(SearchGrpcPolicy::new(kernel.clone(), auth.clone()));
    let ready = DataPlaneReady::pending();
    let routes = extend_routes_with_plugin_endpoints(
        tonic::service::Routes::default(),
        kernel.plugin_grpc_endpoints(),
        Arc::new(std::sync::OnceLock::new()),
        ready.clone(),
        |_| policy.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .timeout(Duration::from_secs(10))
        .connect()
        .await
        .unwrap();
    let mut client = SearchServiceClient::new(channel);

    // No plugin work may run before the composition root finishes wiring policy.
    let mut waiting = client.clone();
    let credential = admin.key.clone();
    let mut held = tokio::spawn(async move {
        waiting
            .health(HealthRequest {
                auth_token: credential,
            })
            .await
    });
    assert!(tokio::time::timeout(Duration::from_millis(100), &mut held)
        .await
        .is_err());
    ready.mark_ready();
    held.await.unwrap().unwrap();

    let batch = IndexDocumentsRequest {
        zone_id: ZONE.into(),
        auth_token: admin.key.clone(),
        documents: ["/docs/public.md", "/docs/private.md", "/__sys__/auth/keys"]
            .into_iter()
            .map(|path| DocumentInput {
                path: path.into(),
                text: format!("widget {path}"),
                ..Default::default()
            })
            .collect(),
    };
    let indexed = client.index_documents(batch).await.unwrap().into_inner();
    assert!(indexed.error.is_none(), "{indexed:?}");
    assert_eq!(indexed.indexed_count, 3);
    assert_eq!(
        paths(client.query(query(&admin.key)).await.unwrap().into_inner()),
        ["/__sys__/auth/keys", "/docs/private.md", "/docs/public.md"]
    );

    for token in ["", "sk-this-unknown-key-is-long-enough-to-parse"] {
        assert_eq!(
            client.query(query(token)).await.unwrap_err().code(),
            Code::Unauthenticated
        );
    }
    for token in [&other.key, &writer.key] {
        assert_eq!(
            client.query(query(token)).await.unwrap_err().code(),
            Code::PermissionDenied
        );
    }
    assert_eq!(
        paths(client.query(query(&alice.key)).await.unwrap().into_inner()),
        ["/docs/public.md"]
    );
    assert_eq!(
        paths(client.query(query(&bob.key)).await.unwrap().into_inner()),
        ["/docs/private.md"]
    );

    // Header-only credentials and an omitted zone bind to the resolved caller.
    let mut header = Request::new(QueryRequest {
        zone_id: String::new(),
        ..query("")
    });
    header.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", alice.key).parse().unwrap(),
    );
    assert_eq!(
        paths(client.query(header).await.unwrap().into_inner()),
        ["/docs/public.md"]
    );
    let mut conflict = Request::new(query(&admin.key));
    conflict.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", alice.key).parse().unwrap(),
    );
    assert_eq!(
        client.query(conflict).await.unwrap_err().code(),
        Code::Unauthenticated
    );

    // Every index-management or aggregate diagnostic RPC has the same gate.
    macro_rules! denied {
        ($method:ident, $request:ident) => {
            assert_eq!(
                client
                    .$method($request {
                        auth_token: alice.key.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
        };
    }
    denied!(index, IndexRequest);
    denied!(refresh, RefreshRequest);
    denied!(index_documents, IndexDocumentsRequest);
    denied!(notify_file_change, NotifyFileChangeRequest);
    denied!(parked_list, ParkedListRequest);
    denied!(parked_retry, ParkedRetryRequest);
    denied!(parked_discard, ParkedDiscardRequest);
    denied!(add_indexed_directory, AddIndexedDirectoryRequest);
    denied!(remove_indexed_directory, RemoveIndexedDirectoryRequest);
    denied!(list_indexed_directories, ListIndexedDirectoriesRequest);
    denied!(set_zone_indexing_mode, SetZoneIndexingModeRequest);
    assert_eq!(
        client
            .list_zone_indexing_modes(ListZoneIndexingModesRequest {
                auth_token: alice.key.clone(),
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied,
    );
    assert_eq!(
        client
            .health(HealthRequest {
                auth_token: alice.key.clone(),
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied,
    );
    denied!(stats, StatsRequest);

    let batch = client
        .batch_query(BatchQueryRequest {
            queries: vec![query(&admin.key)],
            auth_token: alice.key.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        paths(batch.responses.into_iter().next().unwrap()),
        ["/docs/public.md"]
    );
    let wrong_zone = QueryRequest {
        zone_id: "otherzone".into(),
        ..query(&admin.key)
    };
    assert_eq!(
        client
            .batch_query(BatchQueryRequest {
                queries: vec![query(&alice.key), wrong_zone],
                auth_token: alice.key.clone()
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );

    let located = client
        .locate(LocateRequest {
            path: "/docs/public.md".into(),
            zone_id: ZONE.into(),
            auth_token: alice.key.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(located.indexed);
    assert_eq!(
        client
            .locate(LocateRequest {
                path: "/docs/private.md".into(),
                zone_id: ZONE.into(),
                auth_token: alice.key.clone()
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let glob = client
        .glob(GlobRequest {
            root_path: "/docs".into(),
            pattern: "*.md".into(),
            auth_token: alice.key.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(glob.error.is_none(), "{glob:?}");
    assert_eq!(glob.paths, ["/docs/public.md"]);
    let grep = client
        .grep(GrepRequest {
            root_path: "/docs".into(),
            pattern: "widget".into(),
            auth_token: alice.key.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(grep.error.is_none(), "{grep:?}");
    assert_eq!(
        grep.matches
            .iter()
            .map(|hit| hit.path.as_str())
            .collect::<Vec<_>>(),
        ["/docs/public.md"]
    );

    // Refine the discovery result through the same caller boundary. Private
    // paths precede public ones to catch cap starvation before authorization.
    let working = DiscoveryFiles {
        paths: vec![
            "/docs/private.md".into(),
            "docs/public.md".into(),
            "/docs/public.md".into(),
            "/docs-other/public.md".into(),
        ],
    };
    let refined = client
        .grep(GrepRequest {
            root_path: "/docs".into(),
            pattern: "widget".into(),
            max_results: 1,
            files: Some(working),
            auth_token: alice.key.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(refined.error.is_none(), "{refined:?}");
    assert_eq!(refined.applied_filters, DiscoveryFilter::Files as u32);
    assert_eq!(refined.matches.len(), 1);
    assert_eq!(refined.matches[0].path, "/docs/public.md");
    assert!(
        !refined.truncated,
        "denied and duplicate paths cannot consume the cap"
    );
    let empty = client
        .glob(GlobRequest {
            root_path: "/docs".into(),
            pattern: "*.md".into(),
            files: Some(DiscoveryFiles { paths: vec![] }),
            auth_token: alice.key.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(empty.paths.is_empty());
    assert_eq!(
        client
            .grep(GrepRequest {
                root_path: "/docs".into(),
                pattern: "widget".into(),
                files: Some(DiscoveryFiles {
                    paths: vec!["/docs/../private.md".into()]
                }),
                auth_token: alice.key.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        client
            .glob(GlobRequest {
                root_path: "/docs".into(),
                pattern: "*.md".into(),
                files: Some(DiscoveryFiles {
                    paths: vec!["/docs/public.md".into(); 10_001]
                }),
                auth_token: alice.key.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );

    assert_eq!(
        client
            .grep(GrepRequest {
                root_path: "/docs".into(),
                pattern: "widget".into(),
                files: Some(DiscoveryFiles {
                    paths: vec!["/other-docs/public.md".into()]
                }),
                auth_token: alice.key.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );

    // Old plugins encode no acknowledgement even for readable results. The
    // host must reject those responses before returning an unscoped result.
    let selection = Some(DiscoveryFiles {
        paths: vec!["/docs/public.md".into()],
    });
    let legacy_cases = [
        (
            "Glob",
            GlobRequest {
                root_path: "/docs".into(),
                pattern: "*.md".into(),
                files: selection.clone(),
                auth_token: alice.key.clone(),
                ..Default::default()
            }
            .encode_to_vec(),
            GlobResponse {
                paths: vec!["/docs/public.md".into()],
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        (
            "Grep",
            GrepRequest {
                root_path: "/docs".into(),
                pattern: "widget".into(),
                files: selection,
                auth_token: alice.key.clone(),
                ..Default::default()
            }
            .encode_to_vec(),
            GrepResponse {
                matches: vec![GrepMatch {
                    path: "/docs/public.md".into(),
                    line_number: 1,
                    line: "widget".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        ),
    ];
    for (method, mut request, old_response) in legacy_cases {
        let call = policy
            .authorize(method, &mut request, &Default::default(), None)
            .unwrap();
        assert_eq!(
            call.complete(old_response).unwrap_err().code(),
            Code::Unimplemented
        );
    }

    // Changing only a relation does not invalidate the plugin's search cache.
    // The response must nevertheless reflect the new permission graph.
    tuples.delete(&alice_grant).unwrap();
    assert!(paths(client.query(query(&alice.key)).await.unwrap().into_inner()).is_empty());
    assert_eq!(
        paths(client.query(query(&bob.key)).await.unwrap().into_inner()),
        ["/docs/private.md"]
    );
    let revoked = client
        .grep(GrepRequest {
            root_path: "/docs".into(),
            pattern: "widget".into(),
            files: Some(DiscoveryFiles {
                paths: vec!["/docs/public.md".into()],
            }),
            auth_token: alice.key.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(revoked.error.is_none());
    assert!(
        revoked.matches.is_empty(),
        "working sets must observe live grant revocation"
    );
    grant(tuples.as_ref(), "/docs/public.md", "alice");
    assert_eq!(
        paths(client.query(query(&alice.key)).await.unwrap().into_inner()),
        ["/docs/public.md"]
    );
    keys.delete(&alice.key_hash).unwrap();
    auth.invalidate(&alice.key_hash);
    assert_eq!(
        client.query(query(&alice.key)).await.unwrap_err().code(),
        Code::Unauthenticated
    );

    kernel.unload_plugin("search").unwrap();
    assert!(kernel.list_plugins().is_empty());
    // Routes retain their dispatcher after unload; it must reject calls without
    // touching the destroyed instance or unmapped plugin code.
    assert_eq!(
        client.query(query(&admin.key)).await.unwrap_err().code(),
        Code::Unavailable
    );
    server.abort();
    let _ = server.await;
    registry.shutdown_all();
}
