//! Directory views come from distinct replicated zones and nested mounts.
//! Uses native Raft transport and kernel routing, without a user auth policy.
//! Does not claim scoped admission, cold content retention or runtime handoff.

mod common;

use kernel::kernel::syscall::ReaddirOpts;
use kernel::kernel::Kernel;
use kernel::meta_store::{FileMetadata, MetaStore, DT_MOUNT, DT_STREAM};
use nexus_raft::distributed_coordinator::{bootstrap_or_join_zone, RaftDistributedCoordinator};
use nexus_raft::transport::NodeAddress;
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneManager;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn address() -> String {
    format!("127.0.0.1:{}", common::free_port())
}

fn node(id: u64, dir: &Path, addr: &str) -> Arc<ZoneManager> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match ZoneManager::with_node_id(
            "nested-zone-views",
            id,
            dir.to_str().unwrap(),
            vec![],
            addr,
            None,
            Some(format!("http://{addr}")),
            None,
        ) {
            Ok(manager) => return manager,
            Err(nexus_raft::raft::RaftError::DataDirLocked(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("open node: {error}"),
        }
    }
}

fn store(manager: &ZoneManager, zone: &str) -> ZoneMetaStore {
    let handle = manager.get_zone(zone).unwrap();
    ZoneMetaStore::new(handle.consensus_node(), handle.runtime_handle(), "/".into())
}

fn join(manager: &Arc<ZoneManager>, zone: &str, id: u64, addr: &str, source: &str) {
    bootstrap_or_join_zone(
        manager,
        zone,
        id,
        addr,
        &[NodeAddress::parse(&format!("41@{source}"), false).unwrap()],
        false,
        Some(3),
        true,
    )
    .unwrap();
}

fn build_kernel(manager: &Arc<ZoneManager>, addr: &str) -> Arc<Kernel> {
    let kernel = Arc::new(Kernel::new());
    let router = kernel.vfs_router_arc();
    router.add_mount("/", "root", None, false);
    router.install_metastore(
        &kernel::core::vfs_router::canonicalize_mount_path("/", "root"),
        Arc::new(store(manager, "root")),
    );
    let ops = Arc::new(transport::federation::FederationClient::new(
        Arc::clone(kernel.runtime()),
        None,
    ));
    Arc::new(RaftDistributedCoordinator::new()).install_with_kernel(
        Arc::clone(manager),
        manager.runtime_handle(),
        addr,
        &kernel,
        ops,
    );
    kernel
}

fn seed_agent(manager: &ZoneManager, name: &str) {
    let zone = format!("data-{name}");
    let store = store(manager, &zone);
    for (path, entry_type) in [
        (format!("/agents/{name}"), 1),
        (format!("/agents/{name}/memory.md"), 0),
        (format!("/agents/{name}/sessions/sid-{name}"), 6),
        (format!("/sessions/sid-{name}"), 1),
        (format!("/sessions/sid-{name}/transcript.jsonl"), 4),
    ] {
        let mut meta = FileMetadata {
            path: path.clone(),
            entry_type,
            zone_id: Some(zone.clone()),
            owner_id: Some(name.into()),
            ..Default::default()
        };
        if entry_type == 6 {
            meta.link_target = Some(format!("/sessions/sid-{name}"));
        }
        store.put(&path, meta).unwrap();
    }
}

fn assert_view(kernel: &Kernel, manager: &ZoneManager, user: &str, other: &str) {
    let route = kernel.vfs_router_arc().route("/agents", "root").unwrap();
    assert_eq!(
        route.target_zone_id.as_deref(),
        Some(format!("directory-{user}").as_str())
    );
    assert_eq!(
        route
            .metastore
            .as_ref()
            .unwrap()
            .list("/agents/")
            .unwrap()
            .len(),
        2
    );
    let mut expected = vec![format!("/agents/{user}"), "/agents/team".into()];
    expected.sort();
    let actual: Vec<_> = kernel
        .sys_readdir("/agents", "root", false, ReaddirOpts::default())
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    assert_eq!(actual, expected);
    let limited = kernel.sys_readdir(
        "/agents",
        "root",
        false,
        ReaddirOpts {
            limit: Some(1),
            ..Default::default()
        },
    );
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].0, expected[0]);
    let recursive = kernel.sys_readdir(
        "/agents",
        "root",
        false,
        ReaddirOpts {
            recursive: true,
            limit: None,
        },
    );
    assert!(recursive
        .iter()
        .any(|(p, _)| p == &format!("/agents/{user}/memory.md")));
    assert!(recursive.iter().any(|(p, _)| p == "/agents/team/memory.md"));
    assert!(!recursive.iter().any(|(p, _)| p.contains(other)));
    assert!(kernel
        .sys_stat(&format!("/agents/{other}/memory.md"), "root")
        .is_none());
    assert!(kernel
        .sys_stat(&format!("/sessions/sid-{other}"), "root")
        .is_none());
    for name in [user, "team"] {
        let link = format!("/agents/{name}/sessions/sid-{name}");
        let route = kernel.vfs_router_arc().route(&link, "root").unwrap();
        assert_eq!(
            route.target_zone_id.as_deref(),
            Some(format!("data-{name}").as_str())
        );
        let metadata = route.metastore.unwrap().get(&link).unwrap().unwrap();
        assert_eq!(metadata.entry_type, 6);
        assert_eq!(metadata.owner_id.as_deref(), Some(name));
        assert_eq!(metadata.link_target, Some(format!("/sessions/sid-{name}")));
        assert!(kernel
            .sys_stat(&format!("/sessions/sid-{name}/transcript.jsonl"), "root")
            .is_some());
    }
    let directory = store(manager, &format!("directory-{user}"));
    assert!(directory
        .list("/")
        .unwrap()
        .iter()
        .all(|m| !m.path.contains(other)));
    assert_eq!(manager.list_zones().len(), 4);
    assert!(!manager.hosts_zone(&format!("directory-{other}")));
    assert!(!manager.hosts_zone(&format!("data-{other}")));
    for zone in [
        format!("directory-{user}"),
        format!("data-{user}"),
        "data-team".into(),
    ] {
        assert_eq!(
            manager.get_zone(&zone).unwrap().consensus_node().voters(),
            vec![41]
        );
    }
}

#[test]
fn replicated_directory_zones_keep_separate_views_after_source_loss_and_restart() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let source_dir = tempfile::tempdir().unwrap();
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let source_addr = address();
    let source = node(41, source_dir.path(), &source_addr);
    rt.block_on(async {
        for zone in [
            "root",
            "directory-alice",
            "directory-bob",
            "data-alice",
            "data-bob",
            "data-team",
        ] {
            source
                .create_zone_async(zone, vec![format!("41@{source_addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        }
        for name in ["alice", "bob", "team"] {
            seed_agent(&source, name);
        }
        for user in ["alice", "bob"] {
            for agent in [user, "team"] {
                for path in [format!("/agents/{agent}"), format!("/sessions/sid-{agent}")] {
                    source
                        .mount_subtree_async(
                            &format!("directory-{user}"),
                            &path,
                            &format!("data-{agent}"),
                            &path,
                            true,
                        )
                        .await
                        .unwrap();
                }
            }
        }
    });
    for (dir, user) in [(alice_dir.path(), "alice"), (bob_dir.path(), "bob")] {
        run_device(dir, user, Some(&source_addr));
    }
    source.shutdown();
    drop(source);
    for (dir, user) in [(alice_dir.path(), "alice"), (bob_dir.path(), "bob")] {
        run_device(dir, user, None);
    }
}

/// A separate process gives restart its real meaning: no kernel, route,
/// consensus handle or cache from the first device run survives.
fn run_device(dir: &Path, user: &str, source: Option<&str>) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "nested_view_device_worker", "--nocapture"])
        .env("NEXUS_NESTED_VIEW_DIR", dir)
        .env("NEXUS_NESTED_VIEW_USER", user)
        .env("NEXUS_NESTED_VIEW_SOURCE", source.unwrap_or_default())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{user} device (source={source:?}):\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn nested_view_device_worker() {
    let Some(dir) = std::env::var_os("NEXUS_NESTED_VIEW_DIR") else {
        return;
    };
    let user = std::env::var("NEXUS_NESTED_VIEW_USER").unwrap();
    let source = std::env::var("NEXUS_NESTED_VIEW_SOURCE").unwrap();
    let (id, other) = if user == "alice" {
        (42, "bob")
    } else {
        (43, "alice")
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = address();
    let manager = node(id, Path::new(&dir), &addr);
    let kernel = if !source.is_empty() {
        rt.block_on(async {
            manager
                .create_zone_async("root", vec![format!("{id}@{addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        });
        let directory = format!("directory-{user}");
        join(&manager, &directory, id, &addr, &source);
        rt.block_on(async {
            for path in ["/agents", "/sessions"] {
                manager
                    .mount_subtree_async("root", path, &directory, path, false)
                    .await
                    .unwrap();
            }
        });
        let kernel = build_kernel(&manager, &addr);
        // Replaying the parent's declarations must not enroll their children.
        assert_eq!(manager.list_zones().len(), 2);
        assert!(!manager.hosts_zone(&format!("data-{user}")));
        assert!(!manager.hosts_zone("data-team"));
        for zone in [format!("data-{user}"), "data-team".into()] {
            join(&manager, &zone, id, &addr, &source);
        }
        kernel
    } else {
        build_kernel(&manager, &addr)
    };
    assert_view(&kernel, &manager, &user, other);
    manager.shutdown();
}

/// A subtree mount limits paths, while zone membership determines which
/// metadata is replicated. The public directory uses synthetic stream dirents;
/// the single-entry mount also reads real replicated WAL records. No user
/// authorization or agent runtime is installed in this topology probe.
#[test]
fn public_discovery_can_exclude_private_zones_but_subtree_mounts_cannot_filter_replication() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let source_dir = tempfile::tempdir().unwrap();
    let source_addr = address();
    let source = node(41, source_dir.path(), &source_addr);
    rt.block_on(async {
        for zone in ["root", "discovery", "data-alice", "data-bob"] {
            source
                .create_zone_async(zone, vec![format!("41@{source_addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        }
    });
    for name in ["alice", "bob"] {
        seed_agent(&source, name);
        let public_path = format!("/agents/{name}/chat-with-me");
        store(&source, "discovery")
            .put(
                &public_path,
                FileMetadata {
                    path: public_path.clone(),
                    entry_type: DT_STREAM,
                    zone_id: Some("discovery".into()),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    // An alternative layout: the public child is in the same data zone as
    // the agent's private sessions. Project ONLY that child onto the peer.
    let child_path = "/agents/alice/public/chat-with-me";
    store(&source, "data-alice")
        .put(
            child_path,
            FileMetadata {
                path: child_path.into(),
                entry_type: DT_STREAM,
                zone_id: Some("data-alice".into()),
                ..Default::default()
            },
        )
        .unwrap();

    source
        .mount_subtree(
            "root",
            "/agents/alice",
            "data-alice",
            "/agents/alice",
            false,
        )
        .unwrap();
    let source_kernel = build_kernel(&source, &source_addr);
    let inbox = "/agents/alice/chat-with-me";
    a2a::ensure_mailbox_stream(source_kernel.as_ref(), inbox).unwrap();
    let context = kernel::kernel::OperationContext::new("alice", "root", true, None, true);
    let messages: [&[u8]; 2] = [
        br#"{"from":"bob","to":"alice","body":"only for alice"}"#,
        br#"{"from":"carol","to":"alice","body":"also only for alice"}"#,
    ];
    for message in messages {
        source_kernel
            .stream_write_nowait(inbox, message, &context)
            .unwrap();
    }
    assert_eq!(
        source_kernel
            .stream_read_at_blocking(inbox, 0, 1_000)
            .unwrap()
            .0,
        messages[0]
    );

    for (id, zone, mount, subtree) in [
        (42, "discovery", "/agents", "/agents"),
        (43, "data-alice", "/agents/alice", "/agents/alice/public"),
        (
            44,
            "data-alice",
            "/agents/alice/chat-with-me",
            "/agents/alice/chat-with-me",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let addr = address();
        let target = node(id, dir.path(), &addr);
        rt.block_on(async {
            target
                .create_zone_async("root", vec![format!("{id}@{addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        });
        join(&target, zone, id, &addr, &source_addr);
        target
            .mount_subtree("root", mount, zone, subtree, false)
            .unwrap();
        let kernel = build_kernel(&target, &addr);
        let listed = kernel.sys_readdir("/agents/alice", "root", false, ReaddirOpts::default());
        if id == 44 {
            assert_eq!(listed, vec![(inbox.into(), DT_MOUNT)]);
            let stat = kernel.sys_stat(inbox, "root").unwrap();
            assert_eq!(stat.entry_type, DT_STREAM);
            assert!(!stat.is_directory);
            // A single stream can be mounted, but all its senders' records
            // remain readable by the replica. Mounting is not append-only access.
            let mut offset = 0;
            for expected in messages {
                let (data, next) = kernel
                    .stream_read_at_blocking(inbox, offset, 1_000)
                    .unwrap();
                assert_eq!(data, expected);
                offset = next;
            }
        } else {
            assert_eq!(
                listed,
                vec![("/agents/alice/chat-with-me".into(), DT_STREAM)]
            );
        }
        assert!(kernel.sys_stat("/agents/alice/memory.md", "root").is_none());
        assert!(kernel
            .sys_stat("/sessions/sid-alice/transcript.jsonl", "root")
            .is_none());

        let names: Vec<_> = kernel
            .sys_readdir("/agents", "root", false, ReaddirOpts::default())
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        if zone == "discovery" {
            assert_eq!(names, vec!["/agents/alice", "/agents/bob"]);
            assert!(!target.hosts_zone("data-alice"));
            assert!(!target.hosts_zone("data-bob"));
        } else {
            assert_eq!(names, vec!["/agents/alice"]);
            // Hidden from the mounted view, but PRESENT in the target's Raft
            // state: a valid narrow subtree mount is not a privacy boundary.
            let replica = store(&target, "data-alice");
            assert!(replica.get("/agents/alice/memory.md").unwrap().is_some());
            assert!(replica
                .get("/sessions/sid-alice/transcript.jsonl")
                .unwrap()
                .is_some());
        }
        target.shutdown();
    }
    source.shutdown();
}
