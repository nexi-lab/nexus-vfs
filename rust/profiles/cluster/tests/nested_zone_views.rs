//! Directory views come from distinct replicated zones and nested mounts.
//! Uses native Raft transport and kernel routing; the alias test also installs
//! the zone-grant permission provider.
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

#[test]
fn stream_aliases_share_content_and_offsets() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let addr = address();
    let manager = node(41, dir.path(), &addr);
    rt.block_on(async {
        for zone in ["root", "contact-probe"] {
            manager
                .create_zone_async(zone, vec![format!("41@{addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        }
    });
    let canonical = a2a::conversation_transcript_path(&a2a::conversation_id("alice", "bob"));
    let alias = "/aliases/inbox";
    manager
        .mount_subtree(
            "root",
            "/conversations",
            "contact-probe",
            "/conversations",
            false,
        )
        .unwrap();
    manager
        .mount_subtree("root", alias, "contact-probe", &canonical, false)
        .unwrap();
    let kernel = build_kernel(&manager, &addr);
    let ctx = kernel::kernel::OperationContext::new("bob", "root", true, Some("bob"), true);
    a2a::ensure_mailbox_stream(kernel.as_ref(), &ctx, &canonical).unwrap();
    let body = b"one existing conversation record";
    kernel.stream_write_nowait(&canonical, body, &ctx).unwrap();
    let direct = kernel
        .sys_stream_read_at(&canonical, 0, 1_000, &ctx)
        .unwrap()
        .unwrap();
    assert_eq!(direct.0, body);
    assert_eq!(
        kernel.sys_stat(alias, "root").unwrap().entry_type,
        DT_STREAM
    );
    assert_eq!(
        kernel.sys_stream_read_at(alias, 0, 0, &ctx).unwrap(),
        Some(direct.clone())
    );
    let second = b"written through another mount";
    assert_eq!(
        kernel.stream_write_nowait(alias, second, &ctx).unwrap(),
        direct.1
    );
    let via_original = kernel
        .sys_stream_read_at(&canonical, direct.1, 0, &ctx)
        .unwrap()
        .unwrap();
    assert_eq!(via_original.0, second);
    assert_eq!(kernel.stream_tail(alias).unwrap(), via_original.1);
    assert_eq!(
        kernel.sys_stat(alias, "root").unwrap().size,
        via_original.1 as u64
    );
    assert_eq!(
        kernel.sys_stream_collect_all(alias, &ctx).unwrap(),
        [body.as_slice(), second.as_slice()].concat()
    );
    // A fresh kernel has no registry handles. It reconstructs the same WAL
    // from the committed inode, without proposing a replacement inode.
    let cold = build_kernel(&manager, &addr);
    assert_eq!(
        cold.sys_stream_read_at(alias, 0, 0, &ctx).unwrap(),
        Some(direct)
    );
    assert_eq!(
        cold.stream_read_batch(alias, 0, 3).unwrap().0,
        vec![body.to_vec(), second.to_vec()]
    );

    // An alias without the transcript suffix must still run the canonical
    // conversation hook. The authenticated actor wins over a forged envelope.
    let contact = alias;
    a2a::install_a2a_stamp_hook(&kernel, true).unwrap();
    let payload = br#"{"from":"mallory","to":"alice","body":"hello"}"#;
    let at = kernel.stream_write_nowait(contact, payload, &ctx).unwrap();
    let stamped = kernel
        .sys_stream_read_at(&canonical, at, 0, &ctx)
        .unwrap()
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&stamped.0).unwrap();
    assert_eq!(envelope["from"], "bob");

    kernel.set_permission_provider(Arc::new(Box::new(permission::ZonePermsProvider::new())));
    let mut reader =
        kernel::kernel::OperationContext::new("bob", "root", false, Some("bob"), false);
    reader.zone_perms = vec![("contact-probe".into(), "r".into())];
    for visible in [alias, canonical.as_str()] {
        let mut results = kernel.sys_read(
            &[kernel::kernel::ReadRequest {
                path: visible.into(),
                offset: 0,
                len: None,
                timeout_ms: 0,
            }],
            &reader,
        );
        assert_eq!(results.remove(0).unwrap().data.unwrap(), body);
        assert_eq!(
            kernel
                .sys_stream_read_at(visible, 0, 0, &reader)
                .unwrap()
                .unwrap()
                .0,
            body
        );
        assert!(
            matches!(
                kernel.stream_write_nowait(visible, payload, &reader),
                Err(kernel::kernel::KernelError::PermissionDenied(_))
            ),
            "a successful read must not grant write access"
        );
        assert!(matches!(
            kernel
                .sys_write(
                    &[kernel::kernel::WriteRequest {
                        path: visible.into(),
                        content: payload.to_vec(),
                        offset: 0,
                    }],
                    &reader
                )
                .remove(0),
            Err(kernel::kernel::KernelError::PermissionDenied(_))
        ));
    }
    reader.zone_perms = vec![("root".into(), "rw".into())];
    for visible in [alias, canonical.as_str()] {
        assert!(
            matches!(
                kernel.sys_stream_collect_all(visible, &reader),
                Err(kernel::kernel::KernelError::PermissionDenied(_))
            ),
            "the mount's zone grant is required, including after a previous read"
        );
    }
    manager.shutdown();
}

#[test]
fn stream_registry_separates_zones_and_uses_the_callers_namespace() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let addr = address();
    let manager = node(41, dir.path(), &addr);
    rt.block_on(async {
        for zone in ["root", "alice-data", "bob-data"] {
            manager
                .create_zone_async(zone, vec![format!("41@{addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        }
    });
    let kernel = build_kernel(&manager, &addr);
    let router = kernel.vfs_router_arc();
    let path = "/conversations/same/transcript";
    for (zone, bytes) in [
        ("alice-data", b"alice".as_slice()),
        ("bob-data", b"bob".as_slice()),
    ] {
        router.add_mount("/", zone, None, false);
        router.install_metastore(
            &kernel::core::vfs_router::canonicalize_mount_path("/", zone),
            Arc::new(store(&manager, zone)),
        );
        let ctx = kernel::kernel::OperationContext::new(zone, zone, true, Some(zone), true);
        kernel
            .sys_setattr(
                path,
                &ctx,
                DT_STREAM.into(),
                "",
                None,
                None,
                None,
                "wal",
                zone,
                false,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(kernel.stream_write_nowait(path, bytes, &ctx).unwrap(), 0);
    }
    for (zone, expected) in [
        ("alice-data", b"alice".as_slice()),
        ("bob-data", b"bob".as_slice()),
    ] {
        let ctx = kernel::kernel::OperationContext::new(zone, zone, true, Some(zone), true);
        assert_eq!(kernel.sys_stream_collect_all(path, &ctx).unwrap(), expected);
        assert_eq!(kernel.sys_stat(path, zone).unwrap().size, 1);
    }
    let root = kernel::kernel::OperationContext::new("system", "root", true, None, true);
    assert!(kernel.sys_stream_read_at(path, 0, 0, &root).is_err());
    manager.shutdown();
}

#[test]
fn replicated_stream_append_wakes_a_reader_under_a_different_mount() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let founder_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let founder_addr = address();
    let replica_addr = address();
    let founder = node(41, founder_dir.path(), &founder_addr);
    let replica = node(42, replica_dir.path(), &replica_addr);
    rt.block_on(async {
        for (manager, id, addr, zones) in [
            (&founder, 41, &founder_addr, vec!["root", "messages"]),
            (&replica, 42, &replica_addr, vec!["root"]),
        ] {
            for zone in zones {
                manager
                    .create_zone_async(zone, vec![format!("{id}@{addr}")])
                    .await
                    .unwrap()
                    .consensus_node()
                    .campaign()
                    .await
                    .unwrap();
            }
        }
    });
    let original = "/conversations/pair/transcript";
    let alias = "/mounted/inbox";
    founder
        .mount_subtree(
            "root",
            "/conversations",
            "messages",
            "/conversations",
            false,
        )
        .unwrap();
    join(&replica, "messages", 42, &replica_addr, &founder_addr);
    replica
        .mount_subtree("root", alias, "messages", original, false)
        .unwrap();
    let writer = build_kernel(&founder, &founder_addr);
    let reader = build_kernel(&replica, &replica_addr);
    nexus_raft::stream_wakeup::install_stream_wakeup_observer(
        &replica.get_zone("messages").unwrap().consensus_node(),
        Arc::downgrade(&reader),
        "messages",
    );
    let writer_ctx =
        kernel::kernel::OperationContext::new("alice", "root", true, Some("alice"), true);
    a2a::ensure_mailbox_stream(writer.as_ref(), &writer_ctx, original).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while reader.sys_stat(alias, "root").is_none() {
        assert!(
            Instant::now() < deadline,
            "replica did not apply stream inode"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let reading = Arc::clone(&reader);
    let waiter = std::thread::spawn(move || {
        let ctx = kernel::kernel::OperationContext::new("bob", "root", true, Some("bob"), true);
        reading.sys_stream_read_at(alias, 0, 10_000, &ctx)
    });
    while reader.stream_parked_readers(alias, "root") == 0 {
        assert!(Instant::now() < deadline, "replica reader never parked");
        std::thread::sleep(Duration::from_millis(5));
    }
    let ctx = kernel::kernel::OperationContext::new("alice", "root", true, Some("alice"), true);
    let started = Instant::now();
    writer
        .stream_write_nowait(original, b"from another node", &ctx)
        .unwrap();
    let received = waiter.join().unwrap().unwrap().unwrap();
    assert_eq!(received.0, b"from another node");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "reader only observed the append at its timeout"
    );
    replica.shutdown();
    founder.shutdown();
}

#[test]
fn legacy_alias_wal_is_reported_instead_of_opening_an_empty_stream() {
    use kernel::core::stream::wal::WalStreamCore;
    use kernel::stream::StreamBackend;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let addr = address();
    let manager = node(41, dir.path(), &addr);
    rt.block_on(async {
        for zone in ["root", "legacy"] {
            manager
                .create_zone_async(zone, vec![format!("41@{addr}")])
                .await
                .unwrap()
                .consensus_node()
                .campaign()
                .await
                .unwrap();
        }
    });
    let path = "/conversations/legacy/transcript";
    let alias = "/old/inbox";
    manager
        .mount_subtree("root", "/conversations", "legacy", "/conversations", false)
        .unwrap();
    manager
        .mount_subtree("root", alias, "legacy", path, false)
        .unwrap();
    let metadata = FileMetadata {
        path: path.into(),
        entry_type: DT_STREAM,
        zone_id: Some("legacy".into()),
        ..Default::default()
    };
    let backing = Arc::new(store(&manager, "legacy"));
    backing.put(path, metadata).unwrap();
    let legacy = WalStreamCore::new(backing, alias.into());
    legacy.push(b"existing history").unwrap();
    let kernel = build_kernel(&manager, &addr);
    let ctx = kernel::kernel::OperationContext::new("system", "root", true, None, true);
    for visible in [path, alias] {
        let error = kernel.sys_stream_read_at(visible, 0, 0, &ctx).unwrap_err();
        assert!(format!("{error:?}").contains("migrate"), "{error:?}");
        assert!(kernel
            .stream_write_nowait(visible, b"must not fork", &ctx)
            .is_err());
    }
    assert_eq!(legacy.read_at(0).unwrap().unwrap(), b"existing history");
    assert_eq!(legacy.tail_offset(), 1);
    manager.shutdown();
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
    let context = kernel::kernel::OperationContext::new("alice", "root", true, None, true);
    a2a::ensure_mailbox_stream(source_kernel.as_ref(), &context, inbox).unwrap();
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
