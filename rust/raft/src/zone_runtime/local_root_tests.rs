use super::*;
use kernel::kernel::vfs_proto::ZoneMutationHeader;

fn private_root() -> (Arc<ZoneManager>, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let manager = ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let root = manager.create_zone(contracts::ROOT_ZONE_ID).unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(10)));
    (manager, directory)
}

fn header(id: &str) -> Option<ZoneMutationHeader> {
    Some(ZoneMutationHeader {
        operation_id: id.into(),
        request_hash: 0,
    })
}

#[test]
fn local_runtime_requires_the_existing_private_root() {
    let directory = tempfile::tempdir().unwrap();
    let manager = ZoneManager::with_node_id(
        "shared-root",
        31,
        directory.path().to_str().unwrap(),
        Vec::new(),
        "127.0.0.1:0",
        None,
        None,
        None,
    )
    .unwrap();
    manager.create_zone(contracts::ROOT_ZONE_ID).unwrap();
    assert!(matches!(
        ZoneRuntimeBackend::for_local_root(Arc::clone(&manager)),
        Err(ZoneRuntimeError::PermissionDenied(_))
    ));
    manager.shutdown();
    let (manager, _directory) = private_root();
    let backend = ZoneRuntimeBackend::for_local_root(Arc::clone(&manager)).unwrap();
    let status = backend
        .zone_status(&ZoneStatusRequest {
            zone_id: contracts::ROOT_ZONE_ID.into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(status.presence, Presence::Resident as i32);
    assert!(status.deletion.is_none());
    manager.shutdown();
}

#[test]
fn local_runtime_refuses_global_authority_before_recording_intent() {
    let (manager, _directory) = private_root();
    let backend = ZoneRuntimeBackend::for_local_root(Arc::clone(&manager)).unwrap();
    let refusals = [
        backend.zone_create(&ZoneCreateRequest {
            mutation: header("global-create"),
            zone_id: "data-zone".into(),
            ..Default::default()
        }),
        backend.zone_deprovision(&ZoneDeprovisionRequest {
            mutation: header("global-delete"),
            zone_id: "data-zone".into(),
            ..Default::default()
        }),
        backend.zone_join(&ZoneJoinRequest {
            mutation: header("join-voter"),
            zone_id: "data-zone".into(),
            learner: false,
            ..Default::default()
        }),
        backend.zone_mount(&ZoneMountRequest {
            mutation: header("remote-parent"),
            parent_zone_id: "data-zone".into(),
            mount_path: "/nested".into(),
            target_zone_id: "other-zone".into(),
            ..Default::default()
        }),
        backend.zone_unmount(&ZoneUnmountRequest {
            mutation: header("remote-unmount"),
            parent_zone_id: "data-zone".into(),
            mount_path: "/nested".into(),
            ..Default::default()
        }),
        backend.zone_mount(&ZoneMountRequest {
            mutation: header("control-mount"),
            parent_zone_id: contracts::ROOT_ZONE_ID.into(),
            mount_path: "/control".into(),
            target_zone_id: contracts::CONTROL_ZONE_ID.into(),
            ..Default::default()
        }),
    ];
    for refusal in refusals {
        assert!(matches!(
            refusal,
            Err(ZoneRuntimeError::PermissionDenied(_))
        ));
    }
    for id in [
        "global-create",
        "global-delete",
        "join-voter",
        "remote-parent",
        "remote-unmount",
        "control-mount",
    ] {
        assert!(
            backend.journal.get(id).unwrap().is_none(),
            "refused operation created a durable intent: {id}"
        );
    }
    assert_eq!(
        manager.list_zones(),
        vec![contracts::ROOT_ZONE_ID.to_owned()]
    );
    assert!(!manager.hosts_zone(contracts::CONTROL_ZONE_ID));
    manager.shutdown();
}

#[test]
fn local_executor_retains_aged_pending_across_backend_instances() {
    let (manager, _directory) = private_root();
    let first = ZoneRuntimeBackend::for_local_root(Arc::clone(&manager)).unwrap();
    let second = ZoneRuntimeBackend::for_local_root(Arc::clone(&manager)).unwrap();
    let operation = "aged-local-unmount";
    let record = JournalRecord {
        operation_id: operation.into(),
        request_hash: request_hash(b"unmount", &[contracts::ROOT_ZONE_ID, "/absent"]),
        kind: "unmount".into(),
        zone_id: contracts::ROOT_ZONE_ID.into(),
        status: crate::zone_op_journal::STATUS_PENDING.into(),
        receipt: None,
        error: None,
        updated_at_ms: 0,
    };
    let root = manager.get_zone(contracts::ROOT_ZONE_ID).unwrap();
    let storage = crate::control_state_store::ControlStateStore::new(
        root.consensus_node(),
        root.runtime_handle(),
        contracts::CONTROL_NS_ZONE_OPS,
    );
    let original = serde_json::to_vec(&record).unwrap();
    storage.put(operation, &original).unwrap();
    let executing = first.local_execution().unwrap();
    assert!(executing.is_some());
    let request = ZoneUnmountRequest {
        mutation: header(operation),
        parent_zone_id: contracts::ROOT_ZONE_ID.into(),
        mount_path: "/absent".into(),
        ..Default::default()
    };
    assert!(
        matches!(
            second.zone_unmount(&request),
            Err(ZoneRuntimeError::Unavailable(_))
        ),
        "a retry took over a live local executor"
    );
    assert_eq!(
        storage.get(operation).unwrap().as_deref(),
        Some(original.as_slice())
    );
    drop(executing);
    // The same request now reaches the real store and records its definitive
    // missing-mount refusal, proving execution can resume after release.
    assert!(matches!(
        second.zone_unmount(&request),
        Err(ZoneRuntimeError::Conflict(_))
    ));
    assert_eq!(
        second.journal.get(operation).unwrap().unwrap().status,
        crate::zone_op_journal::STATUS_REJECTED
    );
    manager.shutdown();
}
