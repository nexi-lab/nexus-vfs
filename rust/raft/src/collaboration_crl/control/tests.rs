use super::*;
use crate::prelude::{FullStateMachine, ZoneConsensus};
use crate::raft::ZoneRaftRegistry;
use crate::transport::{generate_crl, generate_zone_ca};
use contracts::crl_control::{CrlControlChange, CrlIssuerSelection};

async fn ready(node: &ZoneConsensus<FullStateMachine>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("current-term entry must apply before ReadIndex");
}

fn issuer(operation_id: &str, revision: Option<u64>, ca: Option<&[u8]>) -> CrlControlRequest {
    CrlControlRequest {
        operation_id: operation_id.into(),
        change: CrlControlChange::LocalIssuer {
            expected_revision: revision,
            ca_pem: ca.map(<[u8]>::to_vec),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_crl_roundtrip_retains_original_receipt_after_withdrawal_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    // This is a real FixedLocal foundation. It does not qualify a Managed
    // control zone or enable the typed protocol on a user tenant.
    let registry = ZoneRaftRegistry::isolated_root(directory.path().into(), 1);
    let node = registry
        .create_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime.clone(), 60).unwrap();
    let (ca, key) = generate_zone_ca("original-control-issuer").unwrap();
    let original = issuer("original-issuer", None, Some(&ca));
    assert_eq!(store.current_local_issuer().unwrap(), None);
    assert_eq!(store.reconcile_control(&original).unwrap(), None);
    let enrolled = store.apply_control(&original).unwrap();
    assert_eq!(
        enrolled,
        CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer {
            revision: 1,
            ca_pem: Some(ca.clone()),
        })
    );
    let crl = generate_crl(&[vec![0x80, 1]], 1, &ca, &key).unwrap();
    let install = CrlControlRequest {
        operation_id: "original-signed-crl".into(),
        change: CrlControlChange::Install {
            issuer: CrlIssuerSelection::Local { revision: 1 },
            crl_pem: crl,
            observed_unix_s: crate::collaboration_crl::now().unwrap(),
            maximum_age_secs: 60,
        },
    };
    let installed = store.apply_control(&install).unwrap();
    assert!(matches!(installed, CrlControlOutcome::Installed { .. }));
    assert_eq!(
        store.reconcile_control(&install).unwrap(),
        Some(installed.clone())
    );
    let withdrawn = LocalCrlIssuer {
        revision: 2,
        ca_pem: None,
    };
    assert_eq!(
        store
            .apply_control(&issuer("withdraw-local", Some(1), None))
            .unwrap(),
        CrlControlOutcome::LocalIssuerChanged(withdrawn.clone())
    );
    assert_eq!(
        store.reconcile_control(&original).unwrap(),
        Some(enrolled.clone())
    );
    assert_eq!(
        store.reconcile_control(&install).unwrap(),
        Some(installed.clone())
    );
    assert_eq!(
        store.current_local_issuer().unwrap(),
        Some(withdrawn.clone())
    );
    let changed = issuer("original-issuer", Some(2), Some(&ca));
    assert_eq!(
        store.reconcile_control(&changed).unwrap(),
        Some(CrlControlOutcome::OperationMismatch)
    );
    assert_eq!(
        store.current_local_issuer().unwrap(),
        Some(withdrawn.clone())
    );
    let mut later = install.clone();
    later.operation_id = "new-operation-with-retired-selection".into();
    assert!(matches!(
        store.apply_control(&later).unwrap(),
        CrlControlOutcome::Refused(_)
    ));
    drop(store);
    registry.shutdown().released().await;
    drop(registry);

    let registry = ZoneRaftRegistry::isolated_root(directory.path().into(), 1);
    let node = registry
        .open_persisted_zone(contracts::ROOT_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node, runtime, 60).unwrap();
    assert_eq!(
        store.reconcile_control(&original).unwrap(),
        Some(enrolled.clone())
    );
    assert_eq!(store.reconcile_control(&install).unwrap(), Some(installed));
    assert_eq!(
        store.current_local_issuer().unwrap(),
        Some(withdrawn.clone())
    );
    // Even an explicit original retry returns history without reinstating it.
    assert_eq!(store.apply_control(&original).unwrap(), enrolled);
    assert_eq!(store.current_local_issuer().unwrap(), Some(withdrawn));
    registry.shutdown().released().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_crl_control_refuses_before_any_submission() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(directory.path().into(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    ready(&node).await;
    let store = RaftCollaborationCrlStore::new(node.clone(), runtime, 60).unwrap();
    let (ca, _) = generate_zone_ca("managed-control").unwrap();
    let request = issuer("managed-initial-issuer", None, Some(&ca));
    let before = node.last_index();
    assert!(matches!(
        store.apply_control(&request),
        Err(CrlStateError::Refused(_))
    ));
    assert_eq!(store.reconcile_control(&request).unwrap(), None);
    assert_eq!(store.current_local_issuer().unwrap(), None);
    assert_eq!(
        node.last_index(),
        before,
        "unsupported admission must not enqueue a log entry"
    );
    registry.shutdown().released().await;
}
