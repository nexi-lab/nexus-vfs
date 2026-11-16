//! Actual fixed-local proposals produce retained CRL state for old readers.

use super::*;
use crate::raft::ZonePersistence;
use crate::{
    transport::{generate_crl, generate_zone_ca},
    ZoneManager,
};
use contracts::crl_control::{
    CrlControlChange, CrlControlOutcome, CrlControlRequest, CrlIssuerSelection, LocalCrlIssuer,
};
use lib::transport_primitives::{ca_spki_sha256, verify_signed_crl};
use std::{path::Path, time::Duration};

#[path = "../../../../tests/common/durable_storage_fixtures.rs"]
mod durable_storage_fixtures;
use durable_storage_fixtures::{install_snapshot, saved_image};

const NAMESPACE: &str = "signed-crl-v1";

struct Runtime(Arc<ZoneManager>);

impl Runtime {
    fn open(path: &Path) -> Self {
        let manager = ZoneManager::isolated(path.to_str().unwrap()).unwrap();
        assert!(manager
            .create_zone("root")
            .unwrap()
            .wait_for_leader(Duration::from_secs(5)));
        Self(manager)
    }

    fn apply(&self, operation: &str, change: CrlControlChange) -> CrlControlOutcome {
        let node = self.0.get_zone("root").unwrap().consensus_node().clone();
        let result = self
            .0
            .runtime_handle()
            .block_on(node.submit_storage_command(
                Command::ApplyCrlControl(Box::new(CrlControlRequest {
                    operation_id: operation.into(),
                    change,
                })),
                StorageProtocol::SignedCrl,
            ))
            .unwrap();
        let CommandResult::Value(bytes) = result else {
            panic!("typed CRL result");
        };
        bincode::deserialize(&bytes).unwrap()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn contents(path: &Path) -> Vec<(String, Vec<u8>)> {
    let persistence = crate::raft::ZonePersistence::open(path, "root").unwrap();
    let store = RedbStore::open(persistence.sm_path()).unwrap();
    let state = FullStateMachine::new(&store).unwrap();
    let mut rows = state.list_control_state(NAMESPACE).unwrap();
    rows.extend(state.list_control_state("content-version-v1").unwrap());
    rows.sort();
    rows
}

fn populate(path: &Path, withdraw: bool) {
    let runtime = Runtime::open(path);
    let (ca, signer) = generate_zone_ca("format-original").unwrap();
    assert!(matches!(
        runtime.apply(
            "issuer",
            CrlControlChange::LocalIssuer {
                expected_revision: None,
                ca_pem: Some(ca.clone()),
            }
        ),
        CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer { revision: 1, .. })
    ));
    for (operation, revoked, number) in [("revoke", vec![vec![0x80, 1]], 2), ("prune", vec![], 3)] {
        let crl = generate_crl(&revoked, number, &ca, &signer).unwrap();
        let observed_unix_s = verify_signed_crl(&crl, &ca).unwrap().this_update();
        assert!(matches!(
            runtime.apply(
                operation,
                CrlControlChange::Install {
                    issuer: CrlIssuerSelection::Local { revision: 1 },
                    crl_pem: crl,
                    observed_unix_s,
                    maximum_age_secs: 60,
                }
            ),
            CrlControlOutcome::Installed { .. }
        ));
    }
    if withdraw {
        assert!(matches!(
            runtime.apply(
                "withdraw",
                CrlControlChange::LocalIssuer {
                    expected_revision: Some(1),
                    ca_pem: None,
                }
            ),
            CrlControlOutcome::LocalIssuerChanged(LocalCrlIssuer {
                revision: 2,
                ca_pem: None
            })
        ));
    }
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    let authority: String = ca_spki_sha256(&ca)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    runtime
        .0
        .runtime_handle()
        .block_on(node.read_linearizable(move |state| {
            assert_eq!(
                state
                    .get_control_state(NAMESPACE, &format!("revoked:{authority}:8001"))
                    .unwrap(),
                Some(b"revoked-v1".to_vec())
            );
            assert_eq!(
                state
                    .get_control_state("content-version-v1", "requires:protected-records-v1")
                    .unwrap(),
                Some(b"signed-crl-control-v1".to_vec())
            );
        }))
        .unwrap();
}

fn produce(destination: &Path) {
    let applied = destination.join("crl-applied");
    std::fs::create_dir_all(&applied).unwrap();
    populate(&applied, false);
    saved_image(&applied, false);
    let compacted = destination.join("crl-compacted");
    std::fs::create_dir_all(&compacted).unwrap();
    populate(&compacted, true);
    let snapshot = saved_image(&compacted, true);
    install_snapshot(&compacted, &destination.join("crl-snapshot"), &snapshot);
}

#[test]
fn signed_crl_format_fixtures_for_previous_reader() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = std::env::var_os("NEXUS_REPLICA_FORMAT_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned());
    produce(&destination);
}

#[test]
fn signed_crl_formats_refuse_managed_and_recover_fixed_local() {
    let directory = tempfile::tempdir().unwrap();
    produce(directory.path());
    let expected_snapshot = contents(&directory.path().join("crl-compacted"));
    for name in ["crl-applied", "crl-compacted", "crl-snapshot"] {
        let path = directory.path().join(name);
        let before = contents(&path);
        if name == "crl-snapshot" {
            assert!(before.is_empty());
        } else {
            assert!(!before.is_empty());
        }
        let id = {
            let persistence = ZonePersistence::open(&path, "root").unwrap();
            let storage = RaftStorage::open(persistence.raft_path()).unwrap();
            storage.conf_state().unwrap().voters[0]
        };
        match ZoneManager::with_node_id(
            "unqualified-crl-reader",
            id,
            path.to_str().unwrap(),
            vec![],
            "127.0.0.1:0",
            None,
            None,
            None,
        ) {
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("require qualified fixed-local storage"),
                "{name}: {error}"
            ),
            Ok(manager) => {
                manager.shutdown();
                panic!("managed reader admitted {name}");
            }
        }
        assert_eq!(contents(&path), before);
        {
            let _runtime = Runtime::open(&path);
        }
        assert_eq!(
            contents(&path),
            if name == "crl-snapshot" {
                expected_snapshot.clone()
            } else {
                before
            }
        );
    }
}
