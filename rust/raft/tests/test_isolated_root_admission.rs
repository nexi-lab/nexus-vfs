//! Admission and lifetime boundaries for an owner runtime's local root.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;
use std::time::Duration;

use nexus_raft::raft::{RaftStorage, ZonePersistence};
use nexus_raft::ZoneManager;
use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{
    ConfChange, ConfChangeType, ConfState, Entry, EntryType, Message, MessageType,
};
use tempfile::TempDir;

struct LocalRuntime(Arc<ZoneManager>);

impl Drop for LocalRuntime {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

fn open(dir: &TempDir) -> LocalRuntime {
    LocalRuntime(ZoneManager::isolated(dir.path().to_str().unwrap()).unwrap())
}

#[test]
fn isolated_root_refuses_membership_changes() {
    let dir = TempDir::new().unwrap();
    let runtime = open(&dir);
    let root = runtime.0.create_zone("root", Vec::new()).unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(10)));
    let node = root.consensus_node();
    runtime
        .0
        .runtime_handle()
        .block_on(node.read_linearizable(|_| ()))
        .unwrap();
    let before = root.last_log_index();
    let peer = if runtime.0.node_id() == 1 { 2 } else { 1 };
    let result = runtime
        .0
        .runtime_handle()
        .block_on(node.propose_conf_change(ConfChangeType::AddLearnerNode, peer, Vec::new()));
    assert!(result.is_err(), "isolated root admitted a remote learner");
    assert_eq!(root.last_log_index(), before);
}

#[test]
fn isolated_root_refuses_peer_ingress() {
    let dir = TempDir::new().unwrap();
    let runtime = open(&dir);
    let root = runtime.0.create_zone("root", Vec::new()).unwrap();
    let node = root.consensus_node();
    let peer = if runtime.0.node_id() == 1 { 2 } else { 1 };
    let mut heartbeat = Message::default();
    heartbeat.set_msg_type(MessageType::MsgHeartbeat);
    heartbeat.from = peer;
    heartbeat.to = runtime.0.node_id();
    assert!(runtime
        .0
        .runtime_handle()
        .block_on(node.step(heartbeat))
        .is_err());
}

#[test]
fn isolated_root_reopens_its_durable_metadata() {
    let dir = TempDir::new().unwrap();
    let id = {
        let runtime = open(&dir);
        let root = runtime.0.create_zone("root", Vec::new()).unwrap();
        assert!(root.wait_for_leader(Duration::from_secs(10)));
        root.set_metadata("/saved", b"durable".to_vec(), nexus_raft::Consistency::Sc)
            .unwrap();
        runtime.0.node_id()
    };
    let runtime = open(&dir);
    assert_eq!(runtime.0.node_id(), id);
    let root = runtime.0.create_zone("root", Vec::new()).unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(10)));
    let value = runtime
        .0
        .runtime_handle()
        .block_on(
            root.consensus_node()
                .read_linearizable(|state| state.get_metadata("/saved")),
        )
        .unwrap()
        .unwrap();
    assert_eq!(value, Some(b"durable".to_vec()));
}

#[test]
fn isolated_restart_refuses_a_pending_membership_change() {
    let dir = TempDir::new().unwrap();
    let id = {
        let runtime = open(&dir);
        let root = runtime.0.create_zone("root", Vec::new()).unwrap();
        assert!(root.wait_for_leader(Duration::from_secs(10)));
        runtime.0.node_id()
    };
    let persistence = ZonePersistence::open(dir.path(), "root").unwrap();
    let next = {
        let store = RaftStorage::open(persistence.raft_path()).unwrap();
        let state = store.initial_state_impl().unwrap();
        let next = store.last_index_impl().unwrap() + 1;
        let mut change = ConfChange::default();
        change.set_change_type(ConfChangeType::AddLearnerNode);
        change.node_id = if id == 1 { 2 } else { 1 };
        let mut entry = Entry {
            index: next,
            term: state.hard_state.term,
            data: change.write_to_bytes().unwrap().into(),
            ..Default::default()
        };
        entry.set_entry_type(EntryType::EntryConfChange);
        store.append(&[entry]).unwrap();
        next
    };
    let result = ZoneManager::isolated(dir.path().to_str().unwrap());
    if let Ok(manager) = &result {
        manager.shutdown();
    }
    assert!(
        result.is_err(),
        "isolated root accepted a pending learner admission"
    );
    drop(result);
    let store = RaftStorage::open(persistence.raft_path()).unwrap();
    assert_eq!(store.conf_state().unwrap().voters, vec![id]);
    assert_eq!(store.last_index_impl().unwrap(), next);
}

#[test]
fn isolated_registry_keeps_only_its_local_root() {
    let dir = TempDir::new().unwrap();
    let runtime = open(&dir);
    let result =
        runtime
            .0
            .registry()
            .create_zone("another-zone", Vec::new(), &runtime.0.runtime_handle());
    assert!(
        result.is_err(),
        "isolated registry created an additional zone"
    );
    assert!(!dir.path().join("another-zone").exists());
    assert!(runtime
        .0
        .registry()
        .join_zone("root", Vec::new(), false, &runtime.0.runtime_handle())
        .is_err());
    assert!(!dir.path().join("root").exists());
    runtime.0.create_zone("root", Vec::new()).unwrap();
    assert!(runtime
        .0
        .registry()
        .join_zone("root", Vec::new(), false, &runtime.0.runtime_handle())
        .is_err());
}

#[test]
fn isolated_restart_refuses_nonlocal_restored_membership() {
    for case in ["voter", "learner", "outgoing", "learner-next"] {
        let dir = TempDir::new().unwrap();
        let id = {
            let runtime = open(&dir);
            let root = runtime.0.create_zone("root", Vec::new()).unwrap();
            assert!(root.wait_for_leader(Duration::from_secs(10)));
            runtime.0.node_id()
        };
        let peer = if id == 1 { 2 } else { 1 };
        let mut membership = ConfState {
            voters: vec![id],
            ..Default::default()
        };
        match case {
            "voter" => membership.voters.push(peer),
            "learner" => membership.learners.push(peer),
            "outgoing" => membership.voters_outgoing = vec![id, peer],
            "learner-next" => {
                membership.voters_outgoing = vec![id, peer];
                membership.learners_next = vec![peer];
            }
            _ => unreachable!(),
        }
        let persistence = ZonePersistence::open(dir.path(), "root").unwrap();
        {
            let store = RaftStorage::open(persistence.raft_path()).unwrap();
            store.set_conf_state(&membership).unwrap();
        }
        let result = ZoneManager::isolated(dir.path().to_str().unwrap());
        if let Ok(manager) = &result {
            manager.shutdown();
        }
        assert!(
            result.is_err(),
            "isolated root accepted restored {case} membership"
        );
        drop(result);
        let store = RaftStorage::open(persistence.raft_path()).unwrap();
        assert_eq!(store.conf_state().unwrap(), membership);
    }
}
