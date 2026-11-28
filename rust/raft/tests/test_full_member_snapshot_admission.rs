//! Snapshot admission before a full member replaces durable state.
#![cfg(all(feature = "grpc", has_protos))]

use nexus_raft::raft::{
    Command, FullStateMachine, RaftStorage, StateMachine, ZonePersistence, ZoneRaftRegistry,
};
use nexus_raft::storage::RedbStore;
use raft::eraftpb::{ConfState, Snapshot};

fn put(value: &[u8]) -> Command {
    Command::SetMetadata {
        key: "/file".into(),
        value: value.to_vec(),
    }
}

fn full_image(state: &FullStateMachine, conf: &ConfState) -> Snapshot {
    let mut image = Snapshot {
        data: state.snapshot().unwrap().into(),
        ..Default::default()
    };
    let meta = image.mut_metadata();
    meta.index = state.last_applied_index();
    meta.term = 1;
    meta.set_conf_state(conf.clone());
    image
}

#[derive(Clone, Copy, Debug)]
enum InvalidImage {
    Unreadable,
    Empty,
    WrongIndex,
    BeyondCommit,
    MissingAfterCompaction,
    MissingCommittedTail,
}

async fn refused(image: InvalidImage) {
    let root = tempfile::tempdir().unwrap();
    let mut zone = ZonePersistence::create(root.path(), "test").unwrap();
    let sm_path = zone.sm_path();
    let raft_path = zone.raft_path();
    zone.commit();
    let (mut snapshot, conf) = {
        let db = RedbStore::open(&sm_path).unwrap();
        let mut application = FullStateMachine::new(&db).unwrap();
        application.apply(4, &put(b"snapshot body")).unwrap();
        let conf = ConfState {
            voters: vec![1],
            ..Default::default()
        };
        let snap = full_image(&application, &conf);
        application.apply_local(&put(b"preserve me")).unwrap();
        (snap, conf)
    };
    {
        let log = RaftStorage::open(&raft_path).unwrap();
        log.set_conf_state(&conf).unwrap();
        if matches!(image, InvalidImage::WrongIndex) {
            snapshot.mut_metadata().index = 5;
        }
        if matches!(image, InvalidImage::Empty) {
            snapshot.data.clear();
        }
        log.apply_snapshot(&snapshot).unwrap();
        if matches!(
            image,
            InvalidImage::BeyondCommit | InvalidImage::MissingCommittedTail
        ) {
            let mut hs = log.initial_state_impl().unwrap().hard_state;
            hs.commit = if matches!(image, InvalidImage::BeyondCommit) {
                3
            } else {
                5
            };
            log.set_hard_state(&hs).unwrap();
        }
    }
    if matches!(
        image,
        InvalidImage::Unreadable | InvalidImage::MissingAfterCompaction
    ) {
        let db = RedbStore::open(raft_path.join("raft.redb")).unwrap();
        let table = db.tree("raft_state").unwrap();
        if matches!(image, InvalidImage::Unreadable) {
            table.set(b"snapshot", &[0xff]).unwrap();
        } else {
            table.delete(b"snapshot").unwrap();
        }
    }
    let registry = ZoneRaftRegistry::new(root.path().to_path_buf(), 1);
    let opened = registry.open_persisted_zone("test", &tokio::runtime::Handle::current());
    let error = opened.err().map(|e| e.to_string()).unwrap_or_default();
    registry.shutdown().released().await;
    let db = RedbStore::open(sm_path).unwrap();
    let app = FullStateMachine::new(&db).unwrap();
    assert_eq!(
        app.get_metadata("/file").unwrap().as_deref(),
        Some(b"preserve me".as_slice()),
        "{image:?}"
    );
    assert!(
        error.to_ascii_lowercase().contains("snapshot"),
        "{image:?} opened or reported an unrelated error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_stored_snapshot_preserves_working_state() {
    refused(InvalidImage::Unreadable).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_full_member_snapshot_preserves_working_state() {
    refused(InvalidImage::Empty).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_snapshot_index_preserves_working_state() {
    refused(InvalidImage::WrongIndex).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uncommitted_stored_snapshot_preserves_working_state() {
    refused(InvalidImage::BeyondCommit).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_snapshot_after_compaction_preserves_working_state() {
    refused(InvalidImage::MissingAfterCompaction).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_committed_tail_preserves_working_state() {
    refused(InvalidImage::MissingCommittedTail).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_member_checks_the_raft_cut_before_enqueuing_a_snapshot() {
    use nexus_raft::raft::{RaftConfig, ZoneConsensus};
    use raft::eraftpb::{Message, MessageType};

    let root = tempfile::tempdir().unwrap();
    let log = RaftStorage::open(root.path()).unwrap();
    let conf = ConfState {
        voters: vec![1, 2, 3],
        ..Default::default()
    };
    log.set_conf_state(&conf).unwrap();
    let store = RedbStore::open(root.path().join("sm")).unwrap();
    let app = FullStateMachine::new(&store).unwrap();
    let (handle, _driver) = ZoneConsensus::new(
        RaftConfig {
            id: 2,
            skip_bootstrap: true,
            ..Default::default()
        },
        log,
        app,
        None,
    )
    .unwrap();
    let donor = RedbStore::open_temporary().unwrap();
    let mut donor = FullStateMachine::new(&donor).unwrap();
    donor.apply(4, &put(b"sender image")).unwrap();
    let snap = full_image(&donor, &conf);

    let mut message = Message {
        from: 1,
        to: 2,
        term: 1,
        ..Default::default()
    };
    message.set_msg_type(MessageType::MsgSnapshot);
    assert!(handle.step(message.clone()).await.is_err());
    message.set_snapshot(snap.clone());
    message.mut_snapshot().mut_metadata().index = 5;
    assert!(handle.step(message.clone()).await.is_err());
    message.mut_snapshot().data.clear();
    assert!(handle.step(message.clone()).await.is_err());
    message.set_snapshot(snap);
    handle.step(message).await.unwrap();
}
