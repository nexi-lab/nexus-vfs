//! Storage-authority acceptance using the real Raft actor and persistent store.

use super::*;
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::meta_store::ConditionalMetadata;

const OWNER: &str = "/sessions/session-a/lifetime";
const HISTORY: &str = "/sessions/session-a/history";
const COMPLETION: &str = "/sessions/session-a/completion";
const ACK: &str = "/sessions/session-a/ack";

fn admit(store: &ZoneMetaStore) -> Vec<u8> {
    store.put(OWNER, image("live-owner")).unwrap();
    let owner = protected(store, OWNER).unwrap();
    store
        .put(
            HISTORY,
            FileMetadata {
                entry_type: kernel::meta_store::DT_STREAM,
                ..Default::default()
            },
        )
        .unwrap();
    let history = store.get(HISTORY).unwrap().unwrap();
    store
        .bind_record_guard(HISTORY, Some(&history), OWNER, &owner.version)
        .unwrap();
    for record in [COMPLETION, ACK] {
        store
            .bind_record_guard(record, None, OWNER, &owner.version)
            .unwrap();
    }
    owner.version
}

#[test]
fn prepared_history_completion_and_ack_cannot_commit_after_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    let prepared = image("prepared-before-delete");
    assert_eq!(
        store
            .append_guarded_record(HISTORY, b"completed-turn", &handle)
            .unwrap(),
        0
    );
    assert!(matches!(
        store
            .replace_guarded_record(COMPLETION, image("completed"), None, &handle)
            .unwrap(),
        ConditionalMetadataResult::Committed { .. }
    ));
    let completion = store.read_versioned(COMPLETION).unwrap().unwrap();
    let terminal = store
        .retire_record_guard(OWNER, image("deleted"), &handle)
        .unwrap();
    let ConditionalMetadataResult::Committed {
        version: terminal_version,
    } = terminal
    else {
        panic!("retirement must commit");
    };

    assert!(store
        .append_guarded_record(HISTORY, b"old-runtime-reconnected", &handle)
        .is_err());
    assert!(store
        .replace_guarded_record(COMPLETION, prepared, Some(&completion.version), &handle)
        .is_err());
    assert!(store
        .replace_guarded_record(ACK, image("late-ack"), None, &handle)
        .is_err());
    assert!(store
        .bind_record_guard("/sessions/session-a/new-writer", None, OWNER, &handle)
        .is_err());
    assert!(store
        .bind_record_guard(
            "/sessions/session-a/new-writer",
            None,
            OWNER,
            &terminal_version
        )
        .is_err());
    assert!(matches!(
        store.replace_if_version(OWNER, image("resurrected"), Some(&terminal_version)),
        Err(kernel::meta_store::ConditionalMetadataError::Failed(_))
    ));
    assert!(store.delete(OWNER).is_err());
    assert!(store.put(OWNER, image("resurrected")).is_err());
    assert_eq!(
        store
            .read_versioned(OWNER)
            .unwrap()
            .unwrap()
            .metadata
            .content_id
            .as_deref(),
        Some("deleted")
    );
    assert_eq!(store.stream_tail(&wal_stream_prefix(HISTORY)).unwrap(), 1);
    assert_eq!(
        store.read_versioned(COMPLETION).unwrap().unwrap().version,
        completion.version
    );
    assert!(store.read_versioned(ACK).unwrap().is_none());

    // Retiring one Session does not prevent an unrelated owner from writing.
    store
        .put("/independent-file", image("still-writable"))
        .unwrap();
}

#[test]
fn legacy_wal_and_conditional_writers_cannot_bypass_an_admitted_guard() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    assert!(store
        .append_stream_entry(&wal_stream_prefix(HISTORY), b"unguarded")
        .is_err());
    assert!(matches!(
        store.replace_if_version(ACK, image("unguarded"), None),
        Err(kernel::meta_store::ConditionalMetadataError::Failed(_))
    ));
    assert!(store.delete(HISTORY).is_err());
    assert!(store
        .rename_path("/sessions/session-a", "/renamed", false)
        .is_err());
    assert_eq!(
        store
            .append_guarded_record(HISTORY, b"admitted", &handle)
            .unwrap(),
        0
    );
    for _ in 1..12 {
        store
            .append_guarded_record(HISTORY, b"retained", &handle)
            .unwrap();
    }
    assert!(store
        .append_stream_entry(
            &format!("{}1", wal_stream_prefix(HISTORY)),
            b"overwrite-seq-10"
        )
        .is_err());
    assert_eq!(
        store
            .get_stream_entry(&format!("{}10", wal_stream_prefix(HISTORY)))
            .unwrap()
            .unwrap(),
        b"retained"
    );
    // Other streams retain their ordinary append contract.
    assert_eq!(
        store
            .append_stream_entry(&wal_stream_prefix("/other-stream"), b"ordinary")
            .unwrap(),
        0
    );
}

#[test]
fn reconnect_after_restart_preserves_retirement_and_all_committed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let prior = std::env::var_os("NEXUS_RECORD_GUARD_PRIOR_BINARY")
        .map(|binary| PreviousReader::initialize(directory.path(), binary));
    let handle;
    {
        let runtime = Runtime::open(&data);
        let store = runtime.store("/", "/");
        handle = admit(&store);
        store
            .append_guarded_record(HISTORY, b"before-restart", &handle)
            .unwrap();
        store
            .retire_record_guard(OWNER, image("deleted"), &handle)
            .unwrap();
    }
    if let Some(prior) = prior {
        prior.assert_refuses();
    }
    let runtime = Runtime::open(&data);
    let store = runtime.store("/", "/");
    assert!(store
        .append_guarded_record(HISTORY, b"reconnected", &handle)
        .is_err());
    assert!(store
        .append_stream_entry(&wal_stream_prefix(HISTORY), b"legacy")
        .is_err());
    assert!(store
        .replace_guarded_record(ACK, image("reconnected-ack"), None, &handle)
        .is_err());
    assert_eq!(
        store
            .get_stream_entry(&format!("{}0", wal_stream_prefix(HISTORY)))
            .unwrap()
            .unwrap(),
        b"before-restart"
    );
    assert_eq!(store.stream_tail(&wal_stream_prefix(HISTORY)).unwrap(), 1);
    assert_eq!(
        store
            .read_versioned(OWNER)
            .unwrap()
            .unwrap()
            .metadata
            .content_id
            .as_deref(),
        Some("deleted")
    );
}

/// CI supplies the digest-verified official rc.5 reader. Local core tests can
/// run without that external artifact; full reader acceptance supplies it too.
struct PreviousReader {
    binary: std::ffi::OsString,
    root: std::path::PathBuf,
}

struct ReaderProcess {
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Drop for ReaderProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl PreviousReader {
    fn initialize(root: &std::path::Path, binary: std::ffi::OsString) -> Self {
        use lib::transport_primitives::{user_runtime_server_name, AgentCredential};
        use nexus_raft::transport::{generate_user_runtime_cert, generate_zone_ca};

        let credential = root.join("prior-reader-credential");
        std::fs::create_dir(&credential).unwrap();
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert, key) =
            generate_user_runtime_cert("prior-reader", "alice", 300, &ca, &ca_key).unwrap();
        std::fs::write(credential.join("ca.pem"), ca).unwrap();
        std::fs::write(credential.join("agent.pem"), cert).unwrap();
        std::fs::write(credential.join("agent-key.pem"), key).unwrap();
        let mut manifest = AgentCredential::for_bundle("prior-reader");
        manifest.server_name = user_runtime_server_name("alice").unwrap();
        manifest.write_to(&credential).unwrap();
        let reader = Self {
            binary,
            root: root.to_path_buf(),
        };
        // Let the actual product create its owner binding and original store.
        // This also proves the credentials and filesystem support are valid
        // before an upgraded format becomes the reason for its later refusal.
        let mut process = reader.spawn("baseline");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let output = std::fs::read_to_string(&process.log).unwrap();
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "previous reader baseline failed: {output}"
            );
            if output.contains("confined user runtime ready") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "previous reader baseline did not become ready: {output}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(process);
        reader
    }

    fn spawn(&self, label: &str) -> ReaderProcess {
        let log_path = self.root.join(format!("prior-reader-{label}.log"));
        let log = std::fs::File::create(&log_path).unwrap();
        let mut command = std::process::Command::new(&self.binary);
        command.env_clear().env("RUST_LOG", "info");
        for name in [
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let data = self.root.join("data");
        let child = command
            .current_dir(&data)
            .arg("--data-dir")
            .arg(&data)
            .args([
                "--bind-addr",
                "127.0.0.1:0",
                "serve-user",
                "--owner",
                "alice",
                "--credential",
            ])
            .arg(self.root.join("prior-reader-credential"))
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        ReaderProcess {
            child,
            log: log_path,
        }
    }

    fn assert_refuses(&self) {
        let mut process = self.spawn("retired");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = process.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "previous reader did not refuse guarded storage before serving"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let output = std::fs::read_to_string(&process.log).unwrap();
        eprintln!("Official previous-reader refusal ({}): {output}", status);
        assert!(
            !status.success(),
            "old reader unexpectedly accepted guarded storage"
        );
        assert!(
            output.contains("invalid protected metadata policy"),
            "unexpected refusal: {output}"
        );
        assert!(
            !output.contains("confined user runtime ready"),
            "old reader served unsupported storage"
        );
    }
}

#[test]
fn racing_writers_and_retirement_share_one_commit_order() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = Arc::new(runtime.store("/", "/"));
    let handle = admit(&store);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for writer in 0..2 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let handle = handle.clone();
        workers.push(std::thread::spawn(move || {
            let first = format!("{writer}:admitted");
            let offset = store
                .append_guarded_record(HISTORY, first.as_bytes(), &handle)
                .unwrap();
            let mut committed = vec![(offset, first)];
            barrier.wait();
            for sequence in 0..32 {
                let bytes = format!("{writer}:{sequence}");
                match store.append_guarded_record(HISTORY, bytes.as_bytes(), &handle) {
                    Ok(offset) => committed.push((offset, bytes)),
                    Err(_) => break,
                }
            }
            committed
        }));
    }
    barrier.wait();
    store
        .retire_record_guard(OWNER, image("deleted"), &handle)
        .unwrap();
    let mut committed: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    committed.sort_by_key(|(offset, _)| *offset);
    assert_eq!(
        store.stream_tail(&wal_stream_prefix(HISTORY)).unwrap(),
        committed.len() as u64
    );
    for (expected, (offset, bytes)) in committed.iter().enumerate() {
        assert_eq!(*offset, expected as u64);
        assert_eq!(
            store
                .get_stream_entry(&format!("{}{offset}", wal_stream_prefix(HISTORY)))
                .unwrap()
                .unwrap(),
            bytes.as_bytes()
        );
    }
    assert!(store
        .append_guarded_record(HISTORY, b"after-retirement-returned", &handle)
        .is_err());
}

#[test]
fn snapshot_and_later_adoption_preserve_the_required_reader_format() {
    use nexus_raft::raft::{GuardedRecordMutation, MembershipPolicy};

    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    store
        .retire_record_guard(OWNER, image("deleted"), &handle)
        .unwrap();
    // A later use of the older conditional-only feature cannot downgrade the
    // required reader format and reopen the database to an unsupported reader.
    assert!(protected(&store, "/later-adoption").is_none());
    let node = runtime.0.get_zone("root").unwrap().consensus_node().clone();
    let snapshot = runtime
        .0
        .runtime_handle()
        .block_on(node.with_state_machine(|state| {
            assert_eq!(
                state
                    .get_control_state("content-version-v1", "requires:protected-records-v1")
                    .unwrap()
                    .as_deref(),
                Some(b"guarded-records-v1".as_slice())
            );
            state.snapshot()
        }))
        .unwrap();
    let destination = tempfile::tempdir().unwrap();
    let database = RedbStore::open(destination.path().join("restored.redb")).unwrap();
    let mut restored = FullStateMachine::new(&database).unwrap();
    assert!(restored
        .validate_snapshot_membership(&snapshot, MembershipPolicy::Managed)
        .is_err());
    restored
        .validate_snapshot_membership(&snapshot, MembershipPolicy::FixedLocal)
        .unwrap();
    restored.restore_snapshot(&snapshot).unwrap();
    assert!(restored
        .validate_membership_policy(MembershipPolicy::Managed)
        .is_err());
    let next = restored.last_applied_index() + 1;
    assert!(matches!(
        restored
            .apply(
                next,
                &Command::GuardedRecord {
                    guard_version: handle,
                    mutation: GuardedRecordMutation::Append {
                        stream_prefix: wal_stream_prefix(HISTORY),
                        data: b"restored-old-writer".to_vec()
                    },
                }
            )
            .unwrap(),
        CommandResult::Error(_)
    ));
    assert!(matches!(
        restored
            .apply(
                next + 1,
                &Command::DeleteControlState {
                    namespace: "content-version-v1".into(),
                    key: format!("retired-guard:{OWNER}"),
                }
            )
            .unwrap(),
        CommandResult::Error(_)
    ));
}

#[test]
fn aliases_share_one_guard_and_records_cannot_move_to_another_owner() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let alias = runtime.store("/view", "/sessions/session-a");
    let handle = admit(&store);
    assert_eq!(
        alias
            .append_guarded_record("/view/history", b"same-log", &handle)
            .unwrap(),
        0
    );
    store
        .put("/other-owner", image("independent-owner"))
        .unwrap();
    let other = protected(&store, "/other-owner").unwrap();
    let history = store.get(HISTORY).unwrap().unwrap();
    assert!(store
        .bind_record_guard(HISTORY, Some(&history), "/other-owner", &other.version)
        .is_err());
    alias
        .retire_record_guard("/view/lifetime", image("deleted"), &handle)
        .unwrap();
    assert!(alias
        .append_guarded_record("/view/history", b"old-alias", &handle)
        .is_err());
    assert!(store
        .bind_record_guard(HISTORY, Some(&history), "/other-owner", &other.version)
        .is_err());
    assert_eq!(store.stream_tail(&wal_stream_prefix(HISTORY)).unwrap(), 1);
}

#[test]
fn a_changed_admission_image_publishes_neither_binding_nor_write_policy() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    let path = "/candidate";
    store.put(path, image("qualified-old-image")).unwrap();
    let expected = store.get(path).unwrap().unwrap();
    store.put(path, image("concurrent-change")).unwrap();
    assert!(store
        .bind_record_guard(path, Some(&expected), OWNER, &handle)
        .is_err());
    store.put(path, image("still-ordinary")).unwrap();
    store
        .retire_record_guard(OWNER, image("deleted"), &handle)
        .unwrap();
    store.put(path, image("independently-writable")).unwrap();
    assert_eq!(
        store.get(path).unwrap().unwrap().content_id.as_deref(),
        Some("independently-writable")
    );
}

#[test]
fn an_owner_cannot_become_a_child_and_a_child_cannot_admit_another_record() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::open(directory.path());
    let store = runtime.store("/", "/");
    let handle = admit(&store);
    store.put("/other-owner", image("other-owner")).unwrap();
    let other = protected(&store, "/other-owner").unwrap();
    let owner = store.get(OWNER).unwrap().unwrap();
    assert!(store
        .bind_record_guard(OWNER, Some(&owner), "/other-owner", &other.version)
        .is_err());
    let child = store.read_versioned(HISTORY).unwrap().unwrap();
    assert!(store
        .bind_record_guard("/cycle", None, HISTORY, &child.version)
        .is_err());
    // Both refused role changes preserve the original owner's ability to retire.
    store
        .retire_record_guard(OWNER, image("deleted"), &handle)
        .unwrap();
    assert!(store
        .append_guarded_record(HISTORY, b"after-retirement", &handle)
        .is_err());
    store.put("/cycle", image("no-partial-admission")).unwrap();
}
