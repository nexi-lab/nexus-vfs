//! Three separate mTLS members, independent Raft disks, and a shared immutable
//! content store. The publisher is killed before it receives a committed rename.
#![cfg(feature = "driver-cas-local")]

use backends::storage::cas_local::CasLocalBackend;
use kernel::abc::object_store::ObjectStore;
use kernel::kernel::{Kernel, OperationContext, ReadRequest};
use kernel::meta_store::{FileMetadata, MetaStore};
use nexus_raft::{
    raft::{Command, RaftStorage, ZoneRaftRegistry},
    transport::{generate_node_cert, generate_zone_ca, RaftGrpcServer, ServerConfig, TlsConfig},
    zone_meta_store::ZoneMetaStore,
};
use serde_json::{json, Value};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as Process, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ZONE: &str = "ns-rename";
const SOURCE: &str = "/old";
const TARGET: &str = "/new";
const BODY: &[u8] = b"immutable namespace fixture";
const BUDGET: Duration = Duration::from_secs(30);

fn publish(path: &Path, value: &Value) {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec(value).unwrap()).unwrap();
    fs::rename(tmp, path).unwrap();
}

fn wait(path: &Path) -> Value {
    let stop = Instant::now() + BUDGET;
    loop {
        if let Ok(bytes) = fs::read(path) {
            return serde_json::from_slice(&bytes).unwrap();
        }
        if Instant::now() >= stop {
            let dir = path.parent().unwrap();
            let root = if dir.join("1").is_dir() {
                dir
            } else {
                dir.parent().unwrap()
            };
            for id in 1..=4 {
                let log = fs::read_to_string(root.join(id.to_string()).join("child.log"))
                    .unwrap_or_default();
                eprintln!(
                    "member {id}: {}",
                    log.lines().rev().take(10).collect::<Vec<_>>().join(" | ")
                );
            }
            panic!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Member {
    dir: PathBuf,
    seq: u32,
    process: Option<Child>,
}

impl Member {
    fn start(&mut self) {
        let log = fs::File::create(self.dir.join("child.log")).unwrap();
        self.process = Some(
            Process::new(std::env::current_exe().unwrap())
                .args(["--exact", "namespace_member", "--ignored", "--nocapture"])
                .env("NEXUS_SC_SNAPSHOT_THRESHOLD", "2")
                .env("NEXUS_NAMESPACE_FIXTURE", &self.dir)
                .env("NEXUS_FIXTURE_SEQUENCE", self.seq.to_string())
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
    }
    fn submit(&mut self, op: &str) -> PathBuf {
        self.seq += 1;
        publish(&self.dir.join(format!("request-{}", self.seq)), &json!(op));
        self.dir.join(format!("reply-{}", self.seq))
    }
    fn call(&mut self, op: &str) -> Value {
        let path = self.submit(op);
        let result = wait(&path);
        assert!(result.get("error").is_none(), "{op}: {result}");
        result
    }
    fn stopped_log(&self) -> RaftStorage {
        assert!(self.process.is_none());
        RaftStorage::open(self.dir.join(ZONE).join("raft")).unwrap()
    }
    fn kill(&mut self) {
        if let Some(mut p) = self.process.take() {
            p.kill().unwrap();
            p.wait().unwrap();
        }
    }
}
impl Drop for Member {
    fn drop(&mut self) {
        self.kill();
    }
}

#[test]
fn committed_follower_rename_survives_lost_reply_and_cold_reopen() {
    let base = tempfile::tempdir().unwrap();
    let (ca, key) = generate_zone_ca("root").unwrap();
    let listeners: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();
    drop(listeners);
    let mut members: Vec<_> = (1..=4)
        .map(|id| {
            let dir = base.path().join(id.to_string());
            let raft = dir.join(ZONE).join("raft");
            fs::create_dir_all(&raft).unwrap();
            let mut store = RaftStorage::open(raft).unwrap();
            store.initialize_atomic_namespace().unwrap();
            let mut conf = store.initial_state_impl().unwrap().conf_state;
            conf.voters = vec![1, 2, 3];
            conf.learners = vec![4];
            store.set_conf_state(&conf).unwrap();
            let (cert, secret) = generate_node_cert(id, "root", &ca, &key, &[], None).unwrap();
            fs::write(dir.join("ca"), &ca).unwrap();
            fs::write(dir.join("cert"), cert).unwrap();
            fs::write(dir.join("key"), secret).unwrap();
            publish(&dir.join("addresses"), &json!(addresses));
            Member {
                dir,
                seq: 0,
                process: None,
            }
        })
        .collect();
    for m in &mut members[..3] {
        m.start();
    }
    let leader = members[0].call("leader").as_u64().unwrap() as usize - 1;
    let reader = (leader + 1) % 3;
    let origin = (leader + 2) % 3;
    members[leader].call("seed");
    members[3].start();
    members[3].call("leader");
    assert_eq!(members[3].call("read_old"), json!(BODY));
    members[3].call("check_writer_protocol");
    members[3].call("write_progress");
    assert_eq!(members[leader].call("read_old"), json!(BODY));
    members[3].kill();
    let learner_next = members[3].stopped_log().last_index_impl().unwrap() + 1;
    assert_eq!(members[origin].call("read_old"), json!(BODY));
    let views = members[reader].submit("watch");
    for _ in 0..12 {
        members[origin].call("forward");
        members[origin].call("back");
    }
    publish(&base.path().join("stop-watching"), &json!(true));
    let observed = wait(&views);
    assert!(
        observed["old"].as_u64().unwrap() > 0 && observed["new"].as_u64().unwrap() > 0,
        "{observed}"
    );
    members[leader].call("arm");
    let missing_reply = members[origin].submit("forward");
    wait(&base.path().join("committed"));
    assert!(!missing_reply.exists(), "publisher already returned");
    members[origin].kill();
    assert!(members[origin].stopped_log().first_index_impl().unwrap() > learner_next);
    publish(&base.path().join("release"), &json!(true));
    assert_eq!(members[reader].call("names"), json!([TARGET]));
    assert_eq!(members[reader].call("read_new"), json!(BODY));
    members[reader].call("write_progress");
    members[origin].start();
    assert_eq!(members[origin].call("names"), json!([TARGET]));
    assert_eq!(members[origin].call("read_new"), json!(BODY));
    members[leader].kill();
    members[reader].kill();
    for voter in [reader, leader] {
        assert!(members[voter].stopped_log().first_index_impl().unwrap() > learner_next);
    }
    let stranded = wait(&members[origin].submit("back"));
    assert!(
        stranded.get("error").is_some(),
        "minority acknowledged a rename: {stranded}"
    );
    members[reader].start();
    members[leader].start();
    let _ = members[origin].call("leader");
    let after = members[origin].call("names");
    assert!(
        after == json!([SOURCE]) || after == json!([TARGET]),
        "{after}"
    );
    assert_eq!(members[reader].call("names"), after);
    assert_eq!(
        members[reader].call(if after == json!([SOURCE]) {
            "read_old"
        } else {
            "read_new"
        }),
        json!(BODY)
    );
    // Every possible leader has compacted beyond this learner's next entry.
    members[3].start();
    members[3].call("leader");
    assert_eq!(members[3].call("names"), after);
    let path = if after == json!([SOURCE]) {
        "read_old"
    } else {
        "read_new"
    };
    assert_eq!(members[3].call(path), json!(BODY));
    members[3].call("write_progress");
    eprintln!("Minority returned no success; quorum recovered one complete name: {after}.");
    eprintln!("24 follower renames, {observed} quorum views, publisher killed before receipt; surviving majority and reopened publisher read exact bytes");
}

#[test]
#[ignore = "subprocess member of the three-voter fixture"]
fn namespace_member() {
    let dir = PathBuf::from(std::env::var_os("NEXUS_NAMESPACE_FIXTURE").unwrap());
    let seq: u32 = std::env::var("NEXUS_FIXTURE_SEQUENCE")
        .unwrap()
        .parse()
        .unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run_member(dir, seq));
}

async fn run_member(dir: PathBuf, mut seq: u32) {
    let id: u64 = dir.file_name().unwrap().to_str().unwrap().parse().unwrap();
    let addresses: Vec<String> =
        serde_json::from_slice(&fs::read(dir.join("addresses")).unwrap()).unwrap();
    let tls = TlsConfig {
        ca_pem: fs::read(dir.join("ca")).unwrap(),
        cert_pem: fs::read(dir.join("cert")).unwrap(),
        key_pem: fs::read(dir.join("key")).unwrap(),
    };
    let registry = Arc::new(ZoneRaftRegistry::with_tls(
        dir.clone(),
        id,
        Some(tls.clone()),
    ));
    let rt = tokio::runtime::Handle::current();
    registry.create_zone("root", &rt).unwrap();
    let addr = &addresses[id as usize - 1];
    registry.set_self_address(addr.clone());
    let node = registry.open_persisted_zone(ZONE, &rt).unwrap();
    for (i, a) in addresses.iter().enumerate() {
        if i as u64 + 1 != id {
            registry.learn_peer_address(ZONE, i as u64 + 1, a);
        }
    }
    let server = RaftGrpcServer::new(
        registry.clone(),
        ServerConfig {
            bind_address: addr.parse().unwrap(),
            tls: Some(tls.clone()),
            ..Default::default()
        },
    );
    tokio::spawn(async move {
        server
            .serve_with_shutdown(std::future::pending())
            .await
            .unwrap()
    });
    let base = dir.parent().unwrap();
    let backend = Arc::new(CasLocalBackend::new(&base.join("objects"), true).unwrap());
    let store = Arc::new(ZoneMetaStore::new(node.clone(), rt.clone(), "/".into()));
    let kernel = Kernel::new();
    kernel
        .vfs_router_arc()
        .add_mount("/", ZONE, Some(backend.clone()), false);
    kernel.install_mount_metastore(Kernel::canonical_mount_key("/", ZONE), store.clone());
    let ctx = OperationContext::new("test", ZONE, true, None, true);
    let mut observer = None;
    loop {
        seq += 1;
        let cmd = dir.join(format!("request-{seq}"));
        let idle_deadline = Instant::now() + 3 * BUDGET;
        while !cmd.exists() {
            if Instant::now() >= idle_deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let op: String = serde_json::from_slice(&fs::read(cmd).unwrap()).unwrap();
        let names = || {
            node.read_linearizable(|state| {
                state
                    .list_metadata("/")
                    .unwrap()
                    .into_iter()
                    .filter_map(|(k, _)| (k == SOURCE || k == TARGET).then_some(k))
                    .collect::<Vec<_>>()
            })
        };
        let result = match op.as_str() {
            "leader" => {
                let until = Instant::now() + BUDGET;
                loop {
                    if let Some(leader) = node.leader_id() {
                        if node.read_linearizable(|_| ()).await.is_ok() {
                            break json!(leader);
                        }
                    }
                    assert!(Instant::now() < until);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            "seed" => {
                let blob = backend.write_content(BODY, SOURCE, &ctx, 0).unwrap();
                store
                    .put(
                        SOURCE,
                        FileMetadata {
                            path: SOURCE.into(),
                            content_id: Some(blob.content_id),
                            size: blob.size,
                            zone_id: Some(ZONE.into()),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                json!(true)
            }
            "forward" | "back" => {
                let (s, d) = if op == "forward" {
                    (SOURCE, TARGET)
                } else {
                    (TARGET, SOURCE)
                };
                match kernel.sys_rename(s, d, &ctx) {
                    Ok(r) if r.hit && r.success => json!(true),
                    r => json!({"error":format!("{r:?}")}),
                }
            }
            "read_old" | "read_new" => {
                node.read_linearizable(|_| ()).await.unwrap();
                let path = if op == "read_old" { SOURCE } else { TARGET };
                let result = kernel
                    .sys_read(
                        &[ReadRequest {
                            path: path.into(),
                            offset: 0,
                            len: None,
                            timeout_ms: 0,
                        }],
                        &ctx,
                    )
                    .pop()
                    .unwrap()
                    .unwrap();
                json!(result.data.unwrap())
            }
            "write_progress" => {
                node.propose(Command::SetMetadata {
                    key: "/progress".into(),
                    value: vec![1],
                })
                .await
                .unwrap();
                json!(true)
            }
            "check_writer_protocol" => {
                use nexus_raft::transport::proto::{
                    raft_command, zone_api_service_client::ZoneApiServiceClient, DeleteMetadata,
                    ProposeRequest, RaftCommand,
                };
                use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
                let leader = node.leader_id().unwrap() as usize - 1;
                let channel = Endpoint::from_shared(format!("https://{}", addresses[leader]))
                    .unwrap()
                    .tls_config(
                        ClientTlsConfig::new()
                            .domain_name(TlsConfig::CLUSTER_SERVER_NAME)
                            .ca_certificate(Certificate::from_pem(&tls.ca_pem))
                            .identity(Identity::from_pem(&tls.cert_pem, &tls.key_pem)),
                    )
                    .unwrap()
                    .connect()
                    .await
                    .unwrap();
                let mut api = ZoneApiServiceClient::new(channel);
                let delete = Command::DeleteMetadata { key: SOURCE.into() };
                for forwarded in [false, true] {
                    for raw in [false, true] {
                        let mut req = ProposeRequest {
                            zone_id: ZONE.into(),
                            forwarded,
                            ..Default::default()
                        };
                        if raw {
                            req.raw_command = bincode::serialize(&delete).unwrap();
                        } else {
                            req.command = Some(RaftCommand {
                                command: Some(raft_command::Command::DeleteMetadata(
                                    DeleteMetadata {
                                        path: SOURCE.into(),
                                        zone_id: ZONE.into(),
                                    },
                                )),
                            });
                        }
                        let refusal = api.propose(req).await.unwrap_err();
                        assert_eq!(refusal.code(), tonic::Code::FailedPrecondition);
                    }
                }
                let before = node.ec_wal_bounds();
                assert!(before.is_none());
                assert!(node.propose_ec_local(delete.clone()).await.is_err());
                assert_eq!(node.ec_wal_bounds(), before);
                assert!(node.apply_ec_from_peer(delete, u64::MAX).await.is_err());
                assert_eq!(names().await.unwrap(), [SOURCE]);
                json!(true)
            }
            "arm" => {
                let anchor = base.to_owned();
                observer = Some(
                    node.subscribe_apply_observer(move |event| {
                        if matches!(event.command, Command::RenameNamespaceV1 { .. }) {
                            publish(&anchor.join("committed"), &json!(true));
                            wait(&anchor.join("release"));
                        }
                    })
                    .unwrap(),
                );
                json!(true)
            }
            "names" => json!(names().await.unwrap()),
            "watch" => {
                let (mut old, mut new) = (0, 0);
                let until = Instant::now() + 3 * BUDGET;
                loop {
                    assert!(Instant::now() < until, "observer timed out");
                    let v = names().await.unwrap();
                    assert!(v == [SOURCE] || v == [TARGET], "partial namespace {v:?}");
                    if v == [SOURCE] {
                        old += 1
                    } else {
                        new += 1
                    }
                    if base.join("stop-watching").exists() {
                        break json!({"old":old,"new":new});
                    }
                }
            }
            _ => panic!("unexpected request"),
        };
        std::hint::black_box(&observer);
        publish(&dir.join(format!("reply-{seq}")), &result);
    }
}

#[test]
#[ignore = "release qualification requires a pre-namespace nexusd-cluster executable"]
fn previous_reader_refuses_namespace_disk() {
    let previous = std::env::var_os("NEXUS_PREVIOUS_READER").expect("released executable");
    for namespace in [false, true] {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join(ZONE).join("raft");
        fs::create_dir_all(&dir).unwrap();
        let mut store = RaftStorage::open(dir).unwrap();
        if namespace {
            store.initialize_atomic_namespace().unwrap();
        }
        let mut state = store.initial_state_impl().unwrap().conf_state;
        state.voters = vec![1];
        store.set_conf_state(&state).unwrap();
        drop(store);
        let result = Process::new(&previous)
            .arg("doctor")
            .arg("--data-dir")
            .arg(base.path())
            .args(["--zone", ZONE])
            .env("NEXUS_IDENTITY_DIR", base.path().join("identity"))
            .output()
            .unwrap();
        let report = String::from_utf8(result.stdout).unwrap();
        assert!(report.contains(ZONE), "{report}");
        if namespace {
            assert!(
                report.contains("unsupported Raft log-boundary format") && !result.status.success(),
                "{report}"
            );
        } else {
            assert!(
                report.contains("voters")
                    && !report.contains("unsupported Raft log-boundary format"),
                "{report}"
            );
        }
    }
}
