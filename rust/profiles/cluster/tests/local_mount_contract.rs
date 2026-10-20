//! Explicit local mounts place durable bytes in the requested host directory.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};
use kernel::kernel::vfs_proto::SetattrRequest;

const BUDGET: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_mount_uses_requested_directory_and_survives_process_restart() {
    let temporary = tempfile::tempdir().expect("test directory");
    let data = temporary.path().join("data");
    let identity = temporary.path().join("identity");
    let backing = temporary.path().join("真实目录");
    let address = format!("127.0.0.1:{}", free_port());
    let data_path = data.to_str().unwrap();
    let identity_path = identity.to_str().unwrap();
    let env = [
        ("NEXUS_DATA_DIR", data_path),
        ("NEXUS_IDENTITY_DIR", identity_path),
        ("NEXUS_ADVERTISE_ADDR", address.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let port = address.rsplit_once(':').unwrap().1.parse().unwrap();
    let expected: Vec<u8> = (0..=255).collect();

    for turn in 0..2 {
        let mut daemon = Daemon::spawn(&["--bind-addr", &address], &env);
        daemon
            .wait_for_log("VFS data plane ready", BUDGET)
            .await
            .expect("daemon serves");
        let mut client = Vfs::connect_serving(port, BUDGET).await;

        if turn == 0 {
            client
                .write_file("/seed.bin", b"existing root", "")
                .await
                .unwrap();
            for path in ["/", "/missing-root"] {
                let response = client
                    .setattr_raw(SetattrRequest {
                        path: path.into(),
                        entry_type: 2,
                        backend_type: "path_local".into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert!(response.is_error, "missing root was accepted: {response:?}");
                assert!(!response.created);
            }
            assert!(!client.stat_found("/missing-root", "").await);
        }
        assert_eq!(
            client.read_file("/seed.bin", "").await.unwrap(),
            b"existing root"
        );

        let response = client
            .setattr_raw(SetattrRequest {
                path: "/workspace".into(),
                entry_type: 2,
                backend_name: "local".into(),
                backend_type: "path_local".into(),
                backend_params: HashMap::from([
                    ("local_root".into(), backing.to_str().unwrap().into()),
                    ("fsync".into(), "true".into()),
                ]),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!response.is_error, "mount failed: {response:?}");
        assert!(response.created);
        if turn == 0 {
            client
                .write_file("/workspace/二进制.bin", &expected, "")
                .await
                .unwrap();
        }
        assert_eq!(
            client.read_file("/workspace/二进制.bin", "").await.unwrap(),
            expected
        );
        assert_eq!(std::fs::read(backing.join("二进制.bin")).unwrap(), expected);
        assert!(!data.join("rootfs/workspace/二进制.bin").exists());
        // Dropping the harness kills and waits for the actual daemon.
    }
}
