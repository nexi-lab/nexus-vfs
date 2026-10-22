//! A lock on a shared subtree must contend across nodes and mount aliases,
//! while node-local root locks and other subtrees stay independent.
mod common;

use std::time::Duration;

use common::{cli, free_port, Daemon, Vfs, LOG_FILTER};

const BUDGET: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_receiver_has_one_holder_across_nodes_and_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let fdata = temp
        .path()
        .join("founder-data")
        .to_string_lossy()
        .into_owned();
    let fid = temp
        .path()
        .join("founder-id")
        .to_string_lossy()
        .into_owned();
    let jdata = temp
        .path()
        .join("joiner-data")
        .to_string_lossy()
        .into_owned();
    let jid = temp.path().join("joiner-id").to_string_lossy().into_owned();
    let fp = free_port();
    let jp = free_port();
    let faddr = format!("127.0.0.1:{fp}");
    let jaddr = format!("127.0.0.1:{jp}");
    let fenv = [
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", faddr.as_str()),
        ("NEXUS_CLUSTER_INIT", "sharedzone"),
        ("NEXUS_CLUSTER_INIT_MOUNTS", "/alias=sharedzone"),
        ("NEXUS_NO_TLS", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let jenv = [
        ("NEXUS_DATA_DIR", jdata.as_str()),
        ("NEXUS_IDENTITY_DIR", jid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", jaddr.as_str()),
        ("NEXUS_PEERS", faddr.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut founder = Daemon::spawn(&["--bind-addr", &faddr], &fenv);
    founder
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let (ok, _, err) = cli(
        &jenv,
        &[
            "join",
            &faddr,
            "sharedzone",
            "/sharedzone",
            "--as",
            "learner",
        ],
    );
    assert!(ok, "learner prejoin: {err}");
    let mut joiner = Daemon::spawn(&["--bind-addr", &jaddr], &jenv);
    joiner
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .unwrap();
    let mut f = Vfs::dial_ready(fp, BUDGET).await;
    let mut j = Vfs::dial_ready(jp, BUDGET).await;

    let path = "/agents/worker/receiver";
    let alias = "/alias/agents/worker/receiver";
    let holder = f.try_lock(path, "", 60_000).await.unwrap().unwrap();
    assert_eq!(
        j.try_lock(path, "", 60_000).await.unwrap(),
        None,
        "a second node must not acquire its own root-zone copy of the shared lock"
    );
    assert_eq!(
        j.try_lock(alias, "", 60_000).await.unwrap(),
        None,
        "another spelling of the same shared subtree must contend"
    );
    assert_eq!(
        j.try_lock(alias, &holder, 60_000).await.unwrap(),
        Some(holder.clone()),
        "renew must resolve the same domain and key as acquire"
    );

    // These prefixes expose different subtrees of ONE shared zone. Stripping
    // just the mount prefix would collapse both onto /worker/receiver.
    assert!(j
        .try_lock("/conversations/worker/receiver", "", 60_000)
        .await
        .unwrap()
        .is_some());

    assert!(j.unlock(alias, &holder).await.unwrap());
    let successor = j.try_lock(path, "", 60_000).await.unwrap().unwrap();
    assert_eq!(f.try_lock(alias, "", 60_000).await.unwrap(), None);
    assert_eq!(
        f.try_lock(path, &holder, 60_000).await.unwrap(),
        None,
        "the released holder cannot renew after takeover"
    );
    assert!(f.unlock(alias, &successor).await.unwrap());

    // Each daemon's SOLO root remains its own coordination domain.
    assert!(f
        .try_lock("/node-private/seat", "", 60_000)
        .await
        .unwrap()
        .is_some());
    assert!(j
        .try_lock("/node-private/seat", "", 60_000)
        .await
        .unwrap()
        .is_some());
}
