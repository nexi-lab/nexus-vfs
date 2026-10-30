//! Real CLI + private mTLS founder: exact-target grants, concurrent requests,
//! immutable local replay and Unknown recovery without offline signing.
mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{cli, free_port_pair, Daemon, LOG_FILTER};
use serde_json::{json, Value};

fn request(grant: &Path, claim: &Value) -> Value {
    let mut child = Command::new(common::bin())
        .args(["operator-agent-enroll", "--grant"])
        .arg(grant)
        .env_remove("NEXUS_INSECURE_NO_AUTH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(claim).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "operator failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn claim(actor_digit: char, operation_digit: char, workspace: &Path) -> Value {
    json!({"version":1,"actor":format!("codex-{}",actor_digit.to_string().repeat(32)),
        "operationId":format!("00000000-0000-4000-8000-00000000000{operation_digit}"),
        "threadId":format!("10000000-0000-4000-8000-00000000000{actor_digit}"),"workspace":workspace})
}

async fn ready(daemon: &mut Daemon) {
    daemon
        .wait_for_log("CA holder armed MintAgent RPC", Duration::from_secs(120))
        .await
        .unwrap();
    daemon
        .wait_for_log("Static topology applied", Duration::from_secs(120))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_enrollment_reuses_the_live_minter_and_never_replays_unknown() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let data = root.join("data");
    let identity = root.join("identity");
    let workspace = root.join("project");
    std::fs::create_dir(&workspace).unwrap();
    let port = free_port_pair();
    let address = format!("127.0.0.1:{port}");
    let data_s = data.to_string_lossy();
    let identity_s = identity.to_string_lossy();
    let env = vec![
        ("NEXUS_DATA_DIR", data_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", identity_s.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", address.as_str()),
        ("NEXUS_CLUSTER_INIT", "sharedzone"),
        ("NEXUS_CLUSTER_INIT_MOUNTS", "/agents=sharedzone"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut daemon = Daemon::spawn(&["--bind-addr", &address], &env);
    ready(&mut daemon).await;
    let grant = root.join("grant.json");
    let endpoint = format!("https://{address}");
    let (ok, out, err) = cli(
        &env,
        &[
            "operator-agent-enroll",
            "--initialize",
            "--grant",
            grant.to_str().unwrap(),
            "--endpoint",
            &endpoint,
            "--workspace-root",
            workspace.to_str().unwrap(),
        ],
    );
    assert!(ok, "{out}\n{err}");
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["issued"],
        false
    );
    let policy: Value = serde_json::from_slice(&std::fs::read(&grant).unwrap()).unwrap();
    let state = std::path::PathBuf::from(policy["stateDirectory"].as_str().unwrap());
    assert!(!state.exists(), "preparation performs no issuance");

    let denied = claim('a', '1', &root);
    assert_eq!(request(&grant, &denied)["outcome"], "not_submitted");
    assert!(!state.exists());
    let mut wrong_pin = policy.clone();
    wrong_pin["ownerCertificateSha256"] = json!("0".repeat(64));
    let wrong_grant = root.join("wrong-owner.json");
    std::fs::write(&wrong_grant, serde_json::to_vec(&wrong_pin).unwrap()).unwrap();
    assert_eq!(
        request(&wrong_grant, &claim('a', '1', &workspace))["outcome"],
        "not_submitted"
    );
    let mut forged = claim('a', '1', &workspace);
    forged["owner"] = json!("another-owner");
    assert_eq!(request(&grant, &forged)["outcome"], "not_submitted");
    assert!(!state.exists());

    let first = claim('a', '1', &workspace);
    let receipt = request(&grant, &first);
    assert_eq!(receipt["actor"], first["actor"], "{receipt}");
    let credential = std::path::PathBuf::from(receipt["credentialDirectory"].as_str().unwrap());
    let certificate = std::fs::read(credential.join("agent.pem")).unwrap();
    let key = std::fs::read(credential.join("agent-key.pem")).unwrap();
    assert_eq!(
        request(&grant, &first),
        receipt,
        "same operation replays the committed public receipt"
    );
    assert_eq!(
        std::fs::read(credential.join("agent.pem")).unwrap(),
        certificate
    );
    assert_eq!(
        std::fs::read(credential.join("agent-key.pem")).unwrap(),
        key
    );
    assert_eq!(
        request(&grant, &claim('a', '2', &workspace))["outcome"],
        "unknown"
    );

    let racing = claim('b', '2', &workspace);
    let grant_a = grant.clone();
    let claim_a = racing.clone();
    let winner = std::thread::spawn(move || request(&grant_a, &claim_a));
    let other = request(&grant, &racing);
    let winner = winner.join().unwrap();
    assert!(winner["actor"] == racing["actor"] || other["actor"] == racing["actor"]);
    let selected = request(&grant, &racing);
    for response in [winner, other] {
        assert!(
            response == selected || response["outcome"] == "unknown",
            "{response}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&grant).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(credential.join("agent-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    // The data directory still holds the founder CA key. Even then the new
    // client cannot fall back to local signing when its selected Node is down.
    drop(daemon);
    let uncertain = claim('c', '3', &workspace);
    assert_eq!(request(&grant, &uncertain)["outcome"], "unknown");
    assert!(!data
        .join("agents")
        .join(uncertain["actor"].as_str().unwrap())
        .exists());
    let pending = state.join(format!(
        "{}.attempt.json",
        uncertain["actor"].as_str().unwrap()
    ));
    let original_attempt = std::fs::read(&pending).unwrap();
    let mut daemon = Daemon::spawn(&["--bind-addr", &address], &env);
    ready(&mut daemon).await;
    assert_eq!(
        request(&grant, &uncertain)["outcome"],
        "unknown",
        "recovery never elects a second RPC after the Node returns"
    );
    assert_eq!(std::fs::read(pending).unwrap(), original_attempt);
    assert!(!data
        .join("agents")
        .join(uncertain["actor"].as_str().unwrap())
        .exists());
}
