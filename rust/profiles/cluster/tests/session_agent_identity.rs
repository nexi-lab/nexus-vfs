//! Black-box E2E: auth-ON + mTLS-ON — a front door holding only an AGENT cert
//! obtains a per-session identity bound to a person, uses it, and has it
//! revoked. Every acceptance criterion of the session-identity FR, against a
//! real daemon over real mTLS.
//!
//! The thing being proven is a privilege boundary, so most of the test is
//! refusals. A session credential exists so that an agent cannot forge its own
//! identity and so its actions can be attributed to someone — which is worth
//! nothing if any agent can mint one, if the caller needs a node cert to do it
//! (a node cert carries admin and system, the privilege this exists to avoid),
//! or if revocation does not actually close the door.
//!
//! 1. BOOT     founder, auth-on, CA holder, accepting enrollments (serves the CRL).
//! 2. AGENTS   two ordinary agent certs: `moss` (the front door) and `stranger`.
//! 3. POLICY   the allow-list is NODE-gated — `moss` cannot add itself, the node
//!    cert can, and `list` reflects it.
//! 4. REFUSE   `stranger` is refused a session credential.
//! 5. MINT     `moss` gets one: a fresh `session-<uuid>` subject bound to `alice`,
//!    obtained over mTLS with an AGENT cert and no node cert anywhere.
//! 6. OWNER    the returned cert reads back through `classify_peer_cert_pem` —
//!    the kernel's own classifier — as that session, owned by `alice`.
//! 7. USE      the session credential authenticates to the daemon and writes.
//! 7b. BIND    the owner REACHES a service and outranks the request body:
//!    `start_session_v1` records `alice` for a caller that named nobody, and
//!    refuses one that names `bob`. The control is `moss`, whose ordinary
//!    agent cert has no owner SAN and whose body is still honoured.
//! 8. REVOKE   `moss` revokes it by handing back the certificate; after the CRL
//!    refresh the daemon rejects it, while `moss` keeps working.
//! 9. INTACT   `MintAgent`'s node-only gate is untouched: `moss` still cannot
//!    mint an ordinary agent.

mod common;

use std::time::Duration;

use common::{free_port_pair, mint_agent_cert, write_tls_bundle, Daemon, Vfs, LOG_FILTER};
use nexus_raft::transport::{
    call_allow_session_minter_rpc, call_list_session_minters_rpc, call_mint_agent_rpc,
    call_mint_session_agent_rpc, call_revoke_agent_cert_rpc, generate_join_token, generate_zone_ca,
    TlsConfig,
};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SECRET: &str = "e2e-session-secret";
const BUDGET: Duration = Duration::from_secs(120);
const SESSION_SECS: u64 = 3600;

fn founder_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    mounts: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts),
        ("NEXUS_ACCEPT_ENROLLMENTS", "true"),
        ("RUST_LOG", LOG_FILTER),
        // NEXUS_NO_TLS deliberately UNSET — TLS is on.
    ]
}

/// mTLS client config from a PEM cert + key, as any real caller presents.
fn tls_for(ca: &[u8], cert: &[u8], key: &[u8]) -> TlsConfig {
    TlsConfig {
        ca_pem: ca.to_vec(),
        cert_pem: cert.to_vec(),
        key_pem: key.to_vec(),
    }
}

/// Poll a write until it flips to the wanted state — revocation lands on a CRL
/// refresh cycle, so it is eventually consistent, not instant.
async fn poll_write(v: &mut Vfs, path: &str, want_ok: bool) -> bool {
    let deadline = std::time::Instant::now() + BUDGET;
    while std::time::Instant::now() < deadline {
        if v.write_file(path, b"probe", "").await.is_ok() == want_ok {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_front_door_agent_mints_a_session_identity_for_a_person_and_can_revoke_it() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // ── 1. BOOT ─────────────────────────────────────────────────────────────
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("gen join token");

    let fdata = tmp.path().join("f-data");
    let fid = tmp.path().join("f-id");
    std::fs::create_dir_all(&fdata).unwrap();
    write_tls_bundle(&fdata, 1, &ca, &ca_key, &hash);
    // The node's own client cert — what an operator administering policy holds.
    let node_cert = std::fs::read(fdata.join("tls").join("node.pem")).expect("node cert");
    let node_key = std::fs::read(fdata.join("tls").join("node-key.pem")).expect("node key");

    let fdata_s = fdata.to_string_lossy().to_string();
    let fid_s = fid.to_string_lossy().to_string();
    let fport = free_port_pair();
    let fadv = format!("127.0.0.1:{fport}");
    let fbind = fadv.clone();
    let mounts = format!("{MOUNT}={ZONE}");
    let env = founder_env(&fdata_s, &fid_s, &fadv, &mounts);
    // RPC helpers take a URL; the daemon serves mTLS, so the scheme is https.
    let rpc = format!("https://127.0.0.1:{fport}");

    {
        let mut f = Daemon::spawn(&["--bind-addr", &fbind], &env);
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms the zone");
    }

    // ── 2. AGENTS: two ordinary agent certs, minted the normal way ──────────
    let moss_dir = mint_agent_cert(&env, "moss");
    let stranger_dir = mint_agent_cert(&env, "stranger");
    let moss_cert = std::fs::read(moss_dir.join("agent.pem")).expect("moss cert");
    let moss_key = std::fs::read(moss_dir.join("agent-key.pem")).expect("moss key");
    let stranger_cert = std::fs::read(stranger_dir.join("agent.pem")).expect("stranger cert");
    let stranger_key = std::fs::read(stranger_dir.join("agent-key.pem")).expect("stranger key");

    let mut founder = Daemon::spawn(&["--bind-addr", &fbind], &env);
    founder
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("founder resumes");
    founder
        .wait_for_log("session-mint allow-list bound", BUDGET)
        .await
        .expect("the allow-list binds once the control zone is up");

    let moss_tls = || Some(tls_for(&ca, &moss_cert, &moss_key));
    let stranger_tls = || Some(tls_for(&ca, &stranger_cert, &stranger_key));
    let node_tls = || Some(tls_for(&ca, &node_cert, &node_key));

    // ── 3. POLICY is node-gated ─────────────────────────────────────────────
    let self_serve = call_allow_session_minter_rpc(&rpc, "moss", moss_tls(), 10)
        .await
        .expect("rpc reaches the daemon");
    assert!(
        self_serve.is_err(),
        "an agent must not be able to add itself to the allow-list"
    );

    call_allow_session_minter_rpc(&rpc, "moss", node_tls(), 10)
        .await
        .expect("rpc reaches the daemon")
        .expect("a node caller administers the allow-list");

    let listed = call_list_session_minters_rpc(&rpc, node_tls(), 10)
        .await
        .expect("rpc reaches the daemon")
        .expect("a node caller lists the allow-list");
    assert_eq!(listed, vec!["moss".to_string()]);

    assert!(
        call_list_session_minters_rpc(&rpc, moss_tls(), 10)
            .await
            .expect("rpc reaches the daemon")
            .is_err(),
        "reading the policy is node-gated too — it names who holds delegated authority"
    );

    // ── 4. REFUSE an agent that is not on the list ──────────────────────────
    let refused = call_mint_session_agent_rpc(&rpc, "alice", SESSION_SECS, stranger_tls(), 10)
        .await
        .expect("rpc reaches the daemon");
    assert!(
        !refused.success,
        "an agent off the allow-list must not mint a session identity"
    );

    // ── 5. MINT with an AGENT cert — no node cert anywhere in this call ─────
    let minted = call_mint_session_agent_rpc(&rpc, "alice", SESSION_SECS, moss_tls(), 10)
        .await
        .expect("rpc reaches the daemon");
    assert!(
        minted.success,
        "an allow-listed agent mints: {:?}",
        minted.error
    );
    assert!(
        minted.subject_id.starts_with("session-"),
        "a session subject, got {:?}",
        minted.subject_id
    );

    // A second mint is a different session: one session, one identity.
    let again = call_mint_session_agent_rpc(&rpc, "alice", SESSION_SECS, moss_tls(), 10)
        .await
        .expect("rpc reaches the daemon");
    assert!(again.success);
    assert_ne!(
        minted.subject_id, again.subject_id,
        "session subjects must never repeat"
    );

    // ── 6. OWNER reads back through the kernel's own classifier ─────────────
    let identity =
        transport::peer_identity::classify_peer_cert_pem(&minted.agent_cert_pem, &ca, &[])
            .expect("the minted cert classifies against the cluster CA");
    assert_eq!(
        identity.agent_name.as_deref(),
        Some(minted.subject_id.as_str()),
        "it resolves as the session it says it is"
    );
    assert_eq!(
        identity.owner.as_deref(),
        Some("alice"),
        "the owner binding is readable kernel-side"
    );
    assert_eq!(
        identity.node_id, None,
        "a session credential is never a cluster node"
    );

    // ── 7. USE it: authenticate to the daemon and write ─────────────────────
    let mut session = Vfs::connect_mtls(
        fport,
        &ca,
        &minted.agent_cert_pem,
        &minted.agent_key_pem,
        BUDGET,
    )
    .await;
    let probe = format!("{MOUNT}/session/probe.txt");
    session
        .write_file(&probe, b"before", "")
        .await
        .expect("the session credential authenticates and writes");

    // ── 7b. The owner binding REACHES a service, and outranks the body ──────
    //
    // Minting a cert that names an owner is worth nothing if the owner never
    // arrives anywhere. `start_session_v1` used to take `owner_id` from its
    // request body with no way to check it — an agent could open a session
    // attributed to anyone. These two calls are the whole consumption half:
    // who the daemon records, and what it does when the body disagrees.
    //
    // Note both go over the same mTLS connection as the write above, so the
    // identity under test is the real one the daemon resolved from the
    // certificate — nothing here constructs a context.
    let started = session
        .call(
            "managed_agent.start_session_v1",
            r#"{"agent_id":"scode-standard"}"#,
            "",
        )
        .await
        .expect("a session credential may start a session");
    let session_id = started
        .split("\"session_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("response carries a session_id")
        .to_string();

    // Read the owner back from the daemon rather than trusting the response:
    // `/proc/<pid>` is what an operator and an audit trail actually see.
    let recorded = session
        .call(
            "managed_agent.get_session_v1",
            &format!(r#"{{"session_id":"{session_id}"}}"#),
            "",
        )
        .await
        .expect("the session it just started is readable");
    assert!(
        recorded.contains("\"owner_id\":\"alice\""),
        "the recorded owner must come from the certificate, not the body's \
         default of `system`; got {recorded}"
    );

    // The decision this FR left to us: a body that disagrees with the
    // credential is REFUSED, not silently overwritten. Overwriting would
    // leave the caller believing it opened a session for `bob` while the
    // system recorded `alice`, with nothing said.
    let forged = session
        .call(
            "managed_agent.start_session_v1",
            r#"{"agent_id":"scode-standard","owner_id":"bob"}"#,
            "",
        )
        .await;
    let err = forged.expect_err("a session cert must not open a session for someone else");
    assert!(
        err.contains("bob") && err.contains("alice"),
        "the refusal must name both what was asked and what was proven; got {err}"
    );

    // The control: `moss`, holding an ORDINARY agent cert with no owner SAN,
    // is unaffected — its body still stands. This is what makes the rule
    // arrive with the credential instead of on a flag day.
    let mut front_door = Vfs::connect_mtls(fport, &ca, &moss_cert, &moss_key, BUDGET).await;
    let as_moss = front_door
        .call(
            "managed_agent.start_session_v1",
            r#"{"agent_id":"scode-standard","owner_id":"bob"}"#,
            "",
        )
        .await
        .expect("an ordinary agent cert keeps naming its own owner");
    let moss_sid = as_moss
        .split("\"session_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("response carries a session_id")
        .to_string();
    let moss_recorded = front_door
        .call(
            "managed_agent.get_session_v1",
            &format!(r#"{{"session_id":"{moss_sid}"}}"#),
            "",
        )
        .await
        .expect("readable");
    assert!(
        moss_recorded.contains("\"owner_id\":\"bob\""),
        "a caller with no owner SAN is unchanged; got {moss_recorded}"
    );

    // ── 8. REVOKE by handing back the certificate ───────────────────────────
    call_revoke_agent_cert_rpc(&rpc, &minted.agent_cert_pem, moss_tls(), 10)
        .await
        .expect("rpc reaches the daemon")
        .expect("the minter that issued it may revoke it");

    let mut revoked_conn = Vfs::connect_mtls(
        fport,
        &ca,
        &minted.agent_cert_pem,
        &minted.agent_key_pem,
        BUDGET,
    )
    .await;
    assert!(
        poll_write(&mut revoked_conn, &probe, false).await,
        "the revoked session credential must stop being accepted"
    );

    // The control: revoking one session did not disturb the front door, whose
    // certificate is still valid and still on the allow-list.
    let still_working = call_mint_session_agent_rpc(&rpc, "alice", SESSION_SECS, moss_tls(), 10)
        .await
        .expect("rpc reaches the daemon");
    assert!(
        still_working.success,
        "revoking a session must not disturb the minter: {:?}",
        still_working.error
    );

    // ── 9. The node-only gate on MintAgent is untouched ─────────────────────
    let escalation = call_mint_agent_rpc(&rpc, "sneaky", "sneaky", false, moss_tls(), 10)
        .await
        .expect("rpc reaches the daemon");
    assert!(
        !escalation.success,
        "an allow-listed session minter must still not be able to mint ORDINARY agents"
    );
    assert!(
        escalation
            .error
            .as_deref()
            .is_some_and(|e| e.contains("node-only")),
        "refused by the node gate, not by accident: {:?}",
        escalation.error
    );
}
