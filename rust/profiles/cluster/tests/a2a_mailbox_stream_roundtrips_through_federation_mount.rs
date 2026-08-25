//! Root-cause repro (task #96): the co-host A2A mailbox
//! `/agents/<name>/chat-with-me` read returns FileNotFound on the co-host
//! path, while a plain gRPC read of the same path works.
//!
//! Hypothesis under test — it is NOT the OS, it is the **federation mount**.
//! The one confirmed difference between the Docker duet (PONG) and the native
//! Windows founder (FileNotFound) is that Docker was single-node with `/agents`
//! in the plain root zone, whereas the Windows founder mounted
//! `/agents=<zone>` as a federation mount. The A2A inbox is a DT_STREAM (the
//! co-host loop consumes `stream_next_offset`), and NOBODY provisions
//! `/agents/<name>/chat-with-me` — unlike `/proc/{pid}/chat-with-me`, which
//! `managed_agent::proc_entry` creates with io_profile `wal,memory`. So the
//! stream's write-side backend and the read-side `wal_backend_for` /
//! `routed_zone_id` materializer can resolve to different zones under a mount.
//!
//! This is a BLACK-BOX, cross-platform gate: it stands up the real
//! `nexusd-cluster` founder with the exact failing topology
//! (`--cluster-init <zone> --cluster-init-mount /agents=<zone>`), provisions
//! the inbox as a DT_STREAM the way the fix will, and round-trips one envelope
//! BOTH under the federation mount AND at a plain root path (the control). If
//! the control round-trips but the federation-mounted inbox does not, the
//! federation mount is the root cause — reproduced on Linux CI and Windows
//! alike, with no OS-specific reasoning.

mod common;

use std::time::Duration;

use common::{cli, free_port, write_tls_bundle, Daemon, Vfs, LOG_FILTER};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

const ZONE: &str = "sharedzone";
const BUDGET: Duration = Duration::from_secs(90);

fn base_env<'a>(data: &'a str, id: &'a str, adv: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ]
}

const ENVELOPE: &[u8] = br#"{"from":"win-ai","to":"mac-ai","body":"PING"}"#;

/// One mailbox envelope round-trip on `inbox` via the STREAM RPCs: provision it
/// as a DT_STREAM (`wal,memory` — the same io_profile `proc_entry` uses for the
/// canonical `/proc/{pid}/chat-with-me` mailbox), append one message, then read
/// it back from offset 0. Returns `Ok(bytes)` on a successful read, `Err(reason)`
/// at the first failing step so the caller can pinpoint which op broke.
async fn mailbox_roundtrip(vfs: &mut Vfs, inbox: &str) -> Result<Vec<u8>, String> {
    let token = "";
    vfs.create_stream(inbox, token)
        .await
        .map_err(|e| format!("create_stream({inbox}): {e}"))?;
    vfs.stream_write(inbox, ENVELOPE, token)
        .await
        .map_err(|e| format!("stream_write({inbox}): {e}"))?;
    let out = vfs
        .stream_read_at(inbox, 0, token)
        .await
        .map_err(|e| format!("stream_read_at({inbox}) transport: {e}"))?;
    if out.is_error {
        return Err(format!(
            "stream_read_at({inbox}) kernel error: {}",
            out.error_payload
        ));
    }
    if out.data.is_empty() {
        return Err(format!(
            "stream_read_at({inbox}) returned EMPTY (eof={}, next_offset={})",
            out.eof, out.next_offset
        ));
    }
    Ok(out.data)
}

/// The ACTUAL co-host flow: the inbox is NOT provisioned as a DT_STREAM, and
/// both sides use PLAIN `sys_write` / `sys_read` (what the sudocode co-host
/// loop and the gRPC seed do), NOT the stream RPCs. This is the exact op pair
/// that FileNotFounds on the native founder. `write_file` → `sys_write`,
/// `read_file` → `sys_read`.
async fn mailbox_roundtrip_plain(vfs: &mut Vfs, inbox: &str) -> Result<Vec<u8>, String> {
    let token = "";
    vfs.write_file(inbox, ENVELOPE, token)
        .await
        .map_err(|e| format!("write_file({inbox}): {e}"))?;
    let got = vfs
        .read_file(inbox, token)
        .await
        .map_err(|e| format!("read_file({inbox}): {e}"))?;
    if got.is_empty() {
        return Err(format!("read_file({inbox}) returned EMPTY"));
    }
    Ok(got)
}

/// The POST-FIX co-host pattern: the inbox is PROVISIONED as a DT_STREAM (what
/// the a2a-owned provisioning will do), but the writer/reader still use the
/// PLAIN `sys_write` / `sys_read` the co-host loop uses (not the stream RPCs).
/// `sys_write` to a DT_STREAM appends; `sys_read` tails from offset 0. Proves
/// the fix's op-shape round-trips through a federation mount before it is wired.
async fn mailbox_roundtrip_provisioned_plain(
    vfs: &mut Vfs,
    inbox: &str,
) -> Result<Vec<u8>, String> {
    let token = "";
    vfs.create_stream(inbox, token)
        .await
        .map_err(|e| format!("create_stream({inbox}): {e}"))?;
    vfs.write_file(inbox, ENVELOPE, token)
        .await
        .map_err(|e| format!("write_file({inbox}) to provisioned stream: {e}"))?;
    let got = vfs
        .read_file(inbox, token)
        .await
        .map_err(|e| format!("read_file({inbox}) of provisioned stream: {e}"))?;
    if got.is_empty() {
        return Err(format!(
            "read_file({inbox}) of provisioned stream returned EMPTY"
        ));
    }
    Ok(got)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2a_mailbox_stream_roundtrips_through_federation_mount() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fport = free_port();
    let fdata = tmp.path().join("f-data");
    let fdata = fdata.to_string_lossy();
    let fid = tmp.path().join("f-id");
    let fid = fid.to_string_lossy();
    let fadv = format!("127.0.0.1:{fport}");
    let fbind = format!("127.0.0.1:{fport}");
    let mounts = format!("/agents={ZONE}");
    let zone_registered = format!("Zone '{ZONE}' registered");

    // Single-node founder with the EXACT failing topology: found `sharedzone`
    // and mount it at `/agents` as a federation mount.
    let mut env = base_env(&fdata, &fid, &fadv);
    env.push(("NEXUS_CLUSTER_INIT", ZONE));
    env.push(("NEXUS_CLUSTER_INIT_MOUNTS", &mounts));
    let mut founder = Daemon::spawn(&["--bind-addr", &fbind], &env);
    founder
        .wait_tcp(fport, BUDGET)
        .await
        .expect("founder serves");
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder founds+registers sharedzone");

    let mut vfs = Vfs::dial(fport).await.expect("dial founder");

    let control = "/rootlocal/mac-ai/chat-with-me";
    let subject = "/agents/mac-ai/chat-with-me";

    // Matrix — isolate (federation mount?) × (provisioned DT_STREAM vs the real
    // plain-op flow). Each cell is independent (distinct inbox paths).
    let stream_control = mailbox_roundtrip(&mut vfs, control).await;
    let stream_subject = mailbox_roundtrip(&mut vfs, subject).await;
    let plain_control = mailbox_roundtrip_plain(&mut vfs, "/rootlocal/plain/chat-with-me").await;
    let plain_subject = mailbox_roundtrip_plain(&mut vfs, "/agents/plain/chat-with-me").await;
    // The post-fix shape: provisioned DT_STREAM + the co-host's plain ops.
    let fixed_subject =
        mailbox_roundtrip_provisioned_plain(&mut vfs, "/agents/fixed/chat-with-me").await;

    eprintln!("REPRO96 stream control  ({control})              => {stream_control:?}");
    eprintln!("REPRO96 stream subject  ({subject})              => {stream_subject:?}");
    eprintln!("REPRO96 plain  control  (/rootlocal/plain/…)     => {plain_control:?}");
    eprintln!("REPRO96 plain  subject  (/agents/plain/…)        => {plain_subject:?}");
    eprintln!("REPRO96 fixed  subject  (/agents/fixed/… prov)   => {fixed_subject:?}");

    // Provisioned DT_STREAM round-trips (proved passing already) — kept as the
    // harness-soundness anchor.
    stream_control.expect("stream mailbox in root zone must round-trip");
    stream_subject.expect("stream mailbox under federation mount must round-trip");

    // The REAL flow: plain sys_write + sys_read, inbox unprovisioned. The
    // control (root zone) must round-trip. The subject (federation mount) is
    // the #96 gate — a failure here is the reproduction.
    plain_control.expect(
        "plain sys_write/sys_read mailbox in the ROOT zone must round-trip \
         (this is the Docker/PONG shape)",
    );
    plain_subject.expect(
        "REPRODUCED #96: plain sys_write/sys_read of an unprovisioned A2A \
         mailbox under a `/agents=<zone>` federation mount failed to round-trip",
    );
    fixed_subject.expect(
        "post-fix shape: a PROVISIONED DT_STREAM inbox under a federation mount, \
         written+read with the co-host's PLAIN sys_write/sys_read, must round-trip",
    );
}

const SECRET: &str = "e2e-a2a-mailbox-secret";

/// The last uncovered cell — the EXACT co-host read: a non-admin CERT-AGENT
/// doing a PLAIN `sys_read` (`read_file`) of an UNPROVISIONED
/// `/agents/<name>/chat-with-me` under a federation mount, after the envelope
/// was seeded by a DIFFERENT (admin) identity — the sudocode co-host loop's
/// `kernel.sys_read(inbox, ctx{is_admin:false, agent_id:Some}, …)`.
///
/// Every admin cell (test above) round-trips; `agent_signed_authorship` shows a
/// cert-agent's PROVISIONED stream + plain WRITE work through the mount. This
/// isolates the one combination the live native-founder failure actually hits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cert_agent_plain_read_of_unprovisioned_inbox_through_federation_mount() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let ident = tmp.path().join("id");

    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");
    write_tls_bundle(&data, 1, &ca, &ca_key, &hash);

    let data_s = data.to_string_lossy();
    let ident_s = ident.to_string_lossy();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let bind = format!("127.0.0.1:{port}");
    let mounts = format!("/agents={ZONE}");
    let env = vec![
        ("NEXUS_DATA_DIR", data_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident_s.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let zone_registered = format!("Zone '{ZONE}' registered");

    // Form the zone + persist the mount, then stop to release the data-dir lock
    // for the offline mints.
    {
        let mut f = Daemon::spawn(&["--bind-addr", &bind], &env);
        f.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("founder forms sharedzone + persists the mount");
    }

    // Reader = mac-ai (cert); seed writer = win-ai (a DIFFERENT cert-agent),
    // matching the real "peer seeds, agent reads" flow — both non-admin, both
    // over the mTLS peer plane (empty token).
    let mint_agent = |id: &str| {
        let (ok, dir, err) = cli(
            &env,
            &[
                "auth",
                "mint",
                "--subject-type",
                "agent",
                "--subject-id",
                id,
                "--name",
                "e2e",
            ],
        );
        assert!(ok, "agent cert mint failed for {id}: {err}");
        let b = std::path::PathBuf::from(dir.trim());
        let cert = std::fs::read(b.join("agent.pem")).expect("agent.pem");
        let key = std::fs::read(b.join("agent-key.pem")).expect("agent-key.pem");
        (cert, key)
    };
    let (mac_cert, mac_key) = mint_agent("mac-ai");
    let (win_cert, win_key) = mint_agent("win-ai");

    let mut founder = Daemon::spawn(&["--bind-addr", &bind], &env);
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder resumes sharedzone");

    let inbox = "/agents/mac-ai/chat-with-me";

    // win-ai (non-admin cert) seeds mac-ai's inbox with a PLAIN write — the
    // inbox is NOT provisioned as a stream (nobody provisions it in prod).
    let mut win = Vfs::connect_mtls(port, &ca, &win_cert, &win_key, BUDGET).await;
    let seed = win.write_file(inbox, ENVELOPE, "").await;
    eprintln!("REPRO96 win   write {inbox} => {seed:?}");

    // THE GATE — the co-host read: non-admin cert-agent mac-ai, plain sys_read,
    // unprovisioned inbox, through the federation mount.
    let mut mac = Vfs::connect_mtls(port, &ca, &mac_cert, &mac_key, BUDGET).await;
    let mac_read = mac.read_file(inbox, "").await;
    eprintln!("REPRO96 mac   read  {inbox} => {mac_read:?}");

    drop(founder);

    seed.expect("win-ai (non-admin) must be able to seed mac-ai's inbox");
    mac_read.expect(
        "REPRODUCED #96: a non-admin cert-agent's PLAIN read of the \
         unprovisioned A2A inbox under a federation mount failed — the exact \
         co-host `sys_read` that FileNotFounds on the native founder",
    );
}
