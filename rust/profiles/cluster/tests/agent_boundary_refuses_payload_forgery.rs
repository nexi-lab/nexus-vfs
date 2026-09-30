//! Black-box E2E (acceptance 1, R5): a low-privilege authenticated caller
//! cannot forge `owner_id` / `zone_id` through the generic `Call` surface —
//! the boundary derives identity from the AUTH CONTEXT, not the payload.
//!
//! ApiKey posture (`NEXUS_API_KEY_SECRET` + `--no-tls`): a plain user key
//! (`zone:rw`, NOT `--admin`) is the forger. A zoneless `--admin` key is
//! non-system, but `resolve_agent_zone` respects `is_admin` (like
//! `authorize_agent_owner` / `agent_list`): its registrations land under the
//! root default instead of being refused.

mod common;

use std::time::Duration;

use common::{free_port, mint_token_key, Daemon, Vfs, LOG_FILTER};
use tonic::Code;

const SECRET: &str = "agent-boundary-secret";
const USER: &str = "alice";
const ZONE: &str = "tenant-a";
const BUDGET: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payload_forgery_is_refused_at_the_boundary() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();

    // Offline mint: a low-privilege user key (zone grant, not admin) + an
    // admin key — both durable in the store the daemon will bind. NOTE the
    // NO_TLS marker: the offline mint picks its store zone by the SAME
    // posture signal the daemon will (`--no-tls` ⇒ per-node root), so a
    // mint that thought it was TLS-on would write `__control__` and the
    // daemon would never see the keys.
    let cli_env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_NO_TLS", "true"),
    ];
    let low = mint_token_key(&cli_env, "user", USER, &format!("{ZONE}:rw"));
    let admin = {
        let (ok, out, err) = common::cli(
            &cli_env,
            &[
                "auth",
                "mint",
                "--subject-type",
                "user",
                "--subject-id",
                "root-op",
                "--admin",
                "--name",
                "e2e",
            ],
        );
        assert!(
            ok && out.trim().starts_with("sk-"),
            "admin mint failed: {err}"
        );
        out.trim().to_string()
    };

    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_NO_TLS", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut d = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env);
    d.wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .unwrap_or_else(|_| panic!("daemon did not boot; log:\n{}", d.drain()));
    let mut vfs = Vfs::connect_serving(port, BUDGET).await;
    // Poll the admin ping briefly (store bind beats the socket by a hair).
    let deadline = std::time::Instant::now() + BUDGET;
    loop {
        match vfs.ping(&admin).await {
            Ok(()) => break,
            Err(e) if std::time::Instant::now() < deadline => {
                if e.code() != tonic::Code::Unauthenticated && e.code() != tonic::Code::Unavailable
                {
                    panic!("admin ping failed unexpectedly: {e:?}");
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => panic!(
                "admin token never authenticated ({e:?}); daemon log tail:\n{}",
                d.drain()
            ),
        }
    }

    // ── Forgery 1: claim someone ELSE's owner_id ──
    let forged_owner = vfs
        .call(
            "agent_register",
            &serde_json::json!({
                "name": "forged-owner",
                "owner_id": "bob",       // ≠ ctx.user_id ("alice")
                "zone_id": ZONE,          // alice's own zone — valid otherwise
            }),
            &low,
        )
        .await;
    assert!(
        forged_owner.is_error,
        "a low-privilege caller claiming owner_id=bob must be refused; payload: {}",
        String::from_utf8_lossy(&forged_owner.payload)
    );

    // ── Forgery 2: claim a zone the caller has NO grant on ──
    let forged_zone = vfs
        .call(
            "agent_register",
            &serde_json::json!({
                "name": "forged-zone",
                // owner_id omitted → derives from ctx (alice)
                "zone_id": "someone-elses-zone",
            }),
            &low,
        )
        .await;
    assert!(
        forged_zone.is_error,
        "a zone outside the caller's grants must be refused; payload: {}",
        String::from_utf8_lossy(&forged_zone.payload)
    );

    // ── Control: the SAME low-privilege caller, NO forgery → passes ──
    // (owner derives from the token, zone is its own grant — proving the
    // refusals above were the trust boundary, not a broken surface.)
    let honest = vfs
        .call(
            "agent_register",
            &serde_json::json!({
                "name": "honest-agent",
                "zone_id": ZONE,
            }),
            &low,
        )
        .await;
    assert!(
        !honest.is_error,
        "an honest registration under the caller's own identity/zone must pass: {}",
        String::from_utf8_lossy(&honest.payload)
    );
    let registered: serde_json::Value =
        serde_json::from_slice(&honest.payload).expect("valid json");
    let result = registered.get("result").expect("result envelope");
    assert_eq!(
        result.get("owner_id").and_then(|v| v.as_str()),
        Some(USER),
        "the response must echo the DERIVED owner (the auth context's), not a payload claim: {result}"
    );
    assert_eq!(
        result.get("zone_id").and_then(|v| v.as_str()),
        Some(ZONE),
        "the response must echo the effective zone"
    );

    // ── A zoneless global admin registers under the root default ──
    // resolve_agent_zone respects is_admin (the same respect
    // authorize_agent_owner / agent_list show): a zoneless admin gets the
    // root-zone default instead of the "no explicit zone grant" refusal.
    let admin_reg = vfs
        .call(
            "agent_register",
            &serde_json::json!({ "name": "admin-agent" }),
            &admin,
        )
        .await;
    assert!(
        !admin_reg.is_error,
        "a zoneless global admin registers under the root default: {}",
        String::from_utf8_lossy(&admin_reg.payload)
    );
    let admin_registered: serde_json::Value =
        serde_json::from_slice(&admin_reg.payload).expect("valid json");
    let admin_result = admin_registered.get("result").expect("result envelope");
    assert_eq!(
        admin_result.get("zone_id").and_then(|v| v.as_str()),
        Some("root"),
        "the zoneless admin's registration lands in the root default: {admin_result}"
    );
    assert_eq!(
        admin_result.get("owner_id").and_then(|v| v.as_str()),
        Some("root-op"),
        "the owner still derives from the AUTH context, never the payload: {admin_result}"
    );

    // ── The unauthenticated nobody is nobody ──
    let err = vfs.ping("").await.expect_err("empty token refused");
    assert_eq!(err.code(), Code::Unauthenticated);
}
