//! Federation joins and replicates over **mutual TLS**, and an untrusted
//! client certificate is refused.
//!
//! mTLS is fully wired (server sets `identity` + `client_ca_root`; the
//! pooled raft channels present a client identity via `create_channel`),
//! but until now **no test ever turned TLS on** — every federation path ran
//! `--no-tls`. That left one hole unexercised: the one-shot join RPC
//! (`call_join_zone_rpc`) hand-rolled a plaintext channel and could not
//! dial an `https://` mTLS leader, so the dynamic-join path silently broke
//! the moment TLS was enabled. This test turns real mTLS on over a
//! two-node cluster and exercises the whole journey end to end.
//!
//! Topology (same shape as `test_auth_key_replication`, but TLS-on):
//!   * One shared cluster CA signs both node certs (mTLS chains to one CA).
//!   * Founder bootstraps a 1-voter `sharedzone` and self-elects leader.
//!   * Joiner enters as a Learner over a real `JoinZone` gRPC call — now
//!     dialed over mTLS with the joiner presenting its client cert.
//!
//! The journey — each step consumes the previous step's output:
//!   1. Joiner **joins** the founder's zone via `call_join_zone_rpc` over
//!      mTLS. This is the fixed path: pre-fix it could not have connected.
//!   2. Founder **mints** a credential; the joiner **resolves** it — proving
//!      raft replication flows over the pooled mTLS channels, not just the
//!      one-shot join RPC.
//!   3. A rogue caller presenting a cert signed by a **different** CA is
//!      **refused** at the handshake — `client_ca_root` peer auth actually
//!      rejects an untrusted identity rather than nodding it through.
//!
//! SNI note: `apply_tls` sets no `domain_name`, so the endpoint host must
//! appear in the server cert SANs. `generate_node_cert` always emits
//! `localhost` / `127.0.0.1` / `::1`, so every endpoint here dials
//! `https://127.0.0.1:PORT`.

#![cfg(all(feature = "grpc", has_protos))]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kernel::hal::auth_key_store::AuthKeyStore;
use nexus_raft::auth_key_store::RaftAuthKeyStore;
use nexus_raft::transport::{call_join_zone_rpc, generate_node_cert, generate_zone_ca, TlsConfig};
use nexus_raft::{TlsFiles, ZoneManager};
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

/// Poll budget for a committed entry to reach the learner's state machine.
const REPLICATION_BUDGET: Duration = Duration::from_secs(5);

fn mint_random_id() -> u64 {
    let id = rand::random::<u64>();
    if id == 0 {
        1
    } else {
        id
    }
}

fn write_node_id(dir: &Path, id: u64) {
    std::fs::create_dir_all(dir).expect("create dir");
    std::fs::write(dir.join(NODE_ID_FILE), id.to_be_bytes()).expect("write .node_id");
}

/// Write a CA + node cert/key bundle under `<dir>/tls` and return the
/// `TlsFiles` pointing at it. A pre-minted bundle (rather than the daemon's
/// per-node `bootstrap_tls`) is what gives every node one shared CA — the
/// prerequisite for an mTLS handshake to verify across nodes.
fn write_tls_bundle(dir: &Path, ca_pem: &[u8], cert_pem: &[u8], key_pem: &[u8]) -> TlsFiles {
    let tls_dir = dir.join("tls");
    std::fs::create_dir_all(&tls_dir).expect("mkdir tls");
    let ca_path = tls_dir.join("ca.pem");
    let cert_path = tls_dir.join("node.pem");
    let key_path = tls_dir.join("node-key.pem");
    std::fs::write(&ca_path, ca_pem).expect("write ca.pem");
    std::fs::write(&cert_path, cert_pem).expect("write node.pem");
    std::fs::write(&key_path, key_pem).expect("write node-key.pem");
    TlsFiles {
        cert_path,
        key_path,
        ca_path,
        ca_key_path: None,
        join_token_hash: None,
    }
}

async fn make_tls_node(node_id: u64, dir: &Path, tls: TlsFiles) -> (Arc<ZoneManager>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    let bind_str = format!("{}", addr);

    let zm = ZoneManager::with_node_id(
        "test-host",
        node_id,
        dir.to_str().expect("utf-8"),
        vec![],
        &bind_str,
        Some(tls),
        // Advertise the https endpoint so peers learn a TLS address book.
        Some(format!("https://{bind_str}")),
        None,
    )
    .expect("ZoneManager (TLS)");
    (zm, bind_str)
}

/// Poll `store.get(hash)` until it matches `want`, or the budget expires.
async fn await_resolution(
    store: &RaftAuthKeyStore,
    hash: &str,
    want: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + REPLICATION_BUDGET;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        last = store.get(hash).expect("joiner resolve");
        if last.as_deref() == want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_joins_and_replicates_over_mtls_and_refuses_untrusted_certs() {
    let dir_founder = TempDir::new().expect("dir-founder");
    let dir_joiner = TempDir::new().expect("dir-joiner");

    let id_founder = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_founder, id_joiner, "two random mints must differ");
    write_node_id(dir_founder.path(), id_founder);
    write_node_id(dir_joiner.path(), id_joiner);

    // ── One shared cluster CA signs both node certs ──────────────────────
    let (ca_pem, ca_key_pem) = generate_zone_ca("sharedzone").expect("cluster CA");
    let (founder_cert, founder_key) = generate_node_cert(
        id_founder,
        "sharedzone",
        &ca_pem,
        &ca_key_pem,
        &[],
        Some("founder"),
    )
    .expect("founder cert");
    let (joiner_cert, joiner_key) = generate_node_cert(
        id_joiner,
        "sharedzone",
        &ca_pem,
        &ca_key_pem,
        &[],
        Some("joiner"),
    )
    .expect("joiner cert");

    let tls_founder = write_tls_bundle(dir_founder.path(), &ca_pem, &founder_cert, &founder_key);
    let tls_joiner = write_tls_bundle(dir_joiner.path(), &ca_pem, &joiner_cert, &joiner_key);

    let (zm_founder, bind_founder) =
        make_tls_node(id_founder, dir_founder.path(), tls_founder).await;
    let (zm_joiner, bind_joiner) = make_tls_node(id_joiner, dir_joiner.path(), tls_joiner).await;

    // ── Founder self-elects on a 1-voter zone ────────────────────────────
    let zone_founder = zm_founder
        .create_zone("sharedzone", vec![format!("{id_founder}@{bind_founder}")])
        .expect("create sharedzone on founder");
    for _ in 0..100 {
        if zone_founder.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        zone_founder.is_leader(),
        "founder must self-elect on 1-voter create"
    );

    let endpoint_founder = format!("https://{bind_founder}");
    let endpoint_joiner = format!("https://{bind_joiner}");

    let _zone_joiner_local = zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_founder}@{bind_founder}")],
            /* learner */ true,
        )
        .expect("local join_zone(learner) on joiner");

    // ── 1. JoinZone over mTLS — the fixed path ───────────────────────────
    // The joiner presents its client cert; the founder's `client_ca_root`
    // verifies it chains to the shared CA. Pre-fix this RPC hand-rolled a
    // plaintext channel and could not have completed the handshake.
    let joiner_client_tls = TlsConfig {
        cert_pem: joiner_cert.clone(),
        key_pem: joiner_key.clone(),
        ca_pem: ca_pem.clone(),
    };
    let join_resp = call_join_zone_rpc(
        &endpoint_founder,
        "sharedzone",
        id_joiner,
        &endpoint_joiner,
        /* as_learner */ true,
        Some(joiner_client_tls),
        30,
    )
    .await
    .expect("JoinZone RPC over mTLS");
    assert!(
        join_resp.success,
        "mTLS JoinZone(learner) must succeed: {:?}",
        join_resp.error
    );

    for _ in 0..50 {
        if zm_founder.cluster_status("sharedzone").applied_index >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // ── 2. A minted credential replicates over the pooled mTLS channels ──
    let store_founder =
        RaftAuthKeyStore::new(zone_founder.consensus_node(), zone_founder.runtime_handle());
    let zone_joiner = zm_joiner
        .get_zone("sharedzone")
        .expect("joiner must hold a ZoneHandle for sharedzone");
    let store_joiner =
        RaftAuthKeyStore::new(zone_joiner.consensus_node(), zone_joiner.runtime_handle());

    let record = b"record-over-mtls".to_vec();
    store_founder
        .put("mtls-hash", &record)
        .expect("mint over mTLS");
    assert_eq!(
        await_resolution(&store_joiner, "mtls-hash", Some(&record)).await,
        Some(record.clone()),
        "a credential minted on the founder must replicate to the joiner over mTLS"
    );

    // ── 3. An untrusted client cert is refused ───────────────────────────
    // The rogue trusts the shared CA (so it accepts the founder's server
    // cert), but presents a client cert signed by a DIFFERENT CA. The
    // founder's `client_ca_root` must reject it at the handshake, so the
    // RPC fails to connect rather than being nodded through.
    let (rogue_ca_pem, rogue_ca_key) = generate_zone_ca("rogue").expect("rogue CA");
    let (rogue_cert, rogue_key) = generate_node_cert(
        999_999,
        "rogue",
        &rogue_ca_pem,
        &rogue_ca_key,
        &[],
        Some("rogue"),
    )
    .expect("rogue cert");
    let rogue_tls = TlsConfig {
        cert_pem: rogue_cert,
        key_pem: rogue_key,
        ca_pem: ca_pem.clone(),
    };
    let rogue = call_join_zone_rpc(
        &endpoint_founder,
        "sharedzone",
        mint_random_id(),
        &endpoint_joiner,
        /* as_learner */ true,
        Some(rogue_tls),
        5,
    )
    .await;
    assert!(
        rogue.is_err(),
        "an untrusted client cert must be refused by the mTLS server, got {rogue:?}"
    );
}
