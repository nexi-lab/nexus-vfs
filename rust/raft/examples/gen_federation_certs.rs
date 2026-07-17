//! Dev helper — mint a **shared-CA** TLS bundle for a set of federation
//! nodes, so a docker-compose (or local) mTLS cluster shares one CA rather
//! than each node's `bootstrap_tls` self-signing its own (which never
//! cross-verifies). Not shipped in any binary.
//!
//! ```text
//! cargo run -p raft --example gen_federation_certs -- <outdir> <name>:<node_id> [<name>:<node_id> ...]
//! ```
//!
//! For each `<name>:<node_id>` it writes `<outdir>/<name>/`:
//!   * `.node_id`            — 8-byte big-endian id, so the daemon's
//!     `read_or_mint_node_id` adopts the id the cert's URI SAN was minted
//!     for (instead of minting a fresh one that would mismatch).
//!   * `tls/ca.pem` + `tls/ca-key.pem`  — the shared cluster CA (same bytes
//!     for every node).
//!   * `tls/node.pem` + `tls/node-key.pem` — this node's cert, signed by the
//!     shared CA, with **every** node name in its SANs so a peer dialed by
//!     any container name passes hostname verification (`apply_tls` sets no
//!     `domain_name`).
//!   * `tls/join-token-hash` — present so `bootstrap_tls` treats the bundle
//!     as complete and reuses it rather than regenerating a per-node CA.
//!
//! Bind-mount `<outdir>/<name>` as the node's `--data-dir` and drop
//! `--no-tls`; the daemon then boots on the shared CA and federates over
//! mTLS through the mTLS-aware join path.

use nexus_raft::transport::{generate_node_cert, generate_zone_ca};
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = args
        .next()
        .expect("usage: gen_federation_certs <outdir> <name>:<node_id> ...");
    let specs: Vec<(String, u64)> = args
        .map(|s| {
            let (name, id) = s
                .split_once(':')
                .unwrap_or_else(|| panic!("expected <name>:<node_id>, got {s:?}"));
            (
                name.to_string(),
                id.parse()
                    .unwrap_or_else(|_| panic!("node_id not a u64: {id:?}")),
            )
        })
        .collect();
    assert!(!specs.is_empty(), "need at least one <name>:<node_id>");

    let zone = "root";
    let (ca_pem, ca_key_pem) = generate_zone_ca(zone).expect("generate shared CA");
    // Every node may be dialed by any container name → every cert carries
    // all names, plus certgen's default localhost / 127.0.0.1 / ::1.
    let all_hosts: Vec<String> = specs.iter().map(|(n, _)| n.clone()).collect();

    for (name, id) in &specs {
        let (cert, key) =
            generate_node_cert(*id, zone, &ca_pem, &ca_key_pem, &all_hosts, Some(name))
                .expect("generate node cert");
        let node_dir = Path::new(&outdir).join(name);
        let tls = node_dir.join("tls");
        std::fs::create_dir_all(&tls).expect("mkdir tls");
        std::fs::write(tls.join("ca.pem"), &ca_pem).expect("write ca.pem");
        std::fs::write(tls.join("ca-key.pem"), &ca_key_pem).expect("write ca-key.pem");
        std::fs::write(tls.join("node.pem"), &cert).expect("write node.pem");
        std::fs::write(tls.join("node-key.pem"), &key).expect("write node-key.pem");
        std::fs::write(tls.join("join-token-hash"), "0".repeat(64)).expect("write join-token-hash");
        std::fs::write(node_dir.join(".node_id"), id.to_be_bytes()).expect("write .node_id");
        println!(
            "wrote shared-CA bundle for {name} (node {id}) -> {}",
            tls.display()
        );
    }
    println!(
        "shared CA: {}",
        Path::new(&outdir).join("<name>/tls/ca.pem").display()
    );
}
