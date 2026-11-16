//! A single-endpoint operator client for automatic Codex Agent enrollment.
//!
//! This uses the existing Node-gated MintAgent RPC, TLS loader and credential
//! writer. It never opens the auth store, signs offline, elects another subject
//! or retries an RPC. The local attempt is a client recovery receipt, not an
//! additional identity registry: the existing replicated name claim governs.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use lib::transport_primitives::create_secret;
use nexus_raft::transport::{MintAgentChannel, TlsConfig};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "nexus-agent-enroll",
    version = super::daemon_version_string(),
    about = "Operator-granted client of the existing Node MintAgent RPC"
)]
struct Args {
    #[arg(long)]
    grant: PathBuf,
    #[arg(long)]
    initialize: bool,
    #[arg(long, requires = "initialize")]
    data_dir: Option<PathBuf>,
    #[arg(long, requires = "initialize")]
    endpoint: Option<String>,
    #[arg(long, requires = "initialize")]
    workspace_root: Vec<PathBuf>,
}

/// Standalone client entry; never dispatches the daemon or opens its database.
pub fn main() -> Result<()> {
    let args = Args::parse();
    if args.initialize {
        return initialize(
            &args.grant,
            args.data_dir
                .as_deref()
                .context("--initialize requires --data-dir")?,
            args.endpoint
                .as_deref()
                .context("--initialize requires --endpoint")?,
            args.workspace_root,
        );
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&args.grant))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    version: u32,
    purpose: String,
    endpoint: String,
    node_data_directory: PathBuf,
    state_directory: PathBuf,
    owner_node_identity: String,
    ca_certificate_sha256: String,
    workspace_roots: Vec<PathBuf>,
}

/// Prepare an explicit operator capability without issuing a credential or
/// starting a service. Existing grants are never overwritten.
pub(super) fn initialize(
    file: &Path,
    data_directory: &Path,
    endpoint: &str,
    workspace_roots: Vec<PathBuf>,
) -> Result<()> {
    ensure!(
        file.is_absolute() && data_directory.is_absolute(),
        "absolute grant/data paths are required"
    );
    ensure!(
        !workspace_roots.is_empty(),
        "at least one explicitly authorized workspace root is required"
    );
    let tls = super::load_node_tls(data_directory)?;
    let parent = file.parent().context("grant requires a parent directory")?;
    let grant = Grant {
        version: 1,
        purpose: "codex-a2a".into(),
        endpoint: endpoint.into(),
        node_data_directory: data_directory.canonicalize()?,
        state_directory: parent.join("node-enrollment-operations"),
        owner_node_identity: node_identity(&tls)?,
        ca_certificate_sha256: super::certificate_sha256_hex(&tls.ca_pem)?,
        workspace_roots,
    };
    // The same validator used at issuance checks URI/TLS/root inputs before a
    // grant can be published. Do not run an RPC merely to prepare local policy.
    validate_target(&grant)?;
    for root in &grant.workspace_roots {
        ensure!(
            root.is_absolute() && root.canonicalize()?.is_dir(),
            "workspace roots must be existing absolute directories"
        );
    }
    std::fs::create_dir_all(parent)?;
    create_secret(file, &serde_json::to_vec_pretty(&grant)?)?;
    println!(
        "{}",
        serde_json::json!({"prepared":true,"grantFile":file,"issued":false,
        "endpoint":grant.endpoint,"workspaceRoots":grant.workspace_roots,
        "ownerNodeIdentity":grant.owner_node_identity})
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Claim {
    version: u32,
    actor: String,
    operation_id: String,
    thread_id: String,
    workspace: PathBuf,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attempt {
    claim: Claim,
    canonical_workspace: PathBuf,
    endpoint: String,
    owner_node_identity: String,
    ca_certificate_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    version: u32,
    actor: String,
    operation_id: String,
    credential_directory: PathBuf,
}

#[inline]
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
            }
        })
}

/// The Node a TLS bundle names, through the same check boot applies. A grant
/// binds this durable identity; the leaf naming it is renewed routinely.
#[inline]
fn node_identity(tls: &TlsConfig) -> Result<String> {
    nexus_raft::transport::local_node_identity(&tls.cert_pem, &tls.ca_pem)
        .map(|node| node.identity_uri())
        .map_err(|error| anyhow::anyhow!("operator Node certificate: {error}"))
}

#[inline]
fn read_json<T: serde::de::DeserializeOwned>(file: &Path) -> Result<T> {
    ensure!(
        std::fs::symlink_metadata(file)?.file_type().is_file(),
        "operator records must be regular files: {}",
        file.display()
    );
    let mut raw = Vec::new();
    std::fs::File::open(file)?
        .take(16385)
        .read_to_end(&mut raw)?;
    ensure!(raw.len() <= 16384, "operator record exceeds 16 KiB");
    Ok(serde_json::from_slice(&raw)?)
}

fn prepare(grant_file: &Path, claim: Claim) -> Result<(Grant, Attempt, TlsConfig)> {
    ensure!(
        grant_file.is_absolute(),
        "an absolute operator grant is required"
    );
    let grant: Grant = read_json(grant_file)?;
    ensure!(
        grant.version == 1 && grant.purpose == "codex-a2a",
        "unsupported operator grant"
    );
    ensure!(
        claim.version == 1 && uuid(&claim.operation_id) && uuid(&claim.thread_id),
        "invalid operation/thread identity"
    );
    // Each native frontend (Codex thread, Claude Code session) mints its own
    // random actor under its frontend's prefix; nothing else is issuable.
    let suffix = ["codex-", "claude-"]
        .iter()
        .find_map(|prefix| claim.actor.strip_prefix(prefix))
        .unwrap_or_default();
    ensure!(
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "grant permits only codex-<32 lowercase hex> or claude-<32 lowercase hex> actors"
    );
    ensure!(
        claim.workspace.is_absolute(),
        "an absolute native workspace is required"
    );
    let canonical = claim.workspace.canonicalize()?;
    ensure!(canonical.is_dir(), "native workspace is not a directory");
    let mut authorized = false;
    for root in &grant.workspace_roots {
        ensure!(root.is_absolute(), "grant workspace roots must be absolute");
        authorized |= canonical.starts_with(root.canonicalize()?);
    }
    ensure!(authorized, "native workspace is outside the operator grant");
    ensure!(
        grant.node_data_directory.is_absolute() && grant.state_directory.is_absolute(),
        "operator paths must be absolute"
    );
    let tls = validate_target(&grant)?;
    let attempt = Attempt {
        claim,
        canonical_workspace: canonical,
        endpoint: grant.endpoint.clone(),
        owner_node_identity: grant.owner_node_identity.clone(),
        ca_certificate_sha256: grant.ca_certificate_sha256.clone(),
    };
    Ok((grant, attempt, tls))
}

#[inline]
fn validate_target(grant: &Grant) -> Result<TlsConfig> {
    // There is exactly one destination; no peer selection or offline fallback.
    let endpoint = tonic::transport::Endpoint::from_shared(grant.endpoint.clone())?;
    ensure!(
        endpoint.uri().scheme_str() == Some("https")
            && endpoint.uri().authority().is_some()
            && endpoint.uri().path() == "/"
            && endpoint.uri().query().is_none()
            && !grant.endpoint.contains('@'),
        "grant requires one exact HTTPS endpoint without credentials/query/path"
    );
    let tls = super::load_node_tls(&grant.node_data_directory)?;
    // The pinned CA first: the identity check then verifies the current leaf
    // chains to exactly that cluster before reading which Node it names.
    ensure!(
        super::certificate_sha256_hex(&tls.ca_pem)? == grant.ca_certificate_sha256,
        "operator cluster CA changed"
    );
    ensure!(
        node_identity(&tls)? == grant.owner_node_identity,
        "operator Node identity changed"
    );
    Ok(tls)
}

/// Why an invocation returned no receipt.
enum Failure {
    /// Nothing was reserved or sent: the same operation may run again.
    NotSubmitted(anyhow::Error),
    /// The reserved request may have committed: it is never resubmitted.
    Unknown(anyhow::Error),
}

async fn issue(
    grant: Grant,
    attempt: Attempt,
    tls: TlsConfig,
) -> std::result::Result<Receipt, Failure> {
    let actor = &attempt.claim.actor;
    let attempt_file = grant.state_directory.join(format!("{actor}.attempt.json"));
    let result_file = grant.state_directory.join(format!("{actor}.result.json"));
    let reservation =
        serde_json::to_vec(&attempt).map_err(|error| Failure::NotSubmitted(error.into()))?;
    std::fs::create_dir_all(&grant.state_directory)
        .map_err(|error| Failure::NotSubmitted(error.into()))?;
    let replay =
        || recover(&grant, &attempt, &attempt_file, &result_file).map_err(Failure::Unknown);
    // A reserved operation only replays its local receipt; it opens no channel.
    if !matches!(
        std::fs::symlink_metadata(&attempt_file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return replay();
    }
    // Opening the channel sends no request, so a failure here leaves the
    // operation unreserved and the same operation may run again later.
    let channel = MintAgentChannel::connect(&grant.endpoint, Some(tls), 10)
        .await
        .map_err(|error| Failure::NotSubmitted(error.into()))?;
    match create_secret(&attempt_file, &reservation) {
        Ok(()) => {}
        // Another invocation reserved this actor while this one connected.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return replay(),
        Err(error) => return Err(Failure::Unknown(error.into())),
    }
    // Persisted BEFORE the request leaves. Every error from here is Unknown,
    // including a crash, a refusal whose server semantics may differ, and loss
    // of the public reply after the credential was written. Never resubmit.
    submit(&grant, &attempt, channel, &result_file)
        .await
        .map_err(Failure::Unknown)
}

/// Replay a reserved operation from its local receipt; never sends a request.
fn recover(
    grant: &Grant,
    attempt: &Attempt,
    attempt_file: &Path,
    result_file: &Path,
) -> Result<Receipt> {
    let actor = &attempt.claim.actor;
    let previous: Attempt = read_json(attempt_file)?;
    ensure!(
        previous == *attempt,
        "actor is reserved by another operation or target; operator recovery required"
    );
    let receipt: Receipt = read_json(result_file).context(
        "original issuance may have committed; no RPC retry; operator recovery required",
    )?;
    ensure!(
        receipt.version == 1
            && receipt.actor == *actor
            && receipt.operation_id == attempt.claim.operation_id
            && receipt.credential_directory == grant.node_data_directory.join("agents").join(actor),
        "original receipt binding differs"
    );
    let loaded = nexus_raft::transport::AgentCredential::load(&receipt.credential_directory)
        .map_err(anyhow::Error::msg)?;
    ensure!(loaded.agent == *actor, "persisted credential actor changed");
    Ok(receipt)
}

/// Send the reserved request exactly once and persist its outcome.
async fn submit(
    grant: &Grant,
    attempt: &Attempt,
    channel: MintAgentChannel,
    result_file: &Path,
) -> Result<Receipt> {
    let actor = &attempt.claim.actor;
    ensure!(
        !grant
            .node_data_directory
            .join("agents")
            .join(actor)
            .exists(),
        "credential path already exists; operator recovery required"
    );
    let response = channel.mint(actor, actor, false).await?;
    ensure!(
        response.success,
        "MintAgent returned a refusal: {}",
        response.error.as_deref().unwrap_or("unspecified")
    );
    ensure!(
        super::certificate_sha256_hex(&response.ca_pem)? == grant.ca_certificate_sha256,
        "MintAgent returned another CA"
    );
    ensure!(
        !response.agent_cert_pem.is_empty() && !response.agent_key_pem.is_empty(),
        "MintAgent returned an incomplete credential"
    );
    let directory = super::write_agent_bundle(
        &grant.node_data_directory,
        actor,
        &response.agent_cert_pem,
        &response.agent_key_pem,
        &response.ca_pem,
    )?;
    let receipt = Receipt {
        version: 1,
        actor: actor.clone(),
        operation_id: attempt.claim.operation_id.clone(),
        credential_directory: directory,
    };
    create_secret(result_file, &serde_json::to_vec(&receipt)?)?;
    Ok(receipt)
}

/// Bounded public JSON stdin/stdout; private key bytes never enter stdout.
pub(super) async fn run(grant: &Path) -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().take(8193).read_to_end(&mut input)?;
    let prepared = (|| {
        if input.len() > 8192 {
            bail!("operator claim exceeds 8 KiB");
        }
        prepare(grant, serde_json::from_slice(&input)?)
    })();
    let outcome = match prepared {
        Ok((grant, attempt, tls)) => issue(grant, attempt, tls).await,
        Err(error) => Err(Failure::NotSubmitted(error)),
    };
    let result = match outcome {
        Ok(receipt) => serde_json::to_value(receipt)?,
        Err(Failure::NotSubmitted(error)) => {
            serde_json::json!({"outcome":"not_submitted","detail":error.to_string()})
        }
        Err(Failure::Unknown(error)) => {
            serde_json::json!({"outcome":"unknown","detail":error.to_string()})
        }
    };
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{generate_node_cert, generate_zone_ca};

    /// Write the TLS bundle a Node data directory presents for `node_id`. The
    /// display CN names the host when given (founder bootstrap) and the Node
    /// ID otherwise (enrollment); the identity URI SAN is the same either way.
    fn certify(data: &Path, node_id: u64, host: Option<&str>, ca: &[u8], ca_key: &[u8]) {
        let (cert, key) = generate_node_cert(node_id, "root", ca, ca_key, &[], host).unwrap();
        let tls = data.join("tls");
        std::fs::create_dir_all(&tls).unwrap();
        std::fs::write(tls.join("ca.pem"), ca).unwrap();
        std::fs::write(tls.join("node.pem"), cert).unwrap();
        std::fs::write(tls.join("node-key.pem"), key).unwrap();
    }

    /// An initialized grant for Node 7 plus its granted workspace.
    fn grant_for_node(root: &Path, endpoint: &str) -> (PathBuf, PathBuf, Vec<u8>, Vec<u8>) {
        let (data, workspace) = (root.join("data"), root.join("project"));
        std::fs::create_dir_all(&workspace).unwrap();
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        certify(&data, 7, Some("DESKTOP-K2PHFNR"), &ca, &ca_key);
        let file = root.join("private").join("grant.json");
        initialize(&file, &data, endpoint, vec![workspace.clone()]).unwrap();
        (file, workspace, ca, ca_key)
    }

    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        (directory, root)
    }

    #[test]
    fn a_grant_binds_the_node_and_cluster_rather_than_one_certificate() {
        let (_directory, root) = scratch();
        let (file, _, ca, ca_key) = grant_for_node(&root, "https://127.0.0.1:2");
        let grant: Grant = read_json(&file).unwrap();
        assert_eq!(grant.owner_node_identity, "nexus://zone/root/node/7");
        validate_target(&grant).unwrap();

        // `enroll` renews the hostname-CN founder leaf as a numeric-CN leaf
        // with a new key and serial for the same Node.
        certify(&grant.node_data_directory, 7, None, &ca, &ca_key);
        validate_target(&grant).unwrap();

        certify(&grant.node_data_directory, 8, None, &ca, &ca_key);
        let error = validate_target(&grant).unwrap_err().to_string();
        assert_eq!(error, "operator Node identity changed");

        let (foreign, foreign_key) = generate_zone_ca("root").unwrap();
        certify(&grant.node_data_directory, 7, None, &foreign, &foreign_key);
        let error = validate_target(&grant).unwrap_err().to_string();
        assert_eq!(error, "operator cluster CA changed");
    }

    #[tokio::test]
    async fn an_unreachable_issuer_is_not_submitted_and_reserves_nothing() {
        let (_directory, root) = scratch();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("https://{}", closed.local_addr().unwrap());
        drop(closed);
        let (file, workspace, _, _) = grant_for_node(&root, &endpoint);
        let claim = Claim {
            version: 1,
            actor: format!("codex-{}", "a".repeat(32)),
            operation_id: "00000000-0000-4000-8000-000000000001".into(),
            thread_id: "10000000-0000-4000-8000-000000000001".into(),
            workspace,
        };
        // The same operation stays runnable: neither attempt leaves a record.
        for _ in 0..2 {
            let (grant, attempt, tls) = prepare(&file, claim.clone()).unwrap();
            let reservation = grant
                .state_directory
                .join(format!("{}.attempt.json", claim.actor));
            let Err(Failure::NotSubmitted(error)) = issue(grant, attempt, tls).await else {
                panic!("a refused connection must be reported as not submitted");
            };
            assert!(error.to_string().contains("connect"), "{error}");
            assert!(!reservation.exists(), "nothing was reserved");
        }
    }
}
