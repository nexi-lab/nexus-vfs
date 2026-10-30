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
use lib::transport_primitives::{cert_fingerprint, create_secret, first_certificate_der};
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
    owner_certificate_sha256: String,
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
        owner_certificate_sha256: fingerprint(&tls.cert_pem)?,
        ca_certificate_sha256: fingerprint(&tls.ca_pem)?,
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
        "ownerCertificateSha256":grant.owner_certificate_sha256})
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
    owner_certificate_sha256: String,
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

#[inline]
fn fingerprint(pem: &[u8]) -> Result<String> {
    let der = first_certificate_der(pem, "operator identity").map_err(anyhow::Error::msg)?;
    Ok(cert_fingerprint(&der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
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

fn prepare(
    grant_file: &Path,
    claim: Claim,
) -> Result<(Grant, Attempt, nexus_raft::transport::TlsConfig)> {
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
    let suffix = claim.actor.strip_prefix("codex-").unwrap_or_default();
    ensure!(
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "grant permits only codex-<32 lowercase hex> actors"
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
        owner_certificate_sha256: grant.owner_certificate_sha256.clone(),
        ca_certificate_sha256: grant.ca_certificate_sha256.clone(),
    };
    Ok((grant, attempt, tls))
}

#[inline]
fn validate_target(grant: &Grant) -> Result<nexus_raft::transport::TlsConfig> {
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
    ensure!(
        fingerprint(&tls.cert_pem)? == grant.owner_certificate_sha256,
        "operator Node identity changed"
    );
    ensure!(
        fingerprint(&tls.ca_pem)? == grant.ca_certificate_sha256,
        "operator cluster CA changed"
    );
    Ok(tls)
}

async fn issue(
    grant: Grant,
    attempt: Attempt,
    tls: nexus_raft::transport::TlsConfig,
) -> Result<Receipt> {
    std::fs::create_dir_all(&grant.state_directory)?;
    let actor = &attempt.claim.actor;
    let attempt_file = grant.state_directory.join(format!("{actor}.attempt.json"));
    let result_file = grant.state_directory.join(format!("{actor}.result.json"));
    let bytes = serde_json::to_vec(&attempt)?;
    match create_secret(&attempt_file, &bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let previous: Attempt = read_json(&attempt_file)?;
            ensure!(
                previous == attempt,
                "actor is reserved by another operation or target; operator recovery required"
            );
            let receipt: Receipt = read_json(&result_file).context(
                "original issuance may have committed; no RPC retry; operator recovery required",
            )?;
            ensure!(
                receipt.version == 1
                    && receipt.actor == *actor
                    && receipt.operation_id == attempt.claim.operation_id
                    && receipt.credential_directory
                        == grant.node_data_directory.join("agents").join(actor),
                "original receipt binding differs"
            );
            let loaded =
                nexus_raft::transport::AgentCredential::load(&receipt.credential_directory)
                    .map_err(anyhow::Error::msg)?;
            ensure!(loaded.agent == *actor, "persisted credential actor changed");
            return Ok(receipt);
        }
        Err(error) => return Err(error.into()),
    }
    // Persisted BEFORE opening a channel. Every error from here is Unknown,
    // including a crash, a refusal whose server semantics may differ, and loss
    // of the public reply after the credential was written. Never resubmit.
    ensure!(
        !grant
            .node_data_directory
            .join("agents")
            .join(actor)
            .exists(),
        "credential path already exists; operator recovery required"
    );
    let response = nexus_raft::transport::call_mint_agent_rpc(
        &grant.endpoint,
        actor,
        actor,
        false,
        Some(tls),
        10,
    )
    .await?;
    ensure!(
        response.success,
        "MintAgent returned a refusal: {}",
        response.error.as_deref().unwrap_or("unspecified")
    );
    ensure!(
        fingerprint(&response.ca_pem)? == grant.ca_certificate_sha256,
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
        operation_id: attempt.claim.operation_id,
        credential_directory: directory,
    };
    create_secret(&result_file, &serde_json::to_vec(&receipt)?)?;
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
    let result = match prepared {
        Err(error) => serde_json::json!({"outcome":"not_submitted","detail":error.to_string()}),
        Ok((grant, attempt, tls)) => match issue(grant, attempt, tls).await {
            Ok(receipt) => serde_json::to_value(receipt)?,
            Err(error) => serde_json::json!({"outcome":"unknown","detail":error.to_string()}),
        },
    };
    println!("{result}");
    Ok(())
}
