//! Thin operator transport for the shared caller-owned CSR implementation.
//! Native deploy adapters resolve the actual managed descriptor/owner before
//! invoking this Node-privileged interface. No issuer/store/daemon is opened.

use std::path::PathBuf;

use anyhow::{Context, Result};
use lib::transport_primitives::{create_channel, first_certificate_der, ClientConfig, TlsConfig};
use nexus_raft::{
    agent_csr_client::{AgentCsrBinding, PendingAgentCsr},
    agent_minter::agent_csr_request_digest,
    transport::{
        current_local_node_certificate,
        proto::{
            zone_api_service_client::ZoneApiServiceClient, AgentCsrCapabilitiesRequest,
            AgentCsrState,
        },
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::CommonArgs;

#[derive(Debug, clap::Args)]
pub(super) struct RequestArgs {
    /// One explicit HTTPS issuer. Never tries self/founder/offline fallbacks.
    #[arg(long)]
    endpoint: String,
    /// Actual managed Agent id, resolved by its native owner-checked host.
    #[arg(long)]
    agent: String,
    #[arg(long)]
    owner: String,
    #[arg(long, default_value = "")]
    display_name: String,
    /// The original operation id, retained through an ambiguous response.
    #[arg(long)]
    operation: String,
    /// New or already-persisted owner-only document in controlled storage.
    #[arg(long)]
    pending_file: PathBuf,
}

impl RequestArgs {
    fn binding(&self) -> AgentCsrBinding<'_> {
        AgentCsrBinding {
            agent_name: &self.agent,
            owner_id: &self.owner,
            display_name: &self.display_name,
            operation_id: &self.operation,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
pub(super) enum CsrCommand {
    /// Verify issuer support and persist a NEW key/request. Does not issue.
    Prepare(RequestArgs),
    /// Submit the exact EXISTING request once, or explicitly finish its same I/F.
    Issue(RequestArgs),
    /// Observe the original operation without issuing, signing or publishing.
    Query(RequestArgs),
    /// Query and publish verified F in the existing bundle format, manifest last.
    Publish {
        #[command(flatten)]
        request: RequestArgs,
        /// Explicit versioned output directory; no existing credential is adopted.
        #[arg(long)]
        bundle_dir: PathBuf,
    },
}

struct Failure {
    status: &'static str,
    submitted: bool,
    error: String,
}
impl Failure {
    fn preflight(error: impl ToString) -> Self {
        Self {
            status: "not_submitted",
            submitted: false,
            error: error.to_string(),
        }
    }
    fn unknown(error: impl ToString, submitted: bool) -> Self {
        Self {
            status: "unknown",
            submitted,
            error: error.to_string(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn state_name(state: AgentCsrState) -> &'static str {
    match state {
        AgentCsrState::Unspecified => "unspecified",
        AgentCsrState::Finalized => "finalized",
        AgentCsrState::IntentCommitted => "intent_committed",
        AgentCsrState::NotObserved => "not_observed",
        AgentCsrState::NotSubmitted => "not_submitted",
        AgentCsrState::Unknown => "unknown",
    }
}

fn node_tls(common: &CommonArgs, endpoint: &str) -> Result<TlsConfig> {
    if common.no_tls {
        anyhow::bail!("caller-owned CSR requires actual local Node mTLS");
    }
    let uri: tonic::codegen::http::Uri = endpoint.parse().context("invalid issuer URI")?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
    {
        anyhow::bail!("issuer must be an HTTPS authority without credentials, path or query");
    }
    let directory = common.data_dir.join("tls");
    let tls = TlsConfig {
        ca_pem: std::fs::read(directory.join("ca.pem")).context("read local issuer CA")?,
        cert_pem: std::fs::read(directory.join("node.pem"))
            .context("read local Node certificate")?,
        key_pem: std::fs::read(directory.join("node-key.pem")).context("read local Node key")?,
    };
    let ca = first_certificate_der(&tls.ca_pem, "local issuer CA").map_err(anyhow::Error::msg)?;
    let leaf = first_certificate_der(&tls.cert_pem, "local Node certificate")
        .map_err(anyhow::Error::msg)?;
    current_local_node_certificate(&leaf, &ca).map_err(anyhow::Error::msg)?;
    Ok(tls)
}

pub(super) async fn run(common: CommonArgs, command: CsrCommand) -> Result<()> {
    let (verb, request, bundle) = match command {
        CsrCommand::Prepare(args) => ("prepare", args, None),
        CsrCommand::Issue(args) => ("issue", args, None),
        CsrCommand::Query(args) => ("query", args, None),
        CsrCommand::Publish {
            request,
            bundle_dir,
        } => ("publish", request, Some(bundle_dir)),
    };
    let (receipt, success) = match execute(&common, verb, &request, bundle.as_deref()).await {
        Ok(value) => value,
        Err(failure) => (
            json!({
                "schemaVersion": 1, "action": format!("agent-credential.{verb}"),
                "status": failure.status, "outcomeScope": "this_command",
                "issuanceSubmitted": failure.submitted,
                "operationId": request.operation, "pendingFile": request.pending_file,
                "error": failure.error, "managedRuntimeActivated": false,
            }),
            false,
        ),
    };
    println!("{receipt}");
    if !success {
        anyhow::bail!("CSR command did not complete; retain the original operation and inspect its JSON receipt");
    }
    Ok(())
}

async fn execute(
    common: &CommonArgs,
    verb: &str,
    args: &RequestArgs,
    bundle: Option<&std::path::Path>,
) -> std::result::Result<(Value, bool), Failure> {
    let tls = node_tls(common, &args.endpoint).map_err(Failure::preflight)?;
    let ca = tls.ca_pem.clone();
    let issuer_der = first_certificate_der(&ca, "local issuer CA").map_err(Failure::preflight)?;
    let expected_issuer = Sha256::digest(issuer_der).to_vec();
    let config = ClientConfig {
        tls: Some(tls),
        ..Default::default()
    };
    let channel = create_channel(&args.endpoint, &config)
        .await
        .map_err(Failure::preflight)?;
    let mut client = ZoneApiServiceClient::new(channel);
    // Read-only preflight is not permission or authoritative-store readiness.
    // A later refusal/Unknown never causes another issue or another key.
    let caps = client
        .get_agent_csr_capabilities(AgentCsrCapabilitiesRequest {})
        .await
        .map_err(Failure::preflight)?
        .into_inner();
    if caps.version != 1 || caps.issuer_sha256 != expected_issuer {
        return Err(Failure::preflight(
            "unsupported CSR capability or a different issuer",
        ));
    }
    let binding = args.binding();
    let pending = if verb == "prepare" {
        PendingAgentCsr::create(&args.pending_file, &binding, &ca)
    } else {
        PendingAgentCsr::load(&args.pending_file, &binding, &ca)
    }
    .map_err(Failure::preflight)?;
    let mut receipt = json!({
        "schemaVersion": 1, "action": format!("agent-credential.{verb}"),
        "outcomeScope": "this_command", "operationId": args.operation,
        "agent": args.agent, "owner": args.owner, "pendingFile": args.pending_file,
        "requestSha256": hex(&agent_csr_request_digest(pending.request()).map_err(Failure::preflight)?),
        "issuerSha256": hex(&expected_issuer), "issuanceSubmitted": false,
        "pendingRetained": true, "managedRuntimeActivated": false,
    });
    if verb == "prepare" {
        receipt["status"] = "prepared".into();
        return Ok((receipt, true));
    }
    let submitted = verb == "issue";
    let response = if submitted {
        client.issue_agent_csr_v1(pending.request().clone()).await
    } else {
        client.query_agent_csr_v1(pending.request().clone()).await
    }
    .map_err(|error| Failure::unknown(error, submitted))?
    .into_inner();
    let state = pending
        .observe(&response)
        .map_err(|error| Failure::unknown(error, submitted))?;
    receipt["issuanceSubmitted"] = submitted.into();
    receipt["nativeState"] = state_name(state).into();
    if matches!(
        state,
        AgentCsrState::IntentCommitted | AgentCsrState::Finalized
    ) {
        receipt["serial"] = hex(&response.serial).into();
        receipt["intentSha256"] = hex(&response.intent_sha256).into();
    }
    if state == AgentCsrState::Finalized {
        receipt["certificateSha256"] = hex(&Sha256::digest(&response.certificate_der)).into();
    }
    receipt["status"] = match state {
        AgentCsrState::Unknown | AgentCsrState::Unspecified => "unknown",
        AgentCsrState::NotSubmitted => "not_submitted",
        _ => "observed",
    }
    .into();
    if let Some(error) = &response.error {
        receipt["error"] = error.as_str().into();
    }
    if let Some(directory) = bundle {
        if state == AgentCsrState::Finalized {
            let path = pending
                .publish(&response, directory)
                .map_err(|error| Failure::unknown(error, false))?;
            receipt["status"] = "published".into();
            receipt["credentialManifest"] = path.to_string_lossy().into_owned().into();
            return Ok((receipt, true));
        }
        return Ok((receipt, false));
    }
    let success = if submitted {
        state == AgentCsrState::Finalized
    } else {
        matches!(
            state,
            AgentCsrState::Finalized | AgentCsrState::IntentCommitted | AgentCsrState::NotObserved
        )
    };
    Ok((receipt, success))
}
