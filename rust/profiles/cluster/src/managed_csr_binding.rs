//! Owner-resolved CSR preparation on the actual managed host. Uses the native
//! context-aware Call service and the SAME registry, caller-key persistence and
//! issuer request codec. Issuance reuses the daemon's existing CA-holder slot;
//! publication never implies managed-runtime activation or domain admission.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use contracts::{OperationContext, RustCallError, RustService};
use kernel::kernel::{Kernel, ServiceDecl};
use lib::transport_primitives::first_certificate_der;
use managed_agent::credential_binding::ManagedCredentialBinding;
use nexus_raft::{
    agent_csr_client::{AgentCsrBinding, PendingAgentCsr},
    agent_minter::agent_csr_request_digest,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NAME: &str = "managed_agent_credentials";
const METHODS: &[&str] = &[
    "capabilities_v1",
    "prepare_v1",
    "inspect_v1",
    "issue_v1",
    "query_v1",
    "publish_v1",
];

mod issuance;
pub(super) use issuance::NativeIssuer;

pub(super) fn service_decl(
    root: PathBuf,
    identity_armed: bool,
    issuer: Option<NativeIssuer>,
) -> anyhow::Result<ServiceDecl> {
    if !identity_armed {
        anyhow::bail!("managed Agent credential preparation requires an armed identity plane");
    }
    let root = controlled_root(&root).map_err(anyhow::Error::msg)?;
    let ca = std::fs::read(root.join("ca.pem"))?;
    lib::transport_primitives::ca_spki_sha256(&ca).map_err(anyhow::Error::msg)?;
    Ok(ServiceDecl {
        name: NAME.into(),
        install: Box::new(move |kernel| {
            let service = Arc::new(PreparationService {
                kernel: kernel.clone(),
                root: root.clone(),
                ca: ca.clone(),
                issuer,
            });
            kernel.register_rust_service(NAME, service.clone(), service.exports())
        }),
    })
}

fn controlled_root(root: &Path) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_dir() {
        return Err(
            "credential storage must be an existing native directory, not a symlink".into(),
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("native credential directory must not be a reparse point".into());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(
                "native credential directory must not be writable by another user/group".into(),
            );
        }
    }
    // This directory is chosen by the trusted daemon, never the request. Keys
    // use the shared 0600/owner-DACL create-new primitive, not inherited access.
    std::fs::canonicalize(root).map_err(|e| e.to_string())
}

struct PreparationService {
    kernel: Arc<Kernel>,
    root: PathBuf,
    ca: Vec<u8>,
    issuer: Option<NativeIssuer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    pid: String,
    operation_id: String,
}

impl PreparationService {
    fn operation_key(agent: &str, owner: &str, operation: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"nexus-managed-agent-storage-v1\0");
        for field in [agent, owner, operation] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn pending_path(&self, managed: &ManagedCredentialBinding, operation: &str) -> PathBuf {
        self.root.join(format!(
            "managed-csr-{}.json",
            Self::operation_key(managed.agent(), managed.owner(), operation)
        ))
    }

    fn request(&self, payload: &[u8]) -> Result<Target, RustCallError> {
        if payload.len() > 4096 {
            return Err(RustCallError::InvalidArgument(
                "credential request exceeds 4 KiB".into(),
            ));
        }
        let target: Target = serde_json::from_slice(payload)
            .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
        contracts::validate_operation_id(&target.operation_id)
            .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
        if target.pid.is_empty() || target.pid.len() > 256 {
            return Err(RustCallError::InvalidArgument(
                "invalid existing PID or operation ID".into(),
            ));
        }
        Ok(target)
    }
    fn prepare(
        &self,
        verb: &str,
        target: Target,
        ctx: &OperationContext,
    ) -> Result<Value, RustCallError> {
        let registry = self.kernel.agent_registry();
        let managed = ManagedCredentialBinding::resolve(registry, ctx, &target.pid)?;
        let binding = AgentCsrBinding {
            agent_name: managed.agent(),
            owner_id: managed.owner(),
            display_name: managed.agent(),
            operation_id: &target.operation_id,
        };
        // One bounded filename in the existing owner-controlled TLS directory.
        // Neither caller paths nor arbitrary sender/owner strings are accepted.
        let path = self.pending_path(&managed, &target.operation_id);
        let pending = if verb == "prepare_v1" {
            PendingAgentCsr::create(&path, &binding, &self.ca)
        } else {
            PendingAgentCsr::load(&path, &binding, &self.ca)
        };
        let mut response = json!({"schemaVersion":1,"operationId":target.operation_id,
            "issuanceSubmitted":false,"managedRuntimeActivated":false});
        match pending {
            Ok(pending) => {
                if let Err(error) = managed.ensure_current(registry) {
                    response["localPreparationOutcome"] = "unknown".into();
                    response["error"] =
                        format!("managed binding changed after preparation: {error:?}").into();
                    return Ok(response);
                }
                let request = pending.request();
                response["localPreparationOutcome"] = "prepared".into();
                response["binding"] = json!({"pid":managed.pid(),"agentId":managed.agent(),"ownerId":managed.owner(),"zone":managed.zone()});
                response["requestSha256"] =
                    json!(agent_csr_request_digest(request).map_err(RustCallError::Internal)?);
                // All request fields are public. The private key never leaves
                // PendingAgentCsr or enters a response/model transcript.
                response["publicRequest"] = json!({"agent_name":request.agent_name,"owner_id":request.owner_id,
                    "display_name":request.display_name,"operation_id":request.operation_id,
                    "csr_pem":request.csr_pem,"issuer_sha256":request.issuer_sha256});
            }
            Err(error) => {
                // Preparation may have persisted partial bytes. Never replace
                // its request/key; inspect the SAME operation explicitly.
                response["localPreparationOutcome"] = "unknown".into();
                response["error"] = error.into();
            }
        }
        Ok(response)
    }
}

impl RustService for PreparationService {
    fn name(&self) -> &str {
        NAME
    }
    fn exports(&self) -> Vec<String> {
        METHODS.iter().map(|s| s.to_string()).collect()
    }
    fn dispatch(
        &self,
        method: &str,
        payload: &[u8],
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, RustCallError> {
        if payload.len() > 4096 {
            return Err(RustCallError::InvalidArgument(
                "credential request exceeds 4 KiB".into(),
            ));
        }
        let response = match method {
            "capabilities_v1" => {
                let empty: Value = serde_json::from_slice(payload)
                    .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?;
                if empty != json!({}) {
                    return Err(RustCallError::InvalidArgument(
                        "capabilities requires an empty object".into(),
                    ));
                }
                let issuance = self
                    .issuer
                    .as_ref()
                    .is_some_and(|issuer| issuer.minter(&self.ca).is_ok());
                json!({"prepareVersion":1,"issuanceVersion":u32::from(issuance),"activationVersion":0,
                    "issuerSha256": <[u8;32]>::from(Sha256::digest(first_certificate_der(&self.ca,"native Agent issuer").map_err(RustCallError::Internal)?))})
            }
            "prepare_v1" | "inspect_v1" => self.prepare(method, self.request(payload)?, ctx)?,
            "issue_v1" | "query_v1" | "publish_v1" => {
                self.issue(method, self.request(payload)?, ctx)?
            }
            _ => return Err(RustCallError::NotFound),
        };
        serde_json::to_vec(&response).map_err(|e| RustCallError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
