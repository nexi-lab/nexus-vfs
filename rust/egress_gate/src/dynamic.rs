//! Live policy loaded from a deployment-owned file. The existing egress service
//! keeps its hook for its entire lifetime; policy replacement has no unhook gap.

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use contracts::rust_service::{RustCallError, RustService};
use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};
use kernel::kernel::{OperationContext, ServiceDecl};
use serde::{Deserialize, Serialize};

use crate::{EgressContentHook, GateConfig, GatePolicy, PresidioSettings, DEFAULT_EGRESS_SUFFIXES};

pub const ENV_CONFIG: &str = "NEXUS_EGRESS_GATE_CONFIG";
const MAX_BYTES: u64 = 1024 * 1024;
const MAX_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDocument {
    pub version: u32,
    pub revision: u64,
    pub enabled: bool,
    pub mode: String,
    pub model_mounts: Vec<String>,
    pub a2a_mounts: Vec<String>,
    #[serde(deserialize_with = "required_analyzer")]
    pub analyzer: Option<Analyzer>,
    pub business_policy: BusinessPolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Analyzer {
    pub url: String,
    pub language: String,
    pub score_threshold: f64,
    pub entities: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BusinessPolicy {
    pub version: u32,
    pub public_organizations: Vec<String>,
    pub protected_terms: Vec<String>,
    pub protected_markers: Vec<String>,
}

fn required_analyzer<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Analyzer>, D::Error> {
    Option::<Analyzer>::deserialize(deserializer)
}

impl PolicyDocument {
    fn build(&self, suffix: Option<&'static str>) -> Result<EgressContentHook, String> {
        if self.version != 1 || self.revision > MAX_REVISION || self.business_policy.version != 1 {
            return Err("unsupported egress policy version or revision".into());
        }
        let policy = match self.mode.as_str() {
            "redact" => GatePolicy::default(),
            "deny" => GatePolicy::deny_on_finding(),
            "observe" => GatePolicy::observe_only(),
            _ => return Err("invalid egress policy mode".into()),
        };
        for mounts in [&self.model_mounts, &self.a2a_mounts] {
            validate_list(mounts, 256, |path| {
                path.len() <= 1024
                    && path.starts_with('/')
                    && !path.starts_with("/__sys__")
                    && path
                        .split('/')
                        .skip(1)
                        .all(|part| !part.is_empty() && part != "." && part != "..")
                    && !path.chars().any(|c| c.is_control() || c == '\\')
            })?;
        }
        if self.enabled && self.model_mounts.is_empty() && self.a2a_mounts.is_empty() {
            return Err("enabled egress policy requires an outbound mount".into());
        }
        for values in [
            &self.business_policy.public_organizations,
            &self.business_policy.protected_terms,
            &self.business_policy.protected_markers,
        ] {
            validate_list(values, 10000, |value| {
                !value.trim().is_empty() && value.chars().count() <= 512
            })?;
        }
        let has_business_policy = !self.business_policy.public_organizations.is_empty()
            || !self.business_policy.protected_terms.is_empty()
            || !self.business_policy.protected_markers.is_empty();
        if has_business_policy && self.analyzer.is_none() {
            return Err("business policy requires the local analyzer".into());
        }
        let presidio = if let Some(a) = &self.analyzer {
            if !matches!(a.language.as_str(), "zh" | "en")
                || !a.score_threshold.is_finite()
                || !(0.0..=1.0).contains(&a.score_threshold)
                || a.timeout_ms == 0
                || a.timeout_ms > 60000
            {
                return Err("invalid egress analyzer settings".into());
            }
            validate_list(&a.entities, 256, |entity| {
                !entity.is_empty()
                    && entity.len() <= 64
                    && entity.as_bytes()[0].is_ascii_uppercase()
                    && entity
                        .bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
            })?;
            Some(PresidioSettings {
                url: a.url.clone(),
                language: a.language.clone(),
                score_threshold: a.score_threshold,
                entities: a.entities.clone(),
                timeout: std::time::Duration::from_millis(a.timeout_ms),
            })
        } else {
            None
        };
        let config = GateConfig {
            policy,
            model_mounts: self.model_mounts.clone(),
            a2a_mounts: self.a2a_mounts.clone(),
            presidio,
        };
        let planes = config.planes(suffix)?;
        let classifier = config.classifier()?;
        #[cfg(feature = "presidio")]
        let classifier = if let Some(a) = &self.analyzer {
            let analyzer =
                crate::presidio::PresidioAnalyzer::new(crate::presidio::PresidioConfig {
                    url: a.url.clone(),
                    language: a.language.clone(),
                    score_threshold: a.score_threshold,
                    entities: a.entities.clone(),
                    timeout: std::time::Duration::from_millis(a.timeout_ms),
                })?
                .with_business_policy(
                    serde_json::to_value(&self.business_policy)
                        .map_err(|_| "cannot encode business policy")?,
                );
            Arc::new(crate::AllOf::new(vec![
                crate::deterministic(),
                Arc::new(analyzer),
            ])) as Arc<dyn crate::EgressClassifier>
        } else {
            classifier
        };
        Ok(EgressContentHook::policy_snapshot(
            classifier, policy, planes,
        ))
    }
}

fn validate_list(
    values: &[String],
    max: usize,
    valid: impl Fn(&str) -> bool,
) -> Result<(), String> {
    let unique: std::collections::HashSet<_> = values.iter().collect();
    if values.len() > max
        || unique.len() != values.len()
        || values.iter().any(|value| !valid(value))
    {
        return Err("invalid egress policy list".into());
    }
    Ok(())
}

struct Active {
    bytes: Vec<u8>,
    document: PolicyDocument,
    hook: Arc<EgressContentHook>,
    error: Option<String>,
}

struct LivePolicy {
    path: PathBuf,
    suffix: Option<&'static str>,
    active: Mutex<Active>,
}

fn read(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|_| "egress policy file is unavailable")?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read egress policy file")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("egress policy file exceeds size limit".into());
    }
    Ok(bytes)
}

fn decode(
    bytes: &[u8],
    suffix: Option<&'static str>,
) -> Result<(PolicyDocument, Arc<EgressContentHook>), String> {
    // Parse errors may quote submitted values; never return those values to logs.
    let document: PolicyDocument =
        serde_json::from_slice(bytes).map_err(|_| "invalid egress policy document")?;
    let hook = Arc::new(
        document
            .build(suffix)
            .map_err(|_| "invalid egress policy settings")?,
    );
    Ok((document, hook))
}

impl LivePolicy {
    fn open(path: PathBuf, suffix: Option<&'static str>) -> Result<Self, String> {
        let bytes = read(&path)?;
        let (document, hook) = decode(&bytes, suffix)?;
        Ok(Self {
            path,
            suffix,
            active: Mutex::new(Active {
                bytes,
                document,
                hook,
                error: None,
            }),
        })
    }

    fn refresh(&self) -> std::sync::MutexGuard<'_, Active> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let candidate = read(&self.path).and_then(|bytes| {
            if bytes == active.bytes {
                return Ok(None);
            }
            let (document, hook) = decode(&bytes, self.suffix)?;
            if document.revision <= active.document.revision {
                return Err("egress policy revision must increase".into());
            }
            Ok(Some((bytes, document, hook)))
        });
        match candidate {
            Ok(Some((bytes, document, hook))) => {
                tracing::info!(revision = document.revision, enabled = document.enabled, mode = %document.mode, "egress policy applied");
                *active = Active {
                    bytes,
                    document,
                    hook,
                    error: None,
                };
            }
            Ok(None) => active.error = None,
            Err(error) => active.error = Some(error),
        }
        active
    }
}

struct LiveHook {
    policy: Arc<LivePolicy>,
    suffixes: &'static [&'static str],
}

impl NativeInterceptHook for LiveHook {
    fn name(&self) -> &str {
        "egress_content_gate"
    }
    fn mutating_path_suffixes(&self) -> &'static [&'static str] {
        self.suffixes
    }
    fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
        if contracts::is_system_path(ctx.path()) {
            return Ok(HookOutcome::Pass);
        }
        let HookContext::Write(write) = ctx else {
            return Ok(HookOutcome::Pass);
        };
        if write.content.is_empty() {
            return Ok(HookOutcome::Pass);
        }
        let active = self.policy.refresh();
        if !active.hook.claims(&write.path) {
            return Ok(HookOutcome::Pass);
        }
        if active.error.is_some() {
            return Err("egress gate: policy configuration is unavailable".into());
        }
        if !active.document.enabled {
            return Ok(HookOutcome::Pass);
        }
        let hook = Arc::clone(&active.hook);
        drop(active);
        hook.on_pre(ctx)
    }
}

impl RustService for LivePolicy {
    fn name(&self) -> &str {
        super::SERVICE_NAME
    }
    fn exports(&self) -> Vec<String> {
        vec!["get_policy_status_v1".into()]
    }
    fn dispatch(
        &self,
        method: &str,
        payload: &[u8],
        _ctx: &OperationContext,
    ) -> Result<Vec<u8>, RustCallError> {
        if method != "get_policy_status_v1" {
            return Err(RustCallError::NotFound);
        }
        let request: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|_| RustCallError::InvalidArgument("invalid status request".into()))?;
        if request.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(RustCallError::InvalidArgument(
                "status request must be empty".into(),
            ));
        }
        let active = self.refresh();
        let doc = &active.document;
        serde_json::to_vec(&serde_json::json!({ "version": 1, "revision": doc.revision,
            "enabled": doc.enabled, "mode": doc.mode, "modelMounts": doc.model_mounts,
            "a2aMounts": doc.a2a_mounts, "error": active.error }))
        .map_err(|_| RustCallError::Internal("cannot encode policy status".into()))
    }
}

/// Install the existing service with a read-only status RPC and a stable hook.
/// The file belongs to the deployment; no agent-facing policy mutation RPC exists.
pub fn service_decl(path: PathBuf, suffix: Option<&'static str>) -> ServiceDecl {
    ServiceDecl {
        name: super::SERVICE_NAME.into(),
        install: Box::new(move |kernel| {
            let policy = Arc::new(LivePolicy::open(path, suffix)?);
            kernel.register_rust_service(
                super::SERVICE_NAME,
                Arc::clone(&policy) as Arc<dyn RustService>,
                policy.exports(),
            )?;
            let handle = kernel
                .service_handle(super::SERVICE_NAME)
                .ok_or("egress service handle is missing")?;
            let mut leaves = DEFAULT_EGRESS_SUFFIXES.to_vec();
            if let Some(suffix) = suffix {
                if !leaves.contains(&suffix) {
                    leaves.push(suffix);
                }
            }
            let suffixes = Box::leak(leaves.into_boxed_slice());
            kernel.register_service_hook(&handle, Box::new(LiveHook { policy, suffixes }));
            Ok(())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::core::dispatch::{HookIdentity, WriteHookCtx};

    fn document(revision: u64, enabled: bool, mode: &str) -> serde_json::Value {
        serde_json::json!({ "version": 1, "revision": revision, "enabled": enabled,
            "mode": mode, "modelMounts": ["/cloud-model"], "a2aMounts": [], "analyzer": null,
            "businessPolicy": { "version": 1, "public_organizations": [], "protected_terms": [], "protected_markers": [] } })
    }

    fn write(path: &str) -> HookContext {
        HookContext::Write(WriteHookCtx {
            path: path.into(),
            identity: HookIdentity {
                user_id: "u".into(),
                zone_id: "root".into(),
                agent_id: "agent".into(),
                is_admin: false,
            },
            content: br#"{"messages":[{"role":"user","content":"11010519491231002X"}]}"#.to_vec(),
            is_new_file: false,
            content_id: None,
            new_version: 0,
            size_bytes: None,
        })
    }

    #[test]
    fn a_single_hook_applies_off_redact_deny_and_off_without_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, document(0, false, "redact").to_string()).unwrap();
        let policy = Arc::new(LivePolicy::open(path.clone(), Some(".prompt")).unwrap());
        let hook = LiveHook {
            policy,
            suffixes: &[".prompt"],
        };
        assert!(matches!(
            hook.on_pre(&write("/cloud-model/ask.prompt")).unwrap(),
            HookOutcome::Pass
        ));
        std::fs::write(&path, document(1, true, "redact").to_string()).unwrap();
        let HookOutcome::Replace(bytes) = hook.on_pre(&write("/cloud-model/ask.prompt")).unwrap()
        else {
            panic!("expected redaction")
        };
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("11010519491231002X"));
        assert!(matches!(
            hook.on_pre(&write("/model/ask.prompt")).unwrap(),
            HookOutcome::Pass
        ));
        std::fs::write(&path, document(2, true, "deny").to_string()).unwrap();
        assert!(hook.on_pre(&write("/cloud-model/ask.prompt")).is_err());
        std::fs::write(&path, document(3, false, "redact").to_string()).unwrap();
        assert!(matches!(
            hook.on_pre(&write("/cloud-model/ask.prompt")).unwrap(),
            HookOutcome::Pass
        ));
    }

    #[test]
    fn invalid_or_rollback_policy_cannot_silently_disable_protection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, document(2, true, "redact").to_string()).unwrap();
        let policy = Arc::new(LivePolicy::open(path.clone(), Some(".prompt")).unwrap());
        let hook = LiveHook {
            policy: Arc::clone(&policy),
            suffixes: &[".prompt"],
        };
        for candidate in [
            "{}".to_owned(),
            document(1, false, "redact").to_string(),
            document(2, false, "redact").to_string(),
        ] {
            std::fs::write(&path, candidate).unwrap();
            assert!(hook.on_pre(&write("/cloud-model/ask.prompt")).is_err());
            assert_eq!(policy.refresh().document.revision, 2);
            assert!(matches!(
                hook.on_pre(&write("/model/ask.prompt")).unwrap(),
                HookOutcome::Pass
            ));
        }
        std::fs::remove_file(&path).unwrap();
        assert!(hook.on_pre(&write("/cloud-model/ask.prompt")).is_err());
    }

    #[test]
    fn status_never_discloses_business_values_and_has_no_agent_mutation_method() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, document(0, false, "redact").to_string()).unwrap();
        let policy = LivePolicy::open(path, Some(".prompt")).unwrap();
        let ctx = OperationContext::new("u", "root", false, Some("agent"), false);
        let result = policy
            .dispatch("get_policy_status_v1", b"{}", &ctx)
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(status["revision"], 0);
        assert!(status.get("businessPolicy").is_none());
        assert!(matches!(
            policy.dispatch("set_policy_v1", b"{}", &ctx),
            Err(RustCallError::NotFound)
        ));
    }
}
