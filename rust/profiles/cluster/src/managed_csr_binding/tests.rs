use super::*;
use kernel::core::agents::registry::{AgentDescriptor, AgentKind, AgentState};

const OP: &str = "d5881c0c-4886-4445-976a-e42c95829b16";
fn owner(name: &str) -> OperationContext {
    let mut context =
        OperationContext::new(name, "root", false, Some("actual-session-leaf"), false);
    context.subject_type = "agent".into();
    context.subject_id = Some("actual-session-leaf".into());
    context
}
fn descriptor() -> AgentDescriptor {
    AgentDescriptor {
        pid: "host.1".into(),
        name: "original-agent".into(),
        owner_id: "alice".into(),
        zone_id: "root".into(),
        kind: AgentKind::Managed,
        state: AgentState::Ready,
        ..Default::default()
    }
}
fn setup() -> (tempfile::TempDir, Arc<Kernel>) {
    let directory = tempfile::tempdir().unwrap();
    let (ca, _) = nexus_raft::transport::generate_zone_ca("original").unwrap();
    std::fs::write(directory.path().join("ca.pem"), ca).unwrap();
    let kernel = Arc::new(Kernel::new());
    kernel
        .bring_up_services(vec![service_decl(
            directory.path().to_path_buf(),
            true,
            None,
        )
        .unwrap()])
        .unwrap();
    let instance = kernel
        .agent_registry()
        .register_instance(descriptor())
        .unwrap();
    assert!(kernel.agent_registry().bind_managed_host(&instance));
    (directory, kernel)
}
fn payload(pid: &str, operation: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"pid":pid,"operation_id":operation})).unwrap()
}
fn call(
    kernel: &Kernel,
    verb: &str,
    payload: &[u8],
    ctx: &OperationContext,
) -> Result<Value, RustCallError> {
    let bytes = kernel
        .dispatch_rust_call_ctx(ctx, NAME, verb, payload)
        .unwrap()?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}
fn pending_file(directory: &Path) -> PathBuf {
    let files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    assert_eq!(files.len(), 1);
    files[0].clone()
}

#[test]
fn native_call_prepares_registry_binding_and_recovers_same_request_without_private_key_output() {
    let (directory, kernel) = setup();
    let before = kernel.agent_registry().get("host.1").unwrap();
    let prepared = call(
        &kernel,
        "prepare_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(prepared["localPreparationOutcome"], "prepared");
    assert_eq!(prepared["binding"]["agentId"], "original-agent");
    assert_eq!(prepared["binding"]["ownerId"], "alice");
    assert_eq!(prepared["issuanceSubmitted"], false);
    assert_eq!(prepared["managedRuntimeActivated"], false);
    let file = pending_file(directory.path());
    let bytes = std::fs::read(&file).unwrap();
    assert!(std::str::from_utf8(&bytes).unwrap().contains("PRIVATE KEY"));
    assert!(!prepared.to_string().contains("PRIVATE KEY"));
    assert_eq!(prepared["publicRequest"]["agent_name"], "original-agent");
    assert_eq!(prepared["publicRequest"]["operation_id"], OP);
    let repeated = call(
        &kernel,
        "prepare_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(repeated["localPreparationOutcome"], "unknown");
    let recovered = call(
        &kernel,
        "inspect_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(recovered["requestSha256"], prepared["requestSha256"]);
    assert_eq!(recovered["publicRequest"], prepared["publicRequest"]);
    assert_eq!(std::fs::read(file).unwrap(), bytes);
    let after = kernel.agent_registry().get("host.1").unwrap();
    assert_eq!(
        (before.pid, before.name, before.owner_id, before.state),
        (after.pid, after.name, after.owner_id, after.state)
    );
}

#[test]
fn forged_binding_paths_and_wrong_owner_admin_foreign_or_system_refuse_before_any_key() {
    let (directory, kernel) = setup();
    let input = payload("host.1", OP);
    let mut admin = owner("bob");
    admin.is_admin = true;
    let mut foreign = owner("alice");
    foreign.trust_domain = Some("elsewhere".into());
    let mut node = owner("alice");
    node.is_system = true;
    for ctx in [
        owner("bob"),
        admin,
        foreign,
        node,
        OperationContext::new("cluster-internal", "root", true, None, true),
    ] {
        assert!(matches!(
            call(&kernel, "prepare_v1", &input, &ctx),
            Err(RustCallError::PermissionDenied(_))
        ));
    }
    for field in ["owner_id", "agent_name", "sender", "pending_file"] {
        let mut forged: Value = serde_json::from_slice(&input).unwrap();
        forged[field] = "other".into();
        assert!(matches!(
            call(
                &kernel,
                "prepare_v1",
                &serde_json::to_vec(&forged).unwrap(),
                &owner("alice")
            ),
            Err(RustCallError::InvalidArgument(_))
        ));
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn original_key_survives_same_agent_reentry_but_cannot_be_adopted_by_replacement_owner() {
    let (directory, kernel) = setup();
    let prepared = call(
        &kernel,
        "prepare_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    let path = pending_file(directory.path());
    let bytes = std::fs::read(&path).unwrap();
    kernel.agent_registry().unregister("host.1").unwrap();
    let mut resumed = descriptor();
    resumed.pid = "host.2".into();
    let instance = kernel.agent_registry().register_instance(resumed).unwrap();
    assert!(kernel.agent_registry().bind_managed_host(&instance));
    let recovered = call(
        &kernel,
        "inspect_v1",
        &payload("host.2", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(recovered["localPreparationOutcome"], "prepared");
    assert_eq!(recovered["publicRequest"], prepared["publicRequest"]);
    kernel.agent_registry().unregister("host.2").unwrap();
    let mut other = descriptor();
    other.pid = "host.2".into();
    other.owner_id = "bob".into();
    let instance = kernel.agent_registry().register_instance(other).unwrap();
    assert!(kernel.agent_registry().bind_managed_host(&instance));
    let denied = call(&kernel, "inspect_v1", &payload("host.2", OP), &owner("bob")).unwrap();
    assert_eq!(denied["localPreparationOutcome"], "unknown");
    assert!(denied.get("publicRequest").is_none());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn changed_ca_and_partial_pending_refuse_without_overwrite_or_activation() {
    let (directory, kernel) = setup();
    call(
        &kernel,
        "prepare_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    let path = pending_file(directory.path());
    let bytes = std::fs::read(&path).unwrap();
    let (different, _) = nexus_raft::transport::generate_zone_ca("different").unwrap();
    let service = PreparationService {
        kernel: kernel.clone(),
        root: directory.path().to_path_buf(),
        ca: different,
        issuer: None,
    };
    let changed: Value = serde_json::from_slice(
        &service
            .dispatch("inspect_v1", &payload("host.1", OP), &owner("alice"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(changed["localPreparationOutcome"], "unknown");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::write(&path, b"{").unwrap();
    let partial = call(
        &kernel,
        "inspect_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(partial["localPreparationOutcome"], "unknown");
    assert_eq!(std::fs::read(&path).unwrap(), b"{");
}

#[test]
fn simultaneous_preparations_keep_one_persisted_request_and_explicit_recovery() {
    let (directory, kernel) = setup();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let kernel = kernel.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                call(
                    &kernel,
                    "prepare_v1",
                    &payload("host.1", OP),
                    &owner("alice"),
                )
                .unwrap()
            })
        })
        .collect();
    let values: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        values
            .iter()
            .filter(|v| v["localPreparationOutcome"] == "prepared")
            .count(),
        1
    );
    assert_eq!(
        values
            .iter()
            .filter(|v| v["localPreparationOutcome"] == "unknown")
            .count(),
        1
    );
    let prepared = values
        .iter()
        .find(|v| v["localPreparationOutcome"] == "prepared")
        .unwrap();
    let recovered = call(
        &kernel,
        "inspect_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(recovered["publicRequest"], prepared["publicRequest"]);
    pending_file(directory.path());
}

#[test]
fn service_is_not_noauth_issuer_or_activation_and_request_text_never_selects_a_path() {
    let (directory, kernel) = setup();
    assert!(service_decl(directory.path().to_path_buf(), false, None).is_err());
    let caps = call(&kernel, "capabilities_v1", b"{}", &owner("alice")).unwrap();
    assert_eq!(
        (
            caps["prepareVersion"].as_u64(),
            caps["issuanceVersion"].as_u64(),
            caps["activationVersion"].as_u64()
        ),
        (Some(1), Some(0), Some(0))
    );
    let unsupported = call(&kernel, "issue_v1", &payload("host.1", OP), &owner("alice")).unwrap();
    assert_eq!(unsupported["submissionAttempted"], false);
    assert_eq!(unsupported["issuanceOutcome"], "unknown");
    assert!(unsupported["error"]
        .as_str()
        .unwrap()
        .contains("unsupported"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    assert!(matches!(
        call(
            &kernel,
            "prepare_v1",
            &payload("host.1", "../../outside"),
            &owner("alice"),
        ),
        Err(RustCallError::InvalidArgument(_))
    ));
    let value = call(
        &kernel,
        "prepare_v1",
        &payload("host.1", "CON:retry.2"),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(value["localPreparationOutcome"], "prepared");
    assert_eq!(value["issuanceSubmitted"], false);
    let expected = PreparationService::operation_key("original-agent", "alice", "CON:retry.2");
    assert!(directory
        .path()
        .join(format!("managed-csr-{expected}.json"))
        .is_file());
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        assert_eq!(entry.unwrap().path().parent().unwrap(), directory.path());
    }
}

#[test]
fn generic_registry_metadata_never_authorizes_credential_preparation() {
    let (directory, kernel) = setup();
    let mut registrant = OperationContext::new("alice", "root", false, None, false);
    registrant.subject_type = "user".into();
    registrant.subject_id = Some("alice".into());
    registrant.zone_perms = vec![("root".into(), "rw".into())];
    let reply = transport::call_dispatch::dispatch(
        &kernel,
        &registrant,
        "agent_register",
        &serde_json::to_vec(
            &json!({"name":"forged-metadata","pid":"500.1","kind":"MANAGED",
            "owner_id":"alice","zone_id":"root","labels":{"managed_host_bound":"true"}}),
        )
        .unwrap(),
    )
    .unwrap()
    .into_inner();
    assert!(
        !reply.is_error,
        "negative must reach a real generic registry insertion: {}",
        String::from_utf8_lossy(&reply.payload)
    );
    let raw: Value = serde_json::from_slice(&reply.payload).unwrap();
    let pid = raw.get("result").unwrap_or(&raw)["pid"].as_str().unwrap();
    let record = kernel.agent_registry().get(pid).unwrap();
    assert_eq!(record.kind, AgentKind::Managed);
    assert_eq!(record.owner_id, "alice");
    assert!(
        matches!(
            call(
                &kernel,
                "prepare_v1",
                &payload(pid, "generic-register-negative"),
                &owner("alice")
            ),
            Err(RustCallError::PermissionDenied(_))
        ),
        "public registry metadata must not stand in for a native host binding"
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn owners_do_not_reserve_each_others_local_operation_namespace() {
    let (directory, kernel) = setup();
    let first = call(
        &kernel,
        "prepare_v1",
        &payload("host.1", OP),
        &owner("alice"),
    )
    .unwrap();
    assert_eq!(first["localPreparationOutcome"], "prepared");
    let mut second = descriptor();
    second.pid = "other-host.1".into();
    second.name = "other-agent".into();
    second.owner_id = "bob".into();
    let instance = kernel.agent_registry().register_instance(second).unwrap();
    assert!(kernel.agent_registry().bind_managed_host(&instance));
    let other = call(
        &kernel,
        "prepare_v1",
        &payload("other-host.1", OP),
        &owner("bob"),
    )
    .unwrap();
    assert_eq!(
        other["localPreparationOutcome"], "prepared",
        "another owned Agent's operation must not reserve this namespace"
    );
    assert_ne!(first["requestSha256"], other["requestSha256"]);
    assert_eq!(other["binding"]["ownerId"], "bob");
    assert_eq!(
        call(
            &kernel,
            "inspect_v1",
            &payload("host.1", OP),
            &owner("alice")
        )
        .unwrap()["publicRequest"],
        first["publicRequest"]
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 3);
}
