use super::*;
use crate::replica_control_rpc;
use contracts::replica_binding::ReplicaBindingState;
use contracts::replica_credential::ReplicaIssuanceOutcome;
use nexus_raft::transport::proto::{
    replica_control_request::Operation, ReplicaControlRequest, ReplicaControlResponse,
    ReplicaControlState, ReplicaIssuerQuery,
};
use serde::{de::DeserializeOwned, Serialize};

fn encoded(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn request(operation: Operation) -> ReplicaControlRequest {
    ReplicaControlRequest {
        operation: Some(operation),
    }
}

fn expect(reply: &ReplicaControlResponse, state: ReplicaControlState) {
    assert_eq!(
        reply.state, state as i32,
        "unexpected lifecycle reply: {reply:?}"
    );
    if state != ReplicaControlState::Result {
        assert!(reply.result_json.is_empty());
    }
}

fn decoded<T: DeserializeOwned>(reply: &ReplicaControlResponse) -> T {
    expect(reply, ReplicaControlState::Result);
    serde_json::from_slice(&reply.result_json).unwrap()
}

async fn call(
    client: &mut ZoneApiServiceClient<Channel>,
    operation: Operation,
) -> ReplicaControlResponse {
    client
        .control_replica_v1(request(operation))
        .await
        .unwrap()
        .into_inner()
}

fn registration() -> ReplicaBindingRequest {
    ReplicaBindingRequest {
        operation_id: "controller-original-registration".into(),
        allocation: ReplicaAllocation {
            owner_id: "owner-b".into(),
            allocation_id: "existing-second-home".into(),
        },
        change: ReplicaBindingChange::Register {
            storage: ReplicaStorage {
                authority: "test-control-plane".into(),
                uid: "first-pvc-uid".into(),
            },
            replica_id: 9_007_199_254_740_993,
        },
    }
}

#[test]
fn real_mtls_lifecycle_retains_exact_ids_and_original_receipts_after_replacement() {
    let f = Fixture::open();
    f.manager.runtime_handle().block_on(async {
        let (address, stop, task) = f.start().await;
        let mut client = f.connect(&address, &f.caller).await;
        let original = registration();
        let wire = encoded(&original);
        assert!(std::str::from_utf8(&wire)
            .unwrap()
            .contains("9007199254740993"));
        expect(
            &call(
                &mut client,
                Operation::CurrentBindingJson(encoded(&original.allocation)),
            )
            .await,
            ReplicaControlState::NotObserved,
        );
        expect(
            &call(&mut client, Operation::ReconcileBindingJson(wire.clone())).await,
            ReplicaControlState::NotObserved,
        );
        let applied = call(&mut client, Operation::ApplyBindingJson(wire.clone())).await;
        let ReplicaBindingOutcome::Applied(first) = decoded(&applied) else {
            panic!("registration must commit")
        };
        assert_eq!(first.replica_id, 9_007_199_254_740_993);
        assert_eq!(
            call(&mut client, Operation::ApplyBindingJson(wire.clone())).await,
            applied
        );
        let retire = ReplicaBindingRequest {
            operation_id: "controller-retirement".into(),
            allocation: original.allocation.clone(),
            change: ReplicaBindingChange::Retire {
                expected_revision: first.revision,
            },
        };
        let ReplicaBindingOutcome::Applied(retired) =
            decoded(&call(&mut client, Operation::ApplyBindingJson(encoded(&retire))).await)
        else {
            panic!("retirement must commit")
        };
        assert_eq!(retired.state, ReplicaBindingState::Retired);
        let replace = ReplicaBindingRequest {
            operation_id: "controller-replacement".into(),
            allocation: original.allocation.clone(),
            change: ReplicaBindingChange::Replace {
                expected_revision: retired.revision,
                storage: ReplicaStorage {
                    authority: "test-control-plane".into(),
                    uid: "replacement-pvc-uid".into(),
                },
                replica_id: 9_007_199_254_740_995,
            },
        };
        let ReplicaBindingOutcome::Applied(replaced) =
            decoded(&call(&mut client, Operation::ApplyBindingJson(encoded(&replace))).await)
        else {
            panic!("replacement must commit")
        };
        assert_eq!(replaced.generation, 2);
        assert_eq!(
            call(&mut client, Operation::ReconcileBindingJson(wire.clone())).await,
            applied
        );
        assert_eq!(
            call(&mut client, Operation::ApplyBindingJson(wire)).await,
            applied
        );
        let current: ReplicaBinding = decoded(
            &call(
                &mut client,
                Operation::CurrentBindingJson(encoded(&original.allocation)),
            )
            .await,
        );
        assert_eq!(current, replaced);
        assert_eq!(f.store.current_for_replica(first.replica_id).unwrap(), None);
        stop.send(()).unwrap();
        task.await.unwrap();
    });
}

#[test]
fn real_mtls_lifecycle_requires_node_and_preserves_csr_and_issuer_boundaries() {
    let f = Fixture::open();
    f.manager.runtime_handle().block_on(async {
        let (address, stop, task) = f.start().await;
        let original = registration();
        let agent = generate_agent_cert("atlas-moss", &f.ca, &f.ca_key).unwrap();
        let replica =
            generate_user_replica_cert("owner-replica", "owner-a", 47, 300, &f.ca, &f.ca_key)
                .unwrap();
        for identity in [agent, replica] {
            let mut client = f.connect(&address, &identity).await;
            let error = client
                .control_replica_v1(request(Operation::ApplyBindingJson(encoded(&original))))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::PermissionDenied);
        }
        assert_eq!(f.store.reconcile(&original).unwrap(), None);
        let mut client = f.connect(&address, &f.caller).await;
        let absent_operation = client
            .control_replica_v1(ReplicaControlRequest { operation: None })
            .await
            .unwrap()
            .into_inner();
        expect(&absent_operation, ReplicaControlState::Refused);
        expect(
            &call(&mut client, Operation::ApplyBindingJson(b"{}".to_vec())).await,
            ReplicaControlState::Refused,
        );
        let prepared = f.request("forbidden-control-prepare");
        expect(
            &call(
                &mut client,
                Operation::ApplyIssuerJson(prepared.preparation_json.clone()),
            )
            .await,
            ReplicaControlState::Refused,
        );
        expect(
            &call(
                &mut client,
                Operation::ReconcileIssuerJson(prepared.preparation_json),
            )
            .await,
            ReplicaControlState::Refused,
        );
        assert_eq!(
            f.store.credential("forbidden-control-prepare").unwrap(),
            None
        );
        let foreign = ReplicaIssuanceRequest {
            operation_id: "foreign-control-authority".into(),
            change: ReplicaIssuanceChange::Authority {
                expected_revision: Some(1),
                issuer_sha256: Some([9; 32]),
            },
        };
        expect(
            &call(&mut client, Operation::ApplyIssuerJson(encoded(&foreign))).await,
            ReplicaControlState::Refused,
        );
        assert_eq!(f.store.reconcile_issuance(&foreign).unwrap(), None);
        let current: ReplicaIssuerAuthority =
            decoded(&call(&mut client, Operation::CurrentIssuer(ReplicaIssuerQuery {})).await);
        assert_eq!(current, f.authority);
        // Lifecycle control and its readback use the verifier and durable store;
        // neither needs access to the certificate signing key.
        std::fs::rename(
            f.founder.tls_dir.join("ca-key.pem"),
            f.founder.tls_dir.join("held-key.pem"),
        )
        .unwrap();
        let disable = ReplicaIssuanceRequest {
            operation_id: "disable-control-authority".into(),
            change: ReplicaIssuanceChange::Authority {
                expected_revision: Some(1),
                issuer_sha256: None,
            },
        };
        let applied = call(&mut client, Operation::ApplyIssuerJson(encoded(&disable))).await;
        let outcome: ReplicaIssuanceOutcome = decoded(&applied);
        assert_eq!(Some(outcome), f.store.reconcile_issuance(&disable).unwrap());
        assert_eq!(
            call(
                &mut client,
                Operation::ReconcileIssuerJson(encoded(&disable))
            )
            .await,
            applied
        );
        let now: ReplicaIssuerAuthority =
            decoded(&call(&mut client, Operation::CurrentIssuer(ReplicaIssuerQuery {})).await);
        assert_eq!(now.revision, 2);
        assert_eq!(now.issuer_sha256, None);
        let der = pem::parse(&f.caller.0).unwrap().into_contents();
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        add_revoked_serial(
            &revoked_serials_path(&f.founder.data_dir),
            cert.raw_serial(),
        )
        .unwrap();
        expect(
            &call(&mut client, Operation::CurrentIssuer(ReplicaIssuerQuery {})).await,
            ReplicaControlState::Refused,
        );
        assert_eq!(f.store.issuer_authority().unwrap(), Some(now));
        stop.send(()).unwrap();
        task.await.unwrap();
    });
}

fn withdrawn_lifecycle(mutation: bool) {
    let f = Fixture::open();
    let caller = pem::parse(&f.caller.0).unwrap().into_contents();
    let authority = ReplyAuthority::capture(&f.founder, Some(&caller)).unwrap();
    let serial = authority.serial.clone();
    let revocations = revoked_serials_path(&f.founder.data_dir);
    let original = registration();
    let operation = if mutation {
        Operation::ApplyBindingJson(encoded(&original))
    } else {
        Operation::CurrentIssuer(ReplicaIssuerQuery {})
    };
    let founder = f.founder.clone();
    let reply = f
        .manager
        .runtime_handle()
        .block_on(replica_control_rpc::release(
            authority,
            mutation,
            async move {
                let completed = tokio::task::spawn_blocking(move || {
                    replica_control_rpc::execute(&founder, Some(caller), request(operation))
                })
                .await
                .unwrap();
                expect(&completed, ReplicaControlState::Result);
                add_revoked_serial(&revocations, &serial).unwrap();
                completed
            },
        ));
    expect(
        &reply,
        if mutation {
            ReplicaControlState::Unknown
        } else {
            ReplicaControlState::Refused
        },
    );
    let recovery = generate_node_cert(3, "root", &f.ca, &f.ca_key, &[], None).unwrap();
    let recovered = replica_control_rpc::execute(
        &f.founder,
        Some(pem::parse(recovery.0).unwrap().into_contents()),
        request(if mutation {
            Operation::ReconcileBindingJson(encoded(&original))
        } else {
            Operation::CurrentIssuer(ReplicaIssuerQuery {})
        }),
    );
    expect(&recovered, ReplicaControlState::Result);
    if mutation {
        let applied: ReplicaBindingOutcome = decoded(&recovered);
        assert_eq!(Some(applied), f.store.reconcile(&original).unwrap());
    } else {
        let current: ReplicaIssuerAuthority = decoded(&recovered);
        assert_eq!(current, f.authority);
        assert_eq!(f.store.reconcile(&original).unwrap(), None);
    }
}

#[test]
fn lifecycle_mutation_withdrawn_after_worker_retains_original_operation() {
    withdrawn_lifecycle(true);
}

#[test]
fn lifecycle_read_withdrawn_after_worker_withholds_observation() {
    withdrawn_lifecycle(false);
}
