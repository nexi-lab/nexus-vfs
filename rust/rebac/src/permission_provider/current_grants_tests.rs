use super::*;
use crate::store::{ReBACTupleStore, ReBACTupleStoreError};
use crate::{tuple_key, InMemoryReBACTupleStore};
use lib::types::ReBACTuple;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const PATH: &str = "/sessions/original";

struct OrderedStore {
    local: Vec<(String, Vec<u8>)>,
    current: RwLock<Vec<(String, Vec<u8>)>>,
    unavailable: AtomicBool,
    reads: AtomicUsize,
}

impl ReBACTupleStore for OrderedStore {
    fn put(&self, _: &str, _: &[u8]) -> Result<(), ReBACTupleStoreError> {
        unreachable!("fixture mutation uses its committed snapshot")
    }

    fn delete(&self, _: &str) -> Result<bool, ReBACTupleStoreError> {
        unreachable!("fixture mutation uses its committed snapshot")
    }

    fn get(&self, _: &str) -> Result<Option<Vec<u8>>, ReBACTupleStoreError> {
        unreachable!("authorization must read one complete snapshot")
    }

    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, ReBACTupleStoreError> {
        Ok(self.local.clone())
    }

    fn list_linearizable(&self) -> Result<Vec<(String, Vec<u8>)>, ReBACTupleStoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ReBACTupleStoreError::Backend(
                "ReadIndex unavailable".into(),
            ));
        }
        Ok(self.current.read().clone())
    }

    fn revision(&self) -> Result<u64, ReBACTupleStoreError> {
        Ok(1) // Deliberately lagging local applied state, including a cached grant.
    }
}

fn grant(zone: &str) -> (String, Vec<u8>) {
    let tuple = ReBACTuple {
        object_type: "file".into(),
        object_id: PATH.into(),
        relation: "reader".into(),
        subject_type: "user".into(),
        subject_id: "alice".into(),
        subject_relation: None,
    };
    (tuple_key::encode(zone, &tuple).unwrap(), Vec::new())
}

fn route(zone: &str) -> RouteResult {
    RouteResult {
        mount_point: format!("/{zone}"),
        backend_path: "sessions/original".into(),
        zone_id: zone.into(),
        is_external: false,
        is_cas: true,
        metastore: None,
        backend: None,
        target_zone_id: None,
    }
}

fn caller() -> OperationContext {
    OperationContext::new("alice", "ambient", false, None, false)
}

fn fixture() -> (Arc<OrderedStore>, RebacPermissionProvider) {
    let store = Arc::new(OrderedStore {
        local: vec![grant("original")],
        current: RwLock::new(vec![grant("original")]),
        unavailable: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
    });
    let provider = RebacPermissionProvider::new(Arc::new(ReBACGraphCache::new(store.clone())));
    (store, provider)
}

#[test]
fn current_admission_observes_revocation_despite_cached_local_grant() {
    let (store, provider) = fixture();
    let route = route("original");
    let ctx = caller();
    provider
        .check(PATH, Some(&route), Permission::Read, &ctx)
        .unwrap();
    provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .unwrap();
    store.current.write().clear();
    assert!(provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .is_err());
    // The ordinary local cache still contains its positive. Admission must not
    // use it after revocation or refill it from a separately sampled revision.
    provider
        .check(PATH, Some(&route), Permission::Read, &ctx)
        .unwrap();
    assert_eq!(store.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn current_snapshot_failure_cannot_fall_back_to_an_existing_grant() {
    let (store, provider) = fixture();
    let route = route("original");
    let ctx = caller();
    provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .unwrap();
    store.unavailable.store(true, Ordering::SeqCst);
    let error = provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .unwrap_err();
    assert!(error.to_string().contains("ReadIndex unavailable"));
    assert_eq!(store.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn unsupported_current_snapshot_and_privileged_contexts_do_not_mint_grants() {
    let store = Arc::new(InMemoryReBACTupleStore::new());
    let (key, value) = grant("original");
    store.put(&key, &value).unwrap();
    let provider = RebacPermissionProvider::new(Arc::new(ReBACGraphCache::new(store)));
    let route = route("original");
    let mut ctx = caller();
    provider
        .check(PATH, Some(&route), Permission::Read, &ctx)
        .unwrap();
    let error = provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .unwrap_err();
    assert!(error.to_string().contains("unsupported"));
    let (store, provider) = fixture();
    ctx.is_admin = true;
    provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .unwrap();
    store.current.write().clear();
    assert!(provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .is_err());
    assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    let (store, provider) = fixture();
    ctx.is_admin = false;
    ctx.is_system = true;
    assert!(provider
        .check_current_grants(PATH, &route, Permission::Read, &ctx)
        .is_err());
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
}

#[test]
fn current_grants_use_captured_zone_and_original_authenticated_subject() {
    let (_, provider) = fixture();
    let mut ctx = caller();
    provider
        .check_current_grants(PATH, &route("original"), Permission::Read, &ctx)
        .unwrap();
    assert!(provider
        .check_current_grants(PATH, &route("replacement"), Permission::Read, &ctx)
        .is_err());
    ctx.user_id = "bob".into();
    assert!(provider
        .check_current_grants(PATH, &route("original"), Permission::Read, &ctx)
        .is_err());
}
