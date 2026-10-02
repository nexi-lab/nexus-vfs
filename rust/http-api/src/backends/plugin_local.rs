//! [`PluginLocalSearchBackend`] — [`LocalSearchBackend`] impl that
//! dials the daemon's OWN plugin (`nexus.search.v1.SearchService`)
//! through the shared [`crate::SearchBackend`] tonic-channel cache.
//!
//! # Why this shape
//!
//! The federated dispatcher's per-zone `search_zone(zone_id, req)`
//! call needs to reach the plugin.  Rather than growing the dispatcher
//! to know how to talk gRPC, we adapt the plugin's typed proto
//! response into a [`Hit`] here, once, at the seam.  Consequences:
//!
//! * the dispatcher stays transport-agnostic (a future in-process
//!   plugin path, an in-memory test double, etc. all fit the same
//!   trait);
//! * the attribution-field-to-`extras` stamping lives in ONE place —
//!   the bridge (`handlers::search_bridge`) reads back the same keys.
//!
//! # `extras` contract
//!
//! Every attribution field the plugin surfaces on `QueryResult`
//! lands on `Hit::extras` under the key names in
//! [`crate::handlers::search_bridge::EXTRAS_KEYS`].  The bridge
//! decodes back from those same keys, so a new attribution field
//! lands as one line here + one line in the bridge — no third
//! place to keep in sync.

use async_trait::async_trait;
use nexus_federated_search::{BackendError, LocalSearchBackend, SearchRequest};
use nexus_search_common::Hit;

use crate::backends::proto_bridge::{hit_from_proto, query_for_zone};
use crate::SearchBackend;

/// Dispatches per-zone search requests through the shared
/// [`crate::SearchBackend`] tonic-channel cache.  Cheap to clone —
/// the underlying [`crate::SearchBackend`] is already `Arc`-backed.
pub struct PluginLocalSearchBackend {
    inner: SearchBackend,
}

impl PluginLocalSearchBackend {
    /// Wrap a shared [`crate::SearchBackend`].  The dispatcher's
    /// per-leg `search_zone` calls reuse the backend's cached
    /// tonic Channel — no per-leg dial.
    pub fn new(inner: SearchBackend) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl LocalSearchBackend for PluginLocalSearchBackend {
    async fn search_zone(
        &self,
        zone_id: &str,
        req: &SearchRequest,
    ) -> Result<Vec<Hit>, BackendError> {
        let mut client = self
            .inner
            .client()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let mut proto = query_for_zone(zone_id, req);
        proto.auth_token = req.auth_token.clone();
        let resp = client
            .query(tonic::Request::new(proto))
            .await
            .map_err(|s| BackendError::Backend(s.message().to_string()))?
            .into_inner();
        if let Some(err) = resp.error {
            // The plugin's typed response carries an application-
            // level error string (e.g. "no index for zone X") on the
            // `error` field even on gRPC-OK.  Surface it as a
            // BackendError so the dispatcher lands the leg in
            // `zones_failed` rather than a silently-empty hit list.
            return Err(BackendError::Backend(err));
        }
        Ok(resp.results.into_iter().map(hit_from_proto).collect())
    }
}
