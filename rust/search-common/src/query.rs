//! Query parameters shared by single-zone and federated search.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Bound one batch before allocating per-query authorization views or tasks.
pub const MAX_BATCH_QUERIES: usize = 500;

pub fn validate_batch_size(count: usize) -> Result<(), String> {
    if count > MAX_BATCH_QUERIES {
        Err(format!(
            "too many queries: {count} exceeds the limit of {MAX_BATCH_QUERIES}"
        ))
    } else {
        Ok(())
    }
}

/// Ranking and selection parameters. Credentials and delegated identity are
/// supplied by the transport rather than accepted in this request body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryParameters {
    /// Query text.
    pub q: String,
    /// Zone scoping. Empty uses the caller's zone or readable-zone fanout.
    #[serde(default)]
    pub zone_id: String,
    /// Max results returned.  0 ⇒ server-side default (10).
    #[serde(default)]
    pub limit: u32,
    /// Optional path-prefix filter.
    #[serde(default)]
    pub path_filter: String,
    /// `"keyword"` (default) / `"semantic"` / `"hybrid"`.
    /// Values are case-insensitive; transports reject unknown non-empty values.
    #[serde(default)]
    pub query_type: String,
    #[serde(default)]
    pub alpha: f32,
    /// `"rrf"` (default) / `"weighted"` / `"rrf_weighted"` for fusion inside
    /// each zone. Cross-zone fusion uses the dispatcher's configuration.
    #[serde(default)]
    pub fusion_method: String,
    #[serde(default)]
    pub rrf_k: u32,
    /// Per-document chunk cap for pooling (#4542). 0 = no pooling.
    #[serde(default)]
    pub chunks_per_page: u32,
    /// `"macro"` (neighbour context expansion) / anything else ⇒
    /// none.  Absent ⇒ none.
    #[serde(default)]
    pub expand: String,
    /// `""` / `"off"` (default) / `"on"` / `"auto"`.
    #[serde(default)]
    pub recency_mode: String,
    #[serde(default)]
    pub recency_weight: f32,
    #[serde(default)]
    pub recency_half_life_days: f32,
    /// Per-prefix score multiplier map.  Empty ⇒ no per-prefix boost.
    #[serde(default)]
    pub path_prefix_boosts: HashMap<String, f32>,
    /// Extra path prefixes OR-ed with `path_filter` — one fused
    /// ranking over the union.  Empty ⇒ only `path_filter` applies.
    #[serde(default)]
    pub path_filters: Vec<String>,
}

impl QueryParameters {
    /// Zero selects the query protocol's default result limit.
    pub fn effective_limit(&self) -> usize {
        if self.limit == 0 {
            10
        } else {
            self.limit as usize
        }
    }
}
