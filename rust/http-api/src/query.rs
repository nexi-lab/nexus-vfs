//! Encode query settings once for single-zone, local, and delegated RPCs.

use nexus_search_common::QueryParameters;

use crate::search_proto::{FusionMethod, QueryRequest, QueryType};

fn parse_wire_enum<T: Copy>(
    value: &str,
    field: &str,
    default: T,
    variants: &[(&str, T)],
) -> Result<T, String> {
    if value.is_empty() {
        return Ok(default);
    }
    for (name, variant) in variants {
        if value.eq_ignore_ascii_case(name) {
            return Ok(*variant);
        }
    }
    let names: Vec<String> = variants.iter().map(|(n, _)| format!("\"{n}\"")).collect();
    Err(format!(
        "unknown {field} {value:?} (expected {})",
        names.join(", ")
    ))
}

pub(crate) fn parse_query_type(value: &str) -> Result<QueryType, String> {
    parse_wire_enum(
        value,
        "query_type",
        QueryType::Keyword,
        &[
            ("keyword", QueryType::Keyword),
            ("semantic", QueryType::Semantic),
            ("hybrid", QueryType::Hybrid),
        ],
    )
}

pub(crate) fn parse_fusion_method(value: &str) -> Result<FusionMethod, String> {
    parse_wire_enum(
        value,
        "fusion_method",
        FusionMethod::Rrf,
        &[
            ("rrf", FusionMethod::Rrf),
            ("weighted", FusionMethod::Weighted),
            ("rrf_weighted", FusionMethod::RrfWeighted),
        ],
    )
}

/// Credentials belong to the transport caller: the original bearer for local
/// RPCs, or delegation metadata for remote RPCs.
pub(crate) fn query_request(parameters: QueryParameters) -> Result<QueryRequest, String> {
    Ok(QueryRequest {
        query_type: parse_query_type(&parameters.query_type)? as i32,
        fusion_method: parse_fusion_method(&parameters.fusion_method)? as i32,
        q: parameters.q,
        zone_id: parameters.zone_id,
        limit: parameters.limit,
        path_filter: parameters.path_filter,
        alpha: parameters.alpha,
        rrf_k: parameters.rrf_k,
        chunks_per_page: parameters.chunks_per_page,
        expand: parameters.expand,
        recency_mode: parameters.recency_mode,
        recency_weight: parameters.recency_weight,
        recency_half_life_days: parameters.recency_half_life_days,
        path_prefix_boosts: parameters.path_prefix_boosts,
        path_filters: parameters.path_filters,
        ..Default::default()
    })
}
