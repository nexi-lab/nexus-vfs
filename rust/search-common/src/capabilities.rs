//! Search modes and embedding identity reported by the current plugin.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchCapabilities {
    pub device_tier: String,
    pub search_modes: Vec<String>,
    pub embedding_model: String,
    pub embedding_dimensions: usize,
    pub has_graph: bool,
}
