//! Managed ACP live-delivery wire contract. These types carry transport receipts,
//! not engine admission or execution results. A replay gap requires state recovery.

use crate::session::SessionPayload;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadSessionRequest {
    pub session_id: String,
    pub channel_id: String,
    pub after_sequence: u64,
    #[serde(default)]
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitSessionRequest {
    pub session_id: String,
    pub channel_id: String,
    pub sequence: u64,
    pub payload: SessionPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryFrame {
    pub sequence: u64,
    pub payload: SessionPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadSessionResponse {
    pub frames: Vec<DeliveryFrame>,
    pub earliest_sequence: u64,
    pub latest_sequence: u64,
    pub accepted_sequence: u64,
    pub resync_required: bool,
    /// Registry retirement refuses further inputs. It is not an OS exit proof.
    pub retired: bool,
    pub closed: bool,
}
