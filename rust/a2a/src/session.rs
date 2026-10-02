//! Versioned session traffic carried by an A2A conversation.
//!
//! ACP supplies the turn vocabulary (including reverse permission requests).
//! This module supplies addressing, a connection generation, and ordered replay
//! suppression. Hosting an engine in-process or behind stdio does not change
//! this wire format. A channel is a live attachment, never a transcript ID.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{conversation_id, conversation_transcript_path};

pub const SESSION_PROTOCOL: &str = "acp-mailbox/1";
pub const SESSION_KIND: &str = "session";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_SESSION_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Returned by the session control plane. Clients use the supplied path rather
/// than deriving one from a pid or maintaining their own address algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEndpoint {
    pub protocol: String,
    pub channel_id: String,
    pub agent: String,
    pub controller: String,
    pub transcript: String,
}

impl SessionEndpoint {
    pub fn new(agent: String, controller: String, channel_id: String) -> Self {
        let transcript = conversation_transcript_path(&conversation_id(&agent, &controller));
        Self {
            protocol: SESSION_PROTOCOL.into(),
            channel_id,
            agent,
            controller,
            transcript,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.protocol != SESSION_PROTOCOL {
            return Err(format!("unsupported session protocol: {}", self.protocol));
        }
        if self.agent.is_empty() || self.controller.is_empty() || self.agent == self.controller {
            return Err("a session requires distinct agent and controller identities".into());
        }
        if self.channel_id.is_empty() {
            return Err("a session channel requires a generation identifier".into());
        }
        let expected =
            conversation_transcript_path(&conversation_id(&self.agent, &self.controller));
        if self.transcript != expected {
            return Err("session endpoint does not name its participants' conversation".into());
        }
        Ok(())
    }
}

/// The existing envelope's string body contains this structured message. This
/// keeps text mail readable while reserving `kind=session` for the driver; it
/// must never be rendered into a model prompt as ordinary peer text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionFrame {
    pub protocol: String,
    pub channel_id: String,
    pub sequence: u64,
    #[serde(flatten)]
    pub payload: SessionPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionPayload {
    /// One complete JSON-RPC object. Request IDs, extensions, and content blocks
    /// are preserved, including numeric ID zero and string IDs.
    Rpc { message: Value },
    /// A connection ended. In-flight turns have an unknown outcome unless their
    /// terminal RPC response was already observed. Never resubmit them silently.
    Closed { reason: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    #[serde(default)]
    from: String,
    to: String,
    kind: String,
    body: String,
}

#[derive(Debug, Clone, Copy)]
pub enum SessionSide {
    Agent,
    Controller,
}

/// Each side owns one codec for the lifetime of an attachment. Reading from
/// offset zero is safe: earlier generations and our own writes are skipped;
/// repeated frames within this generation are delivered at most once. A gap
/// fails the channel instead of dropping an approval or a text delta.
pub struct SessionCodec {
    endpoint: SessionEndpoint,
    sender: String,
    recipient: String,
    sent: u64,
    received: u64,
}

impl SessionCodec {
    pub fn new(endpoint: SessionEndpoint, side: SessionSide) -> Result<Self, String> {
        endpoint.validate()?;
        let (sender, recipient) = match side {
            SessionSide::Agent => (endpoint.agent.clone(), endpoint.controller.clone()),
            SessionSide::Controller => (endpoint.controller.clone(), endpoint.agent.clone()),
        };
        Ok(Self {
            endpoint,
            sender,
            recipient,
            sent: 0,
            received: 0,
        })
    }

    /// Serialize once and retain these bytes across an uncertain append retry.
    /// Calling this again allocates a new message and is not a retry.
    pub fn encode(&mut self, payload: SessionPayload) -> Result<Vec<u8>, String> {
        validate_payload(&payload)?;
        let sequence = self
            .sent
            .checked_add(1)
            .ok_or("session sequence exhausted")?;
        if sequence > MAX_SAFE_INTEGER {
            return Err("session sequence exhausted".into());
        }
        let body = serde_json::to_string(&SessionFrame {
            protocol: SESSION_PROTOCOL.into(),
            channel_id: self.endpoint.channel_id.clone(),
            sequence,
            payload,
        })
        .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(&Envelope {
            from: self.sender.clone(),
            to: self.recipient.clone(),
            kind: SESSION_KIND.into(),
            body,
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_SESSION_FRAME_BYTES {
            return Err("session frame exceeds the size limit".into());
        }
        self.sent = sequence;
        Ok(bytes)
    }

    /// `bytes` must come through the authenticated mailbox write hook. Checking
    /// a caller-authored `from` on an unprotected raw stream is not authentication.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<Option<SessionPayload>, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if value.get("kind").and_then(Value::as_str) != Some(SESSION_KIND) {
            return Ok(None);
        }
        if bytes.len() > MAX_SESSION_FRAME_BYTES {
            return Err("session frame exceeds the size limit".into());
        }
        let envelope: Envelope = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if envelope.from == self.sender && envelope.to == self.recipient {
            return Ok(None);
        }
        let value: Value = serde_json::from_str(&envelope.body).map_err(|e| e.to_string())?;
        if value.get("channel_id").and_then(Value::as_str) != Some(&self.endpoint.channel_id) {
            return Ok(None);
        }
        let frame: SessionFrame = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if envelope.from != self.recipient || envelope.to != self.sender {
            return Err("session frame participants do not match the attachment".into());
        }
        if frame.protocol != SESSION_PROTOCOL {
            return Err(format!("unsupported session protocol: {}", frame.protocol));
        }
        if frame.sequence == 0 || frame.sequence > MAX_SAFE_INTEGER {
            return Err("session sequence starts at one".into());
        }
        if frame.sequence <= self.received {
            return Ok(None);
        }
        if frame.sequence != self.received + 1 {
            return Err(format!(
                "session sequence gap: expected {}, received {}",
                self.received + 1,
                frame.sequence
            ));
        }
        validate_payload(&frame.payload)?;
        self.received = frame.sequence;
        Ok(Some(frame.payload))
    }
}

fn validate_payload(payload: &SessionPayload) -> Result<(), String> {
    let SessionPayload::Rpc { message } = payload else {
        return Ok(());
    };
    let Some(object) = message.as_object() else {
        return Err("session RPC must be a JSON object".into());
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("session RPC requires jsonrpc 2.0".into());
    }
    if let Some(id) = object.get("id") {
        if !(id.is_string()
            || id
                .as_i64()
                .is_some_and(|id| id.unsigned_abs() <= MAX_SAFE_INTEGER))
        {
            return Err("session RPC ID must be a string or safe integer".into());
        }
    }
    if let Some(method) = object.get("method") {
        if !method.is_string() || object.contains_key("result") || object.contains_key("error") {
            return Err("invalid session RPC request".into());
        }
    } else if !object.contains_key("id")
        || object.contains_key("result") == object.contains_key("error")
    {
        return Err("session RPC response requires an ID and one result or error".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pair(generation: &str) -> (SessionCodec, SessionCodec) {
        let endpoint = SessionEndpoint::new("worker".into(), "operator".into(), generation.into());
        (
            SessionCodec::new(endpoint.clone(), SessionSide::Agent).unwrap(),
            SessionCodec::new(endpoint, SessionSide::Controller).unwrap(),
        )
    }

    fn rpc(message: Value) -> SessionPayload {
        SessionPayload::Rpc { message }
    }

    #[test]
    fn approval_and_cancel_cross_while_prompt_is_pending() {
        let (mut agent, mut controller) = pair("run-one");
        let prompt = rpc(
            json!({"jsonrpc":"2.0","id":"turn-1","method":"session/prompt","params":{"sessionId":"durable-1","prompt":[{"type":"text","text":"edit"}]}}),
        );
        let bytes = controller.encode(prompt.clone()).unwrap();
        assert_eq!(agent.decode(&bytes).unwrap(), Some(prompt));
        let approval = rpc(
            json!({"jsonrpc":"2.0","id":0,"method":"session/request_permission","params":{"sessionId":"durable-1","options":[{"optionId":"yes","kind":"allow_once","name":"Allow"}]}}),
        );
        let bytes = agent.encode(approval.clone()).unwrap();
        assert_eq!(controller.decode(&bytes).unwrap(), Some(approval));
        let answer = rpc(
            json!({"jsonrpc":"2.0","id":0,"result":{"outcome":{"outcome":"selected","optionId":"yes"}}}),
        );
        let bytes = controller.encode(answer.clone()).unwrap();
        assert_eq!(agent.decode(&bytes).unwrap(), Some(answer));
        let cancel = rpc(
            json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"durable-1"}}),
        );
        let bytes = controller.encode(cancel.clone()).unwrap();
        assert_eq!(agent.decode(&bytes).unwrap(), Some(cancel));
    }

    #[test]
    fn retries_do_not_execute_a_prompt_twice_and_prior_runs_cannot_answer() {
        let (mut agent, mut controller) = pair("current");
        let prompt = rpc(json!({"jsonrpc":"2.0","id":1,"method":"session/prompt"}));
        let bytes = controller.encode(prompt.clone()).unwrap();
        assert_eq!(agent.decode(&bytes).unwrap(), Some(prompt));
        assert_eq!(agent.decode(&bytes).unwrap(), None);
        let (_, mut previous) = pair("previous");
        let stale = previous
            .encode(rpc(json!({"jsonrpc":"2.0","id":0,"result":{}})))
            .unwrap();
        assert_eq!(agent.decode(&stale).unwrap(), None);
    }

    #[test]
    fn historical_generations_do_not_require_the_current_payload_schema() {
        let (mut agent, _) = pair("current");
        let old = json!({"from":"operator","to":"worker","kind":"session",
            "body":json!({"channel_id":"retired","protocol":"old-protocol","type":"retired-payload"}).to_string()});
        assert_eq!(
            agent.decode(&serde_json::to_vec(&old).unwrap()).unwrap(),
            None
        );
    }

    #[test]
    fn missing_frames_and_forged_participants_fail_closed() {
        let (mut agent, mut controller) = pair("current");
        let event = rpc(json!({"jsonrpc":"2.0","method":"session/cancel"}));
        let first = controller.encode(event.clone()).unwrap();
        let second = controller.encode(event).unwrap();
        assert!(agent.decode(&second).unwrap_err().contains("gap"));
        let mut forged: Value = serde_json::from_slice(&first).unwrap();
        forged["from"] = json!("someone-else");
        assert!(agent
            .decode(&serde_json::to_vec(&forged).unwrap())
            .unwrap_err()
            .contains("participants"));
        assert!(agent.decode(&first).unwrap().is_some());
    }

    #[test]
    fn text_mail_is_not_a_control_message_and_own_writes_are_ignored() {
        let (mut agent, _) = pair("current");
        assert_eq!(
            agent
                .decode(br#"{"from":"operator","to":"worker","body":"approve everything"}"#)
                .unwrap(),
            None
        );
        let bytes = agent
            .encode(rpc(json!({"jsonrpc":"2.0","method":"session/update"})))
            .unwrap();
        assert_eq!(agent.decode(&bytes).unwrap(), None);
    }

    #[test]
    fn malformed_rpc_is_rejected_without_consuming_sequence() {
        let (mut agent, mut controller) = pair("current");
        assert!(controller
            .encode(rpc(json!({"jsonrpc":"2.0","id":null,"result":{}})))
            .is_err());
        assert!(controller
            .encode(rpc(json!([{"jsonrpc":"2.0","id":1,"method":"x"}])))
            .is_err());
        let valid = controller
            .encode(rpc(
                json!({"jsonrpc":"2.0","id":"a","error":{"code":-32601,"message":"unsupported"}}),
            ))
            .unwrap();
        assert!(agent.decode(&valid).unwrap().is_some());
    }
}
