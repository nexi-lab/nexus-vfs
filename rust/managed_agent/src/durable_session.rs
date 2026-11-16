//! One runtime transcript binding per original hosted ACP connection.
//!
//! This observes the controller request and the response on private child stdio.
//! It neither issues requests nor retries them. The caller owns the registry
//! incarnation fence; this object is never shared with a replacement process.

use crate::valid_durable_id;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
enum Operation {
    New,
    Load(String),
}

#[derive(Debug)]
struct Pending {
    id: Value,
    operation: Operation,
    settled: bool,
}

#[derive(Default)]
struct Requests {
    establishment: Option<Pending>,
    other_ids: HashSet<String>,
}

fn request_id(message: &Value) -> Option<String> {
    message
        .get("id")
        .filter(|id| id.is_string() || id.is_i64() || id.is_u64())
        .map(Value::to_string)
}

pub(crate) struct DurableSession {
    selected_resume: Option<String>,
    requests: Mutex<Requests>,
    // A read borrowed by SpawnHandle remains valid for its lifetime. No mutable
    // descriptor label or second ID store can overwrite the original response.
    resolved: OnceLock<String>,
}

impl DurableSession {
    pub(crate) fn new(selected_resume: Option<String>) -> Self {
        Self {
            selected_resume,
            requests: Mutex::new(Requests::default()),
            resolved: OnceLock::new(),
        }
    }

    pub(crate) fn id(&self) -> Option<&str> {
        self.resolved.get().map(String::as_str)
    }

    /// Register before writing to child stdin so an immediate response cannot
    /// outrun correlation. A failed write leaves the operation uncertain; the
    /// supervisor closes this connection instead of clearing it for replay.
    pub(crate) fn before_request(&self, message: &Value) -> Result<(), String> {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // Controller responses to child-originated requests use a distinct
            // JSON-RPC direction, even if their IDs happen to be the same.
            return Ok(());
        };
        let mut requests = self.requests.lock();
        let id_key = request_id(message);
        if id_key
            .as_ref()
            .is_some_and(|id| requests.other_ids.contains(id))
        {
            return Err("ACP request ID is already in flight".into());
        }
        if matches!(method, "session/new" | "session/load") {
            if requests.establishment.is_some() {
                return Err("one durable session establishment per hosted connection".into());
            }
            if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                || message.get("result").is_some()
                || message.get("error").is_some()
            {
                return Err("invalid ACP session request".into());
            }
            let id = message
                .get("id")
                .filter(|id| id.is_string() || id.is_i64() || id.is_u64())
                .ok_or("ACP session establishment requires a string or integer request ID")?
                .clone();
            let operation = match (method, self.selected_resume.as_deref()) {
                ("session/new", None) => Operation::New,
                ("session/load", Some(selected)) => {
                    let actual = message.pointer("/params/sessionId").and_then(Value::as_str);
                    if actual != Some(selected) || !valid_durable_id(selected) {
                        return Err("session/load must use the selected exact durable ID".into());
                    }
                    Operation::Load(selected.to_owned())
                }
                _ => {
                    return Err(
                        "ACP new/load does not match the host's selected recovery mode".into(),
                    )
                }
            };
            requests.establishment = Some(Pending {
                id,
                operation,
                settled: false,
            });
        } else {
            if requests
                .establishment
                .as_ref()
                .is_some_and(|pending| !pending.settled && message.get("id") == Some(&pending.id))
            {
                return Err("ACP request ID collides with pending session establishment".into());
            }
            if method.starts_with("session/") {
                let bound = self
                    .id()
                    .ok_or("runtime durable session is not established")?;
                if message.pointer("/params/sessionId").and_then(Value::as_str) != Some(bound) {
                    return Err("session request targets another durable transcript".into());
                }
            }
            // Until establishment settles, another outstanding RPC must not
            // lend its ID (and response bytes) to a session/new or load.
            if requests.establishment.as_ref().is_none_or(|p| !p.settled) {
                if let Some(id) = id_key {
                    if requests.other_ids.len() >= 256 {
                        return Err("too many ACP requests before durable establishment".into());
                    }
                    requests.other_ids.insert(id);
                }
            }
        }
        Ok(())
    }

    /// Returns true only for the first successful correlated establishment.
    /// A valid error is forwarded unchanged, remains unbound, and cannot be
    /// followed by a silent session/new fallback on this connection.
    pub(crate) fn observe_response(&self, message: &Value) -> Result<bool, String> {
        if message.get("method").is_some() {
            return Ok(false);
        }
        let mut requests = self.requests.lock();
        if let Some(id) = request_id(message) {
            if requests.other_ids.remove(&id) {
                return Ok(false);
            }
        }
        let Some(pending) = requests.establishment.as_mut() else {
            return Ok(false);
        };
        if pending.settled || message.get("id") != Some(&pending.id) {
            return Ok(false);
        }
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err("invalid correlated ACP response version".into());
        }
        let result = message.get("result");
        let error = message.get("error");
        if let (None, Some(error)) = (result, error) {
            if error.get("code").and_then(Value::as_i64).is_none()
                || error.get("message").and_then(Value::as_str).is_none()
            {
                return Err("invalid correlated ACP error".into());
            }
            pending.settled = true;
            requests.other_ids.clear();
            return Ok(false);
        }
        let result = match (result, error) {
            (Some(result), None) if result.is_object() => result,
            _ => return Err("ambiguous or invalid correlated ACP response".into()),
        };
        let id = match &pending.operation {
            Operation::New => result
                .get("sessionId")
                .and_then(Value::as_str)
                .filter(|id| valid_durable_id(id))
                .ok_or("session/new did not return a valid durable session ID")?,
            Operation::Load(selected) => {
                // ACP load success may be {}. If a runtime includes its ID it
                // must agree; strict load inside the engine remains mandatory.
                if result
                    .get("sessionId")
                    .is_some_and(|id| id.as_str() != Some(selected.as_str()))
                {
                    return Err("session/load returned another durable session ID".into());
                }
                selected.as_str()
            }
        };
        self.resolved
            .set(id.to_owned())
            .map_err(|_| "durable binding already established")?;
        pending.settled = true;
        requests.other_ids.clear();
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(id: Value, method: &str, sid: &str) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"sessionId":sid}})
    }
    fn success(id: Value, result: Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"result":result})
    }

    #[test]
    fn new_binds_only_the_original_correlated_response() {
        let binding = DurableSession::new(None);
        let response = success(json!(7), json!({"sessionId":"session-original"}));
        assert!(!binding.observe_response(&response).unwrap());
        binding
            .before_request(&request(json!(7), "session/new", ""))
            .unwrap();
        assert!(!binding
            .observe_response(&success(json!("7"), json!({"sessionId":"wrong"})))
            .unwrap());
        assert!(!binding
            .observe_response(
                &json!({"jsonrpc":"2.0","id":7,"method":"session/request_permission"})
            )
            .unwrap());
        assert_eq!(binding.id(), None);
        assert!(binding.observe_response(&response).unwrap());
        assert_eq!(binding.id(), Some("session-original"));
        assert!(!binding
            .observe_response(&success(json!(7), json!({"sessionId":"replacement"})))
            .unwrap());
        assert_eq!(binding.id(), Some("session-original"));
        assert!(binding
            .before_request(&request(json!(8), "session/new", ""))
            .is_err());
    }

    #[test]
    fn load_requires_the_selected_id_and_accepts_empty_success() {
        let binding = DurableSession::new(Some("session-saved".into()));
        assert!(binding
            .before_request(&request(json!(1), "session/new", ""))
            .is_err());
        assert!(binding
            .before_request(&request(json!(1), "session/load", "session-other"))
            .is_err());
        binding
            .before_request(&request(json!(1), "session/load", "session-saved"))
            .unwrap();
        assert!(binding
            .observe_response(&success(json!(1), json!({})))
            .unwrap());
        assert_eq!(binding.id(), Some("session-saved"));
    }

    #[test]
    fn load_error_and_unknown_never_turn_into_new_or_a_binding() {
        for response in [
            None,
            Some(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"not found","data":{"sessionId":"saved"}}}),
            ),
        ] {
            let binding = DurableSession::new(Some("saved".into()));
            binding
                .before_request(&request(json!(1), "session/load", "saved"))
                .unwrap();
            if let Some(response) = response {
                assert!(!binding.observe_response(&response).unwrap());
            }
            assert_eq!(binding.id(), None);
            assert!(binding
                .before_request(&request(json!(2), "session/new", ""))
                .is_err());
            assert!(binding
                .before_request(&request(json!(2), "session/load", "saved"))
                .is_err());
            assert!(binding
                .before_request(&request(json!(3), "session/prompt", "saved"))
                .is_err());
        }
    }

    #[test]
    fn malformed_success_and_load_mismatch_do_not_bind() {
        for result in [
            json!(null),
            json!({}),
            json!({"sessionId":"../path"}),
            json!({"sessionId":"latest"}),
            json!({"sessionId":123}),
        ] {
            let binding = DurableSession::new(None);
            binding
                .before_request(&request(json!(1), "session/new", ""))
                .unwrap();
            assert!(binding
                .observe_response(&success(json!(1), result))
                .is_err());
            assert_eq!(binding.id(), None);
        }
        for result in [json!({"sessionId":"other"}), json!({"sessionId":null})] {
            let binding = DurableSession::new(Some("saved".into()));
            binding
                .before_request(&request(json!(1), "session/load", "saved"))
                .unwrap();
            assert!(binding
                .observe_response(&success(json!(1), result))
                .is_err());
            assert_eq!(binding.id(), None);
        }
    }

    #[test]
    fn collision_notifications_and_cross_session_requests_are_refused() {
        let binding = DurableSession::new(None);
        assert!(binding
            .before_request(&request(Value::Null, "session/new", ""))
            .is_err());
        binding
            .before_request(&request(json!(1), "session/new", ""))
            .unwrap();
        assert!(binding
            .before_request(&request(json!(1), "initialize", ""))
            .is_err());
        binding
            .before_request(&success(json!(1), json!({})))
            .unwrap();
        binding
            .observe_response(&success(json!(1), json!({"sessionId":"saved"})))
            .unwrap();
        binding
            .before_request(&request(json!(2), "session/prompt", "saved"))
            .unwrap();
        assert!(binding
            .before_request(&request(json!(3), "session/prompt", "other"))
            .is_err());
    }

    #[test]
    fn ambiguous_response_is_not_success() {
        let binding = DurableSession::new(None);
        binding
            .before_request(&request(json!(1), "session/new", ""))
            .unwrap();
        assert!(binding.observe_response(&json!({"jsonrpc":"2.0","id":1,"result":{"sessionId":"saved"},"error":{"code":1,"message":"no"}})).is_err());
        assert_eq!(binding.id(), None);
    }

    #[test]
    fn an_unfinished_other_rpc_cannot_lend_its_response_to_new() {
        let binding = DurableSession::new(None);
        binding
            .before_request(&request(json!(1), "initialize", ""))
            .unwrap();
        assert!(binding
            .before_request(&request(json!(1), "session/new", ""))
            .is_err());
        assert!(!binding
            .observe_response(&success(json!(1), json!({"sessionId":"unrelated"})))
            .unwrap());
        assert_eq!(binding.id(), None);
        binding
            .before_request(&request(json!(1), "session/new", ""))
            .unwrap();
        assert!(binding
            .observe_response(&success(json!(1), json!({"sessionId":"actual"})))
            .unwrap());
        assert_eq!(binding.id(), Some("actual"));
    }

    #[test]
    fn pre_establishment_correlation_storage_is_bounded() {
        let binding = DurableSession::new(None);
        for id in 0..256 {
            binding
                .before_request(&request(json!(id), "test/pending", ""))
                .unwrap();
        }
        assert!(binding
            .before_request(&request(json!(256), "test/pending", ""))
            .is_err());
        binding
            .observe_response(&success(json!(0), json!({})))
            .unwrap();
        binding
            .before_request(&request(json!(256), "test/pending", ""))
            .unwrap();
        binding
            .before_request(&request(json!(257), "session/new", ""))
            .unwrap();
    }
}
