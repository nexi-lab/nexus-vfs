//! Lossless provider HTTP over an LLM mount. The mount owns the destination
//! and credentials; callers select only a provider endpoint and JSON body.
//!
//! Reply records are JSON control frames or a zero byte followed by untouched
//! response bytes. The tag makes model text unambiguously data, while leaving
//! it visible to write hooks (no base64 encoding or provider-specific parsing).

use std::sync::Arc;

use futures::StreamExt;
use kernel::cas_engine::CASEngine;
use kernel::extensions::llm_streaming::StreamSink;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    nexus_http: HttpRequest,
    body: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRequest {
    version: u32,
    path: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
}

/// Recognize the explicit transport envelope, leaving legacy prompt JSON alone.
pub(super) fn is_exchange(request: &Value) -> bool {
    request.get("nexus_http").is_some()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    request: Value,
    base_url: &str,
    api_key: &str,
    anthropic: bool,
    http: &reqwest::Client,
    runtime: &tokio::runtime::Runtime,
    engine: &CASEngine,
    stream_path: &str,
    sink: &Arc<dyn StreamSink>,
) -> Result<(), String> {
    let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let exchange: Exchange = serde_json::from_value(request).map_err(|e| e.to_string())?;
    if exchange.nexus_http.version != 1 {
        return Err("unsupported LLM HTTP exchange version".into());
    }
    let path = exchange.nexus_http.path.as_str();
    let allowed = if anthropic {
        matches!(path, "v1/messages" | "v1/messages/count_tokens")
    } else {
        matches!(path, "chat/completions" | "responses")
    };
    if !allowed {
        return Err(format!(
            "endpoint {path:?} is not supported by this model mount"
        ));
    }
    let mut builder = http
        .post(format!("{}/{path}", base_url.trim_end_matches('/')))
        .header("content-type", "application/json");
    builder = if anthropic {
        builder
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
    } else {
        builder.bearer_auth(api_key)
    };
    for (name, value) in exchange.nexus_http.headers {
        // Never let a prompt override mount credentials, host, or framing.
        if matches!(
            name.as_str(),
            "anthropic-version" | "anthropic-beta" | "x-request-id"
        ) {
            builder = builder.header(name, value);
        } else {
            return Err(format!(
                "header {name:?} is not supported by the model transport"
            ));
        }
    }
    let response_bytes = runtime.block_on(async {
        let response = match builder.json(&exchange.body).send().await {
            Ok(response) => response,
            Err(error) if error.is_connect() || error.is_timeout() || error.is_request() => {
                // This mount is the caller's HTTP gateway. A failed upstream
                // connection is a 502/504, not a policy/configuration refusal.
                // Keeping it in the HTTP response contract lets the caller's
                // normal bounded retry policy run, through this same mount.
                let status = if error.is_timeout() { 504 } else { 502 };
                let head = json!({"type":"response","version":1,"status":status,
                    "headers":{"content-type":"application/json"}});
                sink.append(stream_path, &serde_json::to_vec(&head).map_err(|e| e.to_string())?)?;
                let body = serde_json::to_vec(&json!({"error":{
                    "type":"upstream_connection_error", "message":error.to_string()
                }})).map_err(|e| e.to_string())?;
                let mut record = vec![0];
                record.extend_from_slice(&body);
                sink.append(stream_path, &record)?;
                return Ok(body);
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut headers = serde_json::Map::new();
        for name in ["content-type", "retry-after", "request-id", "x-request-id", "x-client-request-id"] {
            if let Some(value) = response.headers().get(name).and_then(|v| v.to_str().ok()) {
                headers.insert(name.to_string(), Value::String(value.to_string()));
            }
        }
        let head = json!({"type": "response", "version": 1, "status": response.status().as_u16(), "headers": headers});
        sink.append(stream_path, &serde_json::to_vec(&head).map_err(|e| e.to_string())?)?;
        let mut collected = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            for part in chunk.chunks(64 * 1024) {
                let mut record = Vec::with_capacity(part.len() + 1);
                record.push(0);
                record.extend_from_slice(part);
                sink.append(stream_path, &record)?;
            }
            collected.extend_from_slice(&chunk);
        }
        Ok::<_, String>(collected)
    })?;
    let (request_hash, _) = engine
        .write_content_tracked(&request_bytes)
        .map_err(|e| e.to_string())?;
    let (response_hash, _) = engine
        .write_content_tracked(&response_bytes)
        .map_err(|e| e.to_string())?;
    let session = json!({"type": "llm_http_session_v1", "request_hash": request_hash, "response_hash": response_hash});
    let (session_hash, _) = engine
        .write_content_tracked(&serde_json::to_vec(&session).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    sink.append(
        stream_path,
        &serde_json::to_vec(&json!({"type": "done", "session_hash": session_hash}))
            .map_err(|e| e.to_string())?,
    )?;
    sink.close(stream_path)
}
