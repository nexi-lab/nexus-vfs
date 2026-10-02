//! Authentication and response authorization at the plugin's network boundary.
//! Policies run in the host, so a plugin's cache or internal recursion cannot
//! bypass the caller's access checks. No Rust value crosses the C ABI here.

use std::sync::Arc;

use tonic::{metadata::MetadataMap, Status};

use crate::auth::{AuthCredentials, AuthProvider, PeerIdentity};

/// Authorize a decoded unary request before the plugin sees it. A policy may
/// bind request fields to the authenticated caller by replacing the payload.
pub trait PluginGrpcPolicy: Send + Sync {
    fn authorize(
        &self,
        method: &str,
        payload: &mut Vec<u8>,
        metadata: &MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Box<dyn AuthorizedPluginCall>, Status>;
}

/// Request-scoped authorization applied to every successful plugin response.
pub trait AuthorizedPluginCall: Send {
    fn complete(self: Box<Self>, payload: Vec<u8>) -> Result<Vec<u8>, Status>;
}

/// The shared identity gate for services whose request does not carry a token.
/// Their credentials are an Authorization header or a verified client cert.
pub struct AuthenticatedPlugin {
    auth: Arc<dyn AuthProvider>,
}

impl AuthenticatedPlugin {
    pub fn new(auth: Arc<dyn AuthProvider>) -> Self {
        Self { auth }
    }
}

impl PluginGrpcPolicy for AuthenticatedPlugin {
    fn authorize(
        &self,
        _method: &str,
        _payload: &mut Vec<u8>,
        metadata: &MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Box<dyn AuthorizedPluginCall>, Status> {
        self.auth.resolve(&AuthCredentials {
            token: request_token(metadata, "")?,
            peer,
        })?;
        Ok(Box::new(AuthenticatedResponse))
    }
}

pub(crate) struct AuthenticatedResponse;

impl AuthorizedPluginCall for AuthenticatedResponse {
    fn complete(self: Box<Self>, payload: Vec<u8>) -> Result<Vec<u8>, Status> {
        Ok(payload)
    }
}

/// Resolve the single bearer credential. Search's protobuf token and the HTTP
/// Authorization header may agree; contradictory or repeated credentials fail.
pub(crate) fn request_token<'a>(
    metadata: &'a MetadataMap,
    message_token: &'a str,
) -> Result<&'a str, Status> {
    let mut values = metadata.get_all("authorization").iter();
    let Some(value) = values.next() else {
        return Ok(message_token);
    };
    if values.next().is_some() {
        return Err(Status::unauthenticated("multiple authorization headers"));
    }
    let value = value
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization header"))?;
    let (_, token) = value
        .split_once(' ')
        .filter(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("bearer")
                && !token.is_empty()
                && !token.bytes().any(|byte| byte.is_ascii_whitespace())
        })
        .ok_or_else(|| Status::unauthenticated("invalid bearer credential"))?;
    if !message_token.is_empty() && message_token != token {
        return Err(Status::unauthenticated("conflicting bearer credentials"));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_sources_must_be_unambiguous() {
        let mut metadata = MetadataMap::new();
        assert_eq!(request_token(&metadata, "body").unwrap(), "body");
        metadata.insert("authorization", "Bearer header".parse().unwrap());
        assert_eq!(request_token(&metadata, "").unwrap(), "header");
        assert_eq!(request_token(&metadata, "header").unwrap(), "header");
        assert_eq!(
            request_token(&metadata, "body").unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        metadata.append("authorization", "Bearer header".parse().unwrap());
        assert!(request_token(&metadata, "header").is_err());
        for invalid in [
            "Basic header",
            "Bearer ",
            "Bearer one two",
            "Bearer  header",
        ] {
            let mut metadata = MetadataMap::new();
            metadata.insert("authorization", invalid.parse().unwrap());
            assert!(request_token(&metadata, "").is_err(), "{invalid:?}");
        }
    }
}
