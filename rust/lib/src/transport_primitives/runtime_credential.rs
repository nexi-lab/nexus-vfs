//! TLS identity for a runtime confined to one signed owner.

use sha2::{Digest, Sha256};
use std::fmt::Write;
use x509_parser::prelude::*;

pub use contracts::USER_RUNTIME_MAX_VALIDITY_SECS;

/// A TLS verification name, derived from the owner rather than a dial address.
pub fn user_runtime_server_name(owner: &str) -> Result<String, String> {
    if owner.is_empty() || owner.len() > 256 || owner.chars().any(char::is_control) {
        return Err("invalid user runtime owner".into());
    }
    let mut name = String::with_capacity(51);
    name.push_str("nexus-user-");
    for byte in &Sha256::digest(owner.as_bytes())[..20] {
        write!(name, "{byte:02x}").expect("String formatting is infallible");
    }
    Ok(name)
}

/// Preserve server capability only for the owner's exact runtime identity.
/// Issuer, current validity and proof verification belong to the caller.
pub fn user_runtime_name_from_x509(cert: &X509Certificate<'_>) -> Result<Option<String>, String> {
    let usages = cert
        .extended_key_usage()
        .map_err(|_| "invalid credential key usage")?;
    let Some(usages) = usages.filter(|usages| usages.value.server_auth) else {
        return Ok(None);
    };
    if !usages.value.client_auth || usages.value.any || !usages.value.other.is_empty() {
        return Err("invalid user runtime key usage".into());
    }
    let owner =
        super::authorship::owner_from_x509(cert).ok_or("user runtime requires a signed owner")?;
    let name = user_runtime_server_name(&owner)?;
    let names = &cert
        .subject_alternative_name()
        .map_err(|_| "invalid runtime SAN")?
        .ok_or("missing runtime SAN")?
        .value
        .general_names;
    let dns: Vec<&str> = names
        .iter()
        .filter_map(|entry| match entry {
            GeneralName::DNSName(name) => Some(*name),
            _ => None,
        })
        .collect();
    if dns != [name.as_str()]
        || names
            .iter()
            .any(|entry| !matches!(entry, GeneralName::URI(_) | GeneralName::DNSName(_)))
    {
        return Err("runtime server name does not match its signed owner".into());
    }
    Ok(Some(name))
}
