//! Canonical Node identity shared by credential issuance and TLS admission.

use x509_parser::{extensions::GeneralName, prelude::X509Certificate};

const PREFIX: &str = "nexus://zone/";

/// Build the Node identity URI carried by its signed certificate.
pub fn node_identity_uri(zone_id: &str, node_id: u64) -> String {
    format!("{PREFIX}{zone_id}/node/{node_id}")
}

/// Parse a Node identity URI. Certificate admission additionally checks its
/// canonical representation and the zone's existing-reference contract.
pub fn parse_node_identity_uri(uri: &str) -> Option<(String, u64)> {
    let (zone, node) = uri.strip_prefix(PREFIX)?.split_once("/node/")?;
    if zone.is_empty() {
        return None;
    }
    Some((zone.to_owned(), node.parse().ok()?))
}

/// Extract exactly one canonical Node identity. The TLS verifier supplies
/// issuer, validity, key usage and proof-of-possession verification.
pub fn node_identity_from_x509(leaf: &X509Certificate<'_>) -> Result<(String, u64), String> {
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| "invalid Node SAN")?
        .ok_or("missing Node SAN")?;
    let mut identities = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) if uri.starts_with("nexus://") => Some(*uri),
            _ => None,
        });
    let identity = identities.next().ok_or("missing Node identity")?;
    if identities.next().is_some() {
        return Err("Node certificate must carry exactly one Nexus identity".into());
    }
    let (zone, node) =
        parse_node_identity_uri(identity).ok_or("certificate does not name a Node")?;
    contracts::validate_zone_id_for(contracts::ZoneIdUse::ExistingRef, &zone)
        .map_err(|error| error.to_string())?;
    if node_identity_uri(&zone, node) != identity {
        return Err("Node identity is not canonical".into());
    }
    Ok((zone, node))
}
