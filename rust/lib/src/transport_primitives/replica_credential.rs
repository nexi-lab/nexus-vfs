//! Replica identity carried by the existing short-lived owner runtime leaf.

use x509_parser::prelude::*;

const PREFIX: &str = "nexus://replica/";

/// The issuer assigns this identity; zone membership supplies its authority.
pub fn replica_identity_uri(node_id: u64) -> Result<String, String> {
    if node_id == 0 {
        return Err("replica identity requires a nonzero node ID".into());
    }
    Ok(format!("{PREFIX}{node_id}"))
}

/// Read the signed replica identity. The caller verifies issuer, lifetime and
/// possession of the leaf key before using it as an authenticated identity.
pub fn replica_node_id_from_x509(cert: &X509Certificate<'_>) -> Result<Option<u64>, String> {
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(|_| "invalid replica SAN")?
    else {
        return Ok(None);
    };
    let names = &san.value.general_names;
    let mut replicas = names.iter().filter_map(|entry| match entry {
        GeneralName::URI(uri) if uri.starts_with(PREFIX) => Some(*uri),
        _ => None,
    });
    let Some(replica) = replicas.next() else {
        return Ok(None);
    };
    if replicas.next().is_some() {
        return Err("credential must carry exactly one replica identity".into());
    }
    let value = replica
        .strip_prefix(PREFIX)
        .ok_or("invalid replica node ID")?;
    if !matches!(value.as_bytes().first(), Some(b'1'..=b'9')) {
        return Err("replica node ID must be canonical".into());
    }
    let node_id = value
        .parse::<u64>()
        .map_err(|_| "invalid replica node ID")?;
    super::user_runtime_name_from_x509(cert)?
        .ok_or("replica identity requires an owner runtime credential")?;
    let mut seen = 0_u8;
    for entry in names {
        let GeneralName::URI(uri) = entry else {
            continue;
        };
        let bit = if *uri == replica {
            1
        } else if crate::agent_identity::parse_agent_identity_uri_ref(uri).is_some() {
            2
        } else if crate::agent_identity::parse_owner_uri_ref(uri).is_some() {
            4
        } else {
            return Err("replica identity must name one owner and one agent subject".into());
        };
        if seen & bit != 0 {
            return Err("replica identity must name one owner and one agent subject".into());
        }
        seen |= bit;
    }
    if seen != 0b111 {
        return Err("replica identity must name one owner and one agent subject".into());
    }
    Ok(Some(node_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate, CertificateParams, ExtendedKeyUsagePurpose, KeyPair, SanType};

    fn certificate(uris: &[&str]) -> Certificate {
        certificate_with_names(uris, Vec::new())
    }

    fn certificate_with_names(uris: &[&str], extra_names: Vec<SanType>) -> Certificate {
        let mut params =
            CertificateParams::new(vec![
                super::super::user_runtime_server_name("alice").unwrap()
            ])
            .unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.subject_alt_names.extend(
            uris.iter()
                .map(|uri| SanType::URI((*uri).try_into().unwrap())),
        );
        params.subject_alt_names.extend(extra_names);
        params.self_signed(&KeyPair::generate().unwrap()).unwrap()
    }

    #[test]
    fn ordinary_owner_credentials_have_no_replica_identity() {
        let leaf = certificate(&["nexus://agent/session-a", "nexus://owner/alice"]);
        let (_, cert) = X509Certificate::from_der(leaf.der()).unwrap();
        assert_eq!(replica_node_id_from_x509(&cert).unwrap(), None);
    }

    #[test]
    fn replica_identity_accepts_each_san_order() {
        let uris = [
            "nexus://agent/session-a",
            "nexus://owner/alice",
            "nexus://replica/7",
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let leaf = certificate(&order.map(|index| uris[index]));
            let (_, cert) = X509Certificate::from_der(leaf.der()).unwrap();
            assert_eq!(replica_node_id_from_x509(&cert).unwrap(), Some(7));
        }
    }

    #[test]
    fn replica_identity_accepts_the_full_nonzero_u64_range() {
        for id in [1, u64::MAX] {
            let uri = replica_identity_uri(id).unwrap();
            let leaf = certificate(&["nexus://agent/session-a", "nexus://owner/alice", &uri]);
            let (_, cert) = X509Certificate::from_der(leaf.der()).unwrap();
            assert_eq!(replica_node_id_from_x509(&cert).unwrap(), Some(id));
        }
    }

    #[test]
    fn replica_identity_rejects_additional_dns_and_non_uri_names() {
        for name in [
            SanType::DnsName(
                super::super::user_runtime_server_name("alice")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            SanType::DnsName("nexus-node".try_into().unwrap()),
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
        ] {
            let leaf = certificate_with_names(
                &[
                    "nexus://agent/session-a",
                    "nexus://owner/alice",
                    "nexus://replica/7",
                ],
                vec![name],
            );
            let (_, cert) = X509Certificate::from_der(leaf.der()).unwrap();
            assert!(replica_node_id_from_x509(&cert).is_err());
        }
    }

    #[test]
    fn replica_requires_one_canonical_identity_and_the_exact_owner_runtime_shape() {
        for uri in [
            "nexus://replica/0",
            "nexus://replica/007",
            "nexus://replica/+7",
            "nexus://replica/7/",
            "nexus://replica/18446744073709551616",
        ] {
            let leaf = certificate(&["nexus://agent/session-a", "nexus://owner/alice", uri]);
            let (_, cert) = X509Certificate::from_der(leaf.der()).unwrap();
            assert!(replica_node_id_from_x509(&cert).is_err(), "{uri}");
        }
        for uris in [
            vec!["nexus://agent/", "nexus://owner/alice", "nexus://replica/7"],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/",
                "nexus://replica/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://agent/session-b",
                "nexus://owner/alice",
                "nexus://replica/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://agent/session-a",
                "nexus://owner/alice",
                "nexus://replica/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/alice",
                "nexus://owner/alice",
                "nexus://replica/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/alice",
                "nexus://replica/7",
                "nexus://unexpected/7",
            ],
            vec!["nexus://agent/session-a", "nexus://replica/7"],
            vec!["nexus://owner/alice", "nexus://replica/7"],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/bob",
                "nexus://replica/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/alice",
                "nexus://replica/7",
                "nexus://replica/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/alice",
                "nexus://replica/7",
                "nexus://zone/root/node/7",
            ],
            vec![
                "nexus://agent/session-a",
                "nexus://owner/alice",
                "nexus://owner/bob",
                "nexus://replica/7",
            ],
        ] {
            let leaf = certificate(&uris);
            let (_, cert) = X509Certificate::from_der(leaf.der()).unwrap();
            assert!(replica_node_id_from_x509(&cert).is_err(), "{uris:?}");
        }
    }
}
