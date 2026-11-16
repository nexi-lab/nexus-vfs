//! Peer addressing for a committed segment, independent of CAS/PAS object IDs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

const PREFIX: &str = "/__stream_segments__/";
const READ_PREFIX: &str = "nexus-cold-v1:";
const READ_NAMESPACE: &str = "nexus-cold-";
const MAX_CONTENT_ID_BYTES: usize = 64 * 1024;

/// A segment locator names an existing entry in the owning stream's index.
/// It supplies no authority and never permits an unindexed object read.
pub struct ColdSegmentAddress<'a> {
    pub stream_path: &'a str,
    pub base: u64,
}

/// A peer read may also bind its locator to the caller's committed object ID.
/// This comparison supplies no authority to enter another storage owner.
pub struct ColdSegmentRead<'a> {
    pub address: ColdSegmentAddress<'a>,
    expected_content_id: Option<String>,
}

impl ColdSegmentRead<'_> {
    pub fn matches_content_id(&self, content_id: &str) -> bool {
        self.expected_content_id
            .as_deref()
            .is_none_or(|expected| expected == content_id)
    }
}

impl ColdSegmentAddress<'_> {
    /// The same key used when writing a path-addressed sealed segment.
    pub fn key(&self, zone: &str) -> String {
        format!(
            "{PREFIX}{zone}{}/{base}",
            self.stream_path,
            base = self.base
        )
    }

    /// Retain the existing index ID when a local miss requires a peer read.
    /// The stored segment key and durable index encoding remain unchanged.
    pub fn read_key(&self, zone: &str, content_id: &str) -> Result<String, String> {
        if content_id.is_empty() || content_id.len() > MAX_CONTENT_ID_BYTES {
            return Err("invalid sealed segment content identity".into());
        }
        Ok(format!(
            "{READ_PREFIX}{}/{zone}{}/{base}",
            URL_SAFE_NO_PAD.encode(content_id),
            self.stream_path,
            base = self.base,
        ))
    }
}

impl<'a> ColdSegmentAddress<'a> {
    /// Legacy locators identify the current index entry. Bound reads also
    /// require that entry to retain the originally committed object ID.
    /// Unsupported versions never fall back to an ordinary file read.
    pub fn parse_read(zone: &str, key: &'a str) -> Result<Option<ColdSegmentRead<'a>>, String> {
        if let Some(rest) = key.strip_prefix(READ_PREFIX) {
            let (encoded, address) = rest
                .split_once('/')
                .ok_or("invalid sealed segment read locator")?;
            if encoded.is_empty() || encoded.len() > MAX_CONTENT_ID_BYTES.div_ceil(3) * 4 {
                return Err("invalid sealed segment content identity".into());
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| "invalid sealed segment content identity")?;
            if bytes.is_empty()
                || bytes.len() > MAX_CONTENT_ID_BYTES
                || URL_SAFE_NO_PAD.encode(&bytes) != encoded
            {
                return Err("invalid sealed segment content identity".into());
            }
            let expected_content_id =
                String::from_utf8(bytes).map_err(|_| "invalid sealed segment content identity")?;
            return Ok(Some(ColdSegmentRead {
                address: Self::parse_address(zone, address)?,
                expected_content_id: Some(expected_content_id),
            }));
        }
        if key.starts_with(READ_NAMESPACE) {
            return Err("unsupported sealed segment read locator".into());
        }
        Ok(Self::parse(zone, key)?.map(|address| ColdSegmentRead {
            address,
            expected_content_id: None,
        }))
    }

    /// Decode only the addressed zone; malformed reserved locators refuse.
    pub fn parse(zone: &str, key: &'a str) -> Result<Option<Self>, String> {
        let Some(rest) = key.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        Self::parse_address(zone, rest).map(Some)
    }

    fn parse_address(zone: &str, rest: &'a str) -> Result<Self, String> {
        let invalid = || "invalid sealed segment locator".to_owned();
        let (addressed_zone, _) = rest.split_once('/').ok_or_else(invalid)?;
        if addressed_zone != zone {
            return Err(invalid());
        }
        // Include the leading slash without allocating a second path.
        let rest = &rest[addressed_zone.len()..];
        let (stream_path, base) = rest.rsplit_once('/').ok_or_else(invalid)?;
        contracts::validate_zone_path(stream_path).map_err(|_| invalid())?;
        let parsed = base.parse::<u64>().map_err(|_| invalid())?;
        if base != parsed.to_string() {
            return Err(invalid());
        }
        Ok(Self {
            stream_path,
            base: parsed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_read_locator_preserves_object_identity_and_legacy_index_lookup() {
        let address = ColdSegmentAddress {
            stream_path: "/history/part",
            base: 8,
        };
        let key = address.read_key("agent-alice", "same-hash").unwrap();
        assert_eq!(key, "nexus-cold-v1:c2FtZS1oYXNo/agent-alice/history/part/8");
        assert!(ColdSegmentAddress::parse("agent-alice", &key)
            .unwrap()
            .is_none());
        assert!(contracts::validate_zone_path(&key).is_err());
        let parsed = ColdSegmentAddress::parse_read("agent-alice", &key)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.address.stream_path, "/history/part");
        assert_eq!(parsed.address.base, 8);
        assert!(parsed.matches_content_id("same-hash"));
        assert!(!parsed.matches_content_id("replacement-hash"));
        assert!(ColdSegmentAddress::parse_read("agent-bob", &key).is_err());
        let legacy_key = address.key("agent-alice");
        let legacy = ColdSegmentAddress::parse_read("agent-alice", &legacy_key)
            .unwrap()
            .unwrap();
        assert!(legacy.matches_content_id("current-index-object"));
        assert!(ColdSegmentAddress::parse_read("agent-alice", "/ordinary")
            .unwrap()
            .is_none());
    }

    #[test]
    fn malformed_or_unsupported_bound_locators_cannot_become_file_reads() {
        for key in [
            "nexus-cold-v2:c2FtZS1oYXNo/agent-alice/history/8",
            "nexus-cold-v1:/agent-alice/history/8",
            "nexus-cold-v1:%/agent-alice/history/8",
            "nexus-cold-v1:_w/agent-alice/history/8",
            "nexus-cold-v1:YQ==/agent-alice/history/8",
            "nexus-cold-v1:YQ/agent-alice/history/08",
            "nexus-cold-v1:YQ/agent-alice/../history/8",
        ] {
            assert!(ColdSegmentAddress::parse_read("agent-alice", key).is_err());
        }
        let address = ColdSegmentAddress {
            stream_path: "/history",
            base: 8,
        };
        assert!(address.read_key("agent-alice", "").is_err());
        assert!(address
            .read_key("agent-alice", &"x".repeat(MAX_CONTENT_ID_BYTES + 1))
            .is_err());
    }
}
