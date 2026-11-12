//! Peer addressing for a committed segment, independent of CAS/PAS object IDs.

const PREFIX: &str = "/__stream_segments__/";

/// A segment locator names an existing entry in the owning stream's index.
/// It supplies no authority and never permits an unindexed object read.
pub struct ColdSegmentAddress<'a> {
    pub stream_path: &'a str,
    pub base: u64,
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
}

impl<'a> ColdSegmentAddress<'a> {
    /// Decode only the addressed zone; malformed reserved locators refuse.
    pub fn parse(zone: &str, key: &'a str) -> Result<Option<Self>, String> {
        let Some(rest) = key.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        let invalid = || "invalid sealed segment locator".to_owned();
        let (addressed_zone, _) = rest.split_once('/').ok_or_else(invalid)?;
        if addressed_zone != zone {
            return Err(invalid());
        }
        // Include the leading slash without allocating a second path.
        let rest = &key[PREFIX.len() + addressed_zone.len()..];
        let (stream_path, base) = rest.rsplit_once('/').ok_or_else(invalid)?;
        contracts::validate_zone_path(stream_path).map_err(|_| invalid())?;
        let parsed = base.parse::<u64>().map_err(|_| invalid())?;
        if base != parsed.to_string() {
            return Err(invalid());
        }
        Ok(Some(Self {
            stream_path,
            base: parsed,
        }))
    }
}
