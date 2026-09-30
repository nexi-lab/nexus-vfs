//! Strict, opt-in zone-relative paths for new reference boundaries.
//!
//! This module does not replace the kernel's legacy `validate_path_fast` or
//! reinterpret persisted keys. It defines the portable subset identified by
//! [`ZONE_PATH_CONTRACT_ID`]: callers validate raw input before authorization,
//! routing, or storage and retain the exact accepted spelling.

/// A portable fixture generated from `contracts/zone-path/cases.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZonePathVector {
    pub id: &'static str,
    pub class: &'static str,
    pub path: &'static str,
    pub should_accept: bool,
}

include!(concat!(env!("OUT_DIR"), "/zone_path_rules.rs"));

/// Why a strict ZonePath was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZonePathError {
    Empty,
    NotAbsolute,
    RepeatedSeparator { at: usize },
    TrailingSeparator,
    ForbiddenSegment { got: &'static str, at: usize },
    ForbiddenCharacter { got: char, at: usize },
}

impl std::fmt::Display for ZonePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "zone path must not be empty"),
            Self::NotAbsolute => write!(
                f,
                "zone path must start with the {ZONE_PATH_SEPARATOR:?} separator"
            ),
            Self::RepeatedSeparator { at } => write!(
                f,
                "zone path contains a repeated {ZONE_PATH_SEPARATOR:?} separator at position {at}"
            ),
            Self::TrailingSeparator => write!(
                f,
                "zone path must not end with {ZONE_PATH_SEPARATOR:?} unless it is {ZONE_PATH_ROOT:?}"
            ),
            Self::ForbiddenSegment { got, at } => {
                write!(f, "zone path contains forbidden segment {got:?} at index {at}")
            }
            Self::ForbiddenCharacter { got, at } => write!(
                f,
                "zone path contains forbidden character {got:?} at position {at}"
            ),
        }
    }
}

impl std::error::Error for ZonePathError {}

/// A borrowed path that has passed the strict owner validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZonePathRef<'a>(&'a str);

impl<'a> ZonePathRef<'a> {
    pub fn parse(path: &'a str) -> Result<Self, ZonePathError> {
        validate_zone_path(path)?;
        Ok(Self(path))
    }

    pub fn as_str(self) -> &'a str {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for ZonePathRef<'a> {
    type Error = ZonePathError;

    fn try_from(path: &'a str) -> Result<Self, Self::Error> {
        Self::parse(path)
    }
}

impl AsRef<str> for ZonePathRef<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl std::fmt::Display for ZonePathRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Validate a strict zone-relative path without changing its spelling.
pub fn validate_zone_path(path: &str) -> Result<(), ZonePathError> {
    if path.is_empty() {
        return Err(ZonePathError::Empty);
    }
    if !path.starts_with(ZONE_PATH_SEPARATOR) {
        return Err(ZonePathError::NotAbsolute);
    }
    if path == ZONE_PATH_ROOT {
        return Ok(());
    }
    if path.ends_with(ZONE_PATH_SEPARATOR) {
        return Err(ZonePathError::TrailingSeparator);
    }

    let mut previous_separator = false;
    for (at, got) in path.chars().enumerate() {
        if ZONE_PATH_FORBIDDEN_CHARACTERS.contains(&got) {
            return Err(ZonePathError::ForbiddenCharacter { got, at });
        }
        if got == ZONE_PATH_SEPARATOR {
            if previous_separator {
                return Err(ZonePathError::RepeatedSeparator { at });
            }
            previous_separator = true;
        } else {
            previous_separator = false;
        }
    }

    for (at, segment) in path.split(ZONE_PATH_SEPARATOR).enumerate().skip(1) {
        if let Some(got) = ZONE_PATH_FORBIDDEN_SEGMENTS
            .iter()
            .copied()
            .find(|forbidden| segment == *forbidden)
        {
            return Err(ZonePathError::ForbiddenSegment { got, at });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_agrees_with_every_owner_fixture() {
        let mut disagreed = Vec::new();
        for case in ZONE_PATH_VECTORS {
            let accepted = validate_zone_path(case.path).is_ok();
            if accepted != case.should_accept {
                disagreed.push(format!(
                    "{} ({:?}, {}): expected accepted={}, validator said {accepted}",
                    case.id, case.path, case.class, case.should_accept
                ));
            }
        }
        assert!(
            disagreed.is_empty(),
            "validator disagrees with owner fixtures:\n  {}",
            disagreed.join("\n  ")
        );
        assert!(ZONE_PATH_VECTORS.iter().any(|case| case.should_accept));
        assert!(ZONE_PATH_VECTORS.iter().any(|case| !case.should_accept));
        assert!(ZONE_PATH_VECTORS
            .iter()
            .any(|case| case.class == "boundary"));
    }

    #[test]
    fn generated_projections_match_the_pinned_owner_files() {
        let committed = include_str!("../../../contracts/zone-path/schema.json");
        assert_eq!(
            ZONE_PATH_SCHEMA_JSON, committed,
            "contracts/zone-path/schema.json drifted; regenerate it with \
             `cargo run -p contracts --example zone_path_projection > \
             contracts/zone-path/schema.json`"
        );

        let committed_meta = include_str!("../../../contracts/zone-path/meta-schema.json");
        assert_eq!(
            ZONE_PATH_META_SCHEMA_JSON, committed_meta,
            "contracts/zone-path/meta-schema.json drifted; regenerate it with \
             `cargo run -p contracts --example zone_path_meta_schema > \
             contracts/zone-path/meta-schema.json`"
        );
    }

    #[test]
    fn accepted_spelling_is_preserved_without_normalization() {
        let nfc = ZonePathRef::parse("/资料/café.txt").unwrap();
        let nfd = ZonePathRef::parse("/资料/cafe\u{301}.txt").unwrap();
        let encoded = ZonePathRef::parse("/literal/%2e%2e/value").unwrap();

        assert_eq!(nfc.as_str(), "/资料/café.txt");
        assert_eq!(nfd.as_str(), "/资料/cafe\u{301}.txt");
        assert_ne!(nfc.as_str().as_bytes(), nfd.as_str().as_bytes());
        assert_eq!(encoded.as_str(), "/literal/%2e%2e/value");
    }

    #[test]
    fn errors_identify_the_first_actionable_violation() {
        assert_eq!(validate_zone_path(""), Err(ZonePathError::Empty));
        assert_eq!(
            validate_zone_path("relative"),
            Err(ZonePathError::NotAbsolute)
        );
        assert_eq!(
            validate_zone_path("/a/"),
            Err(ZonePathError::TrailingSeparator)
        );
        assert_eq!(
            validate_zone_path("/a//b"),
            Err(ZonePathError::RepeatedSeparator { at: 3 })
        );
        assert_eq!(
            validate_zone_path("/a/../b"),
            Err(ZonePathError::ForbiddenSegment { got: "..", at: 2 })
        );
        assert_eq!(
            validate_zone_path("/a\\b"),
            Err(ZonePathError::ForbiddenCharacter { got: '\\', at: 2 })
        );
    }

    #[test]
    fn contract_identity_comes_from_the_owner_spec() {
        assert_eq!(ZONE_PATH_CONTRACT_ID, "urn:sudo:nexus-vfs:zone-path:v1");
        assert_eq!(
            ZONE_PATH_META_SCHEMA_ID,
            "urn:sudo:nexus-vfs:meta:zone-path:v1"
        );
        assert_eq!(
            ZONE_PATH_REQUIRED_VOCABULARY,
            "urn:sudo:nexus-vfs:vocab:zone-path:v1"
        );
        assert_eq!(ZONE_PATH_ROOT, "/");
        assert_eq!(ZONE_PATH_SEPARATOR, '/');
    }
}
