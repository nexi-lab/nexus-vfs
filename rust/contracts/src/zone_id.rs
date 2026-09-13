//! Zone-id format, enforced rather than described.
//!
//! The rules below are generated at build time from `contracts/zone-id/spec.json`
//! into `OUT_DIR` and included here. Nothing in the tree restates them, so there
//! is exactly one place to change a bound and no second copy to forget.
//!
//! # Why this exists
//!
//! The format was documented in several places — 3–63 characters, lowercase
//! alphanumeric plus hyphen, no leading or trailing hyphen, reserved ids
//! excluded — and enforced in none. `parse_zones_str` splits on commas and
//! trims; `ZoneManager::create_zone` validates the peer list and passes
//! `zone_id: &str` straight through. A 200-character id with capitals and a
//! trailing hyphen is accepted today, and the first thing that notices is
//! whatever downstream cannot put it in a DNS label.
//!
//! # Where this is NOT used
//!
//! Not on `route()`. Typing zones to enforce their rules in the type system was
//! considered and deferred as YAGNI (see `constants::ROOT_ZONE_ID`), partly
//! because `route().zone_id` is on the file read/write path. Nothing here
//! changes that: this validates at admission — where an id is first accepted
//! from an operator, an API, or a config string — and never on the hot path. An
//! id that reached storage was validated once, at the boundary.

include!(concat!(env!("OUT_DIR"), "/zone_id_rules.rs"));

/// Why a zone id was refused. Carries the offending detail so an operator is
/// told what to change, not merely that something was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneIdError {
    /// Shorter than [`ZONE_ID_MIN_LEN`] or longer than [`ZONE_ID_MAX_LEN`].
    Length { got: usize },
    /// Contains a character outside [`ZONE_ID_CHARSET`].
    Character { got: char, at: usize },
    /// Starts with [`ZONE_ID_NO_LEADING`].
    LeadingHyphen,
    /// Ends with [`ZONE_ID_NO_TRAILING`].
    TrailingHyphen,
    /// Matches an id the kernel owns.
    Reserved,
}

impl std::fmt::Display for ZoneIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length { got } => write!(
                f,
                "zone id must be {ZONE_ID_MIN_LEN}–{ZONE_ID_MAX_LEN} characters, got {got}"
            ),
            Self::Character { got, at } => write!(
                f,
                "zone id contains {got:?} at position {at}; permitted characters are {ZONE_ID_CHARSET}"
            ),
            Self::LeadingHyphen => write!(f, "zone id must not start with {ZONE_ID_NO_LEADING:?}"),
            Self::TrailingHyphen => write!(f, "zone id must not end with {ZONE_ID_NO_TRAILING:?}"),
            Self::Reserved => write!(
                f,
                "zone id is reserved by the kernel; reserved ids are {ZONE_ID_RESERVED:?}"
            ),
        }
    }
}

impl std::error::Error for ZoneIdError {}

/// Checks a zone id against the format.
///
/// Returns the first violation rather than a list: an operator fixes one thing
/// and re-runs, and a partial id is not worth describing exhaustively.
///
/// Reserved ids are refused here because this is the tenant-facing check. The
/// kernel creates its own reserved zones by other paths and does not come
/// through this function.
pub fn validate_zone_id(id: &str) -> Result<(), ZoneIdError> {
    let len = id.chars().count();
    if !(ZONE_ID_MIN_LEN..=ZONE_ID_MAX_LEN).contains(&len) {
        return Err(ZoneIdError::Length { got: len });
    }

    // Edges before charset: "-abc" is more usefully reported as a leading
    // hyphen than as a permitted character in a forbidden position.
    if id.starts_with(ZONE_ID_NO_LEADING) {
        return Err(ZoneIdError::LeadingHyphen);
    }
    if id.ends_with(ZONE_ID_NO_TRAILING) {
        return Err(ZoneIdError::TrailingHyphen);
    }

    for (at, got) in id.chars().enumerate() {
        if !ZONE_ID_CHARSET.contains(got) {
            return Err(ZoneIdError::Character { got, at });
        }
    }

    if ZONE_ID_RESERVED.contains(&id) {
        return Err(ZoneIdError::Reserved);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_shapes_the_docs_promise() {
        for id in [
            "cloud-user-1001",
            "private-acme-office",
            "private-acme-core",
            "edge-device-01",
            "abc",
        ] {
            assert_eq!(validate_zone_id(id), Ok(()), "{id} should be accepted");
        }
    }

    #[test]
    fn refuses_what_was_accepted_before_this_existed() {
        // Every one of these is admitted by the daemon today.
        assert!(matches!(
            validate_zone_id("ab"),
            Err(ZoneIdError::Length { got: 2 })
        ));
        assert!(matches!(
            validate_zone_id(&"a".repeat(ZONE_ID_MAX_LEN + 1)),
            Err(ZoneIdError::Length { .. })
        ));
        assert_eq!(
            validate_zone_id("-leading"),
            Err(ZoneIdError::LeadingHyphen)
        );
        assert_eq!(
            validate_zone_id("trailing-"),
            Err(ZoneIdError::TrailingHyphen)
        );
        assert!(matches!(
            validate_zone_id("Has-Upper"),
            Err(ZoneIdError::Character { got: 'H', at: 0 })
        ));
        assert!(matches!(
            validate_zone_id("has_underscore"),
            Err(ZoneIdError::Character { .. })
        ));
    }

    #[test]
    fn boundaries_are_inclusive() {
        assert_eq!(validate_zone_id(&"a".repeat(ZONE_ID_MIN_LEN)), Ok(()));
        assert_eq!(validate_zone_id(&"a".repeat(ZONE_ID_MAX_LEN)), Ok(()));
    }

    #[test]
    fn reserved_ids_are_refused_by_the_constants_that_own_them() {
        // Named, not spelled: constants.rs is the SSOT for these strings, so a
        // rename there must not leave this test asserting a stale literal.
        assert_eq!(
            validate_zone_id(crate::constants::ROOT_ZONE_ID),
            Err(ZoneIdError::Reserved)
        );
        // CONTROL_ZONE_ID is doubly excluded — it is also unspellable under the
        // charset rule, which is why it fails on the character check first.
        assert!(validate_zone_id(crate::constants::CONTROL_ZONE_ID).is_err());
    }

    #[test]
    fn rules_come_from_the_spec_not_from_here() {
        // If someone edits the generated file in OUT_DIR these still pass, which
        // is fine: that copy is rebuilt from the spec on the next build. What
        // this pins is that the constants are wired to the generator at all.
        assert_eq!(ZONE_ID_MIN_LEN, 3);
        assert_eq!(ZONE_ID_MAX_LEN, 63);
        assert!(ZONE_ID_CHARSET.contains('-'));
        assert!(!ZONE_ID_CHARSET.contains('_'));
    }

    #[test]
    fn agrees_with_the_vectors_every_consumer_checks_against() {
        // The cross-language contract, asserted on this side.
        //
        // Sharing one spec makes the rule DATA impossible to drift. It does not
        // make the LOGIC impossible to drift — sudostack's TypeScript validator
        // is a second implementation, and it could forget a case while reading
        // the same constants. Both sides check the same derived vectors, so a
        // divergence fails somebody's build instead of waiting to be noticed by
        // whichever consumer hits it first in production.
        let mut disagreed = Vec::new();
        for (id, should_accept) in ZONE_ID_VECTORS {
            let accepted = validate_zone_id(id).is_ok();
            if accepted != *should_accept {
                disagreed.push(format!(
                    "{id:?}: spec says accepted={should_accept}, validator said {accepted}"
                ));
            }
        }
        assert!(
            disagreed.is_empty(),
            "validator disagrees with the spec:
  {}",
            disagreed.join(
                "
  "
            )
        );

        // A vector set that were all-accepting would be satisfied by a validator
        // that never refuses, and all-refusing by one that always does.
        assert!(
            ZONE_ID_VECTORS.iter().any(|(_, ok)| *ok),
            "no accepting vectors"
        );
        assert!(
            ZONE_ID_VECTORS.iter().any(|(_, ok)| !*ok),
            "no refusing vectors"
        );
    }

    #[test]
    fn the_error_says_what_to_change() {
        let msg = validate_zone_id("Has-Upper").unwrap_err().to_string();
        assert!(msg.contains("'H'"), "{msg}");
        assert!(msg.contains("position 0"), "{msg}");
    }
}
