//! Shape contract for a zone-mutation `operation_id` — the idempotency
//! key of the typed ZoneRuntime surface.
//!
//! The id becomes a `PutControlState` key in the control zone's replicated
//! store (it rides the raft log and lives in the state machine), so an
//! unbounded arbitrary string is a resource-hygiene hole, not just a
//! cosmetic one: the same request could plant a megabytes-long key. The
//! charset keeps the id safe for logs, journal listings and line-oriented
//! tooling — alphanumeric plus the three separator punctuation `-`, `:`,
//! `.`.

/// Minimum length (non-empty, expressed as an inclusive bound for
/// symmetry with the zone-id contract).
pub const OPERATION_ID_MIN_LEN: usize = 1;
/// Maximum length — generous for a caller-minted unique key, far below
/// anything that could bloat the control store.
pub const OPERATION_ID_MAX_LEN: usize = 128;
/// The one permitted separator set.
pub const OPERATION_ID_CHARSET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-:._";

/// Refusal reasons, mirroring the zone-id contract's error shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationIdError {
    Length { got: usize },
    Character { got: char, at: usize },
}

impl std::fmt::Display for OperationIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationIdError::Length { got } => write!(
                f,
                "operation_id length must be {OPERATION_ID_MIN_LEN}..={OPERATION_ID_MAX_LEN}, got {got}"
            ),
            OperationIdError::Character { got, at } => write!(
                f,
                "operation_id contains a character outside [A-Za-z0-9-:._] at byte {at}: {got:?}"
            ),
        }
    }
}

/// Validate an `operation_id` for use as a mutation idempotency key.
pub fn validate_operation_id(id: &str) -> Result<(), OperationIdError> {
    let len = id.chars().count();
    if !(OPERATION_ID_MIN_LEN..=OPERATION_ID_MAX_LEN).contains(&len) {
        return Err(OperationIdError::Length { got: len });
    }
    for (at, got) in id.chars().enumerate() {
        if !OPERATION_ID_CHARSET.contains(got) {
            return Err(OperationIdError::Character { got, at });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_documented_shape() {
        assert!(validate_operation_id("op-create-tenant-a-0001").is_ok());
        assert!(validate_operation_id("a").is_ok());
        assert!(validate_operation_id("retry:2.20261007").is_ok());
    }

    #[test]
    fn refuses_empty_oversized_and_bad_characters() {
        assert_eq!(
            validate_operation_id(""),
            Err(OperationIdError::Length { got: 0 })
        );
        let long = "x".repeat(OPERATION_ID_MAX_LEN + 1);
        assert_eq!(
            validate_operation_id(&long),
            Err(OperationIdError::Length {
                got: OPERATION_ID_MAX_LEN + 1
            })
        );
        assert_eq!(
            validate_operation_id("op\n"),
            Err(OperationIdError::Character { got: '\n', at: 2 })
        );
        assert_eq!(
            validate_operation_id("op id"),
            Err(OperationIdError::Character { got: ' ', at: 2 })
        );
    }
}
