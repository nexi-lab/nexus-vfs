//! Zone-relative wire-path validation.
//!
//! Rules are generated from `contracts/zone-path/spec.json`. This validates the
//! path accepted at an API boundary; kernel routing separately prefixes the zone
//! id to derive an internal storage key.

include!(concat!(env!("OUT_DIR"), "/zone_path_rules.rs"));

/// Why a zone-relative path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZonePathError {
    /// The path is longer than [`ZONE_PATH_MAX_LEN`].
    Length { got: usize },
    /// The path does not begin with [`ZONE_PATH_START`].
    NotAbsolute,
    /// A component is empty, including a non-root trailing slash.
    EmptyComponent { at: usize },
    /// A component is `.` or `..`.
    ForbiddenComponent { component: String, at: usize },
    /// A component exceeds [`ZONE_PATH_COMPONENT_MAX_LEN`].
    ComponentLength { got: usize, at: usize },
    /// A component contains a character outside [`ZONE_PATH_COMPONENT_CHARSET`].
    Character {
        got: char,
        component: usize,
        at: usize,
    },
    /// The path exceeds [`ZONE_PATH_MAX_DEPTH`] components.
    Depth { got: usize },
    /// The path is under a kernel-owned prefix.
    ReservedPrefix,
}

impl std::fmt::Display for ZonePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length { got } => {
                write!(f, "zone path must be at most {ZONE_PATH_MAX_LEN} characters, got {got}")
            }
            Self::NotAbsolute => write!(f, "zone path must start with {ZONE_PATH_START:?}"),
            Self::EmptyComponent { at } => write!(f, "zone path contains an empty component at {at}"),
            Self::ForbiddenComponent { component, at } => {
                write!(f, "zone path component {at} must not be {component:?}")
            }
            Self::ComponentLength { got, at } => write!(
                f,
                "zone path component {at} must be at most {ZONE_PATH_COMPONENT_MAX_LEN} characters, got {got}"
            ),
            Self::Character { got, component, at } => write!(
                f,
                "zone path component {component} contains {got:?} at position {at}"
            ),
            Self::Depth { got } => {
                write!(f, "zone path must have at most {ZONE_PATH_MAX_DEPTH} components, got {got}")
            }
            Self::ReservedPrefix => write!(
                f,
                "zone path is under a kernel-owned prefix: {ZONE_PATH_RESERVED_PREFIXES:?}"
            ),
        }
    }
}

impl std::error::Error for ZonePathError {}

/// Checks a canonical zone-relative wire path.
pub fn validate_zone_path(path: &str) -> Result<(), ZonePathError> {
    let len = path.chars().count();
    if len > ZONE_PATH_MAX_LEN {
        return Err(ZonePathError::Length { got: len });
    }
    if !path.starts_with(ZONE_PATH_START) {
        return Err(ZonePathError::NotAbsolute);
    }
    if path == ZONE_PATH_ROOT {
        return Ok(());
    }

    if ZONE_PATH_RESERVED_PREFIXES.iter().any(|prefix| {
        let prefix = prefix.trim_end_matches('/');
        path == prefix || path.starts_with(&format!("{prefix}/"))
    }) {
        return Err(ZonePathError::ReservedPrefix);
    }

    let components = path[ZONE_PATH_START.len()..].split('/').collect::<Vec<_>>();
    if components.len() > ZONE_PATH_MAX_DEPTH {
        return Err(ZonePathError::Depth {
            got: components.len(),
        });
    }

    for (component_index, component) in components.iter().enumerate() {
        if component.is_empty() && !ZONE_PATH_ALLOW_EMPTY_COMPONENTS {
            return Err(ZonePathError::EmptyComponent {
                at: component_index,
            });
        }
        if ZONE_PATH_FORBIDDEN_COMPONENTS.contains(component) {
            return Err(ZonePathError::ForbiddenComponent {
                component: (*component).to_string(),
                at: component_index,
            });
        }
        let component_len = component.chars().count();
        if component_len > ZONE_PATH_COMPONENT_MAX_LEN {
            return Err(ZonePathError::ComponentLength {
                got: component_len,
                at: component_index,
            });
        }
        for (at, got) in component.chars().enumerate() {
            if !ZONE_PATH_COMPONENT_CHARSET.contains(got) {
                return Err(ZonePathError::Character {
                    got,
                    component: component_index,
                    at,
                });
            }
        }
    }

    if !ZONE_PATH_ALLOW_TRAILING_SLASH && path.ends_with('/') {
        return Err(ZonePathError::EmptyComponent {
            at: components.len() - 1,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agrees_with_owner_fixtures() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/zone-path/fixtures/paths.json"
        )))
        .expect("zone-path fixture must be valid JSON");

        for case in fixture["cases"].as_array().expect("cases must be an array") {
            let path = case["path"].as_str().expect("path must be a string");
            let expected = case["valid"].as_bool().expect("valid must be a boolean");
            assert_eq!(
                validate_zone_path(path).is_ok(),
                expected,
                "fixture disagrees for {path:?}"
            );
        }
    }

    #[test]
    fn enforces_generated_bounds() {
        let deep = format!("/{}", vec!["a"; ZONE_PATH_MAX_DEPTH + 1].join("/"));
        assert!(matches!(
            validate_zone_path(&deep),
            Err(ZonePathError::Depth { .. })
        ));

        let long_component = format!("/{}", "a".repeat(ZONE_PATH_COMPONENT_MAX_LEN + 1));
        assert!(matches!(
            validate_zone_path(&long_component),
            Err(ZonePathError::ComponentLength { .. })
        ));
    }
}
