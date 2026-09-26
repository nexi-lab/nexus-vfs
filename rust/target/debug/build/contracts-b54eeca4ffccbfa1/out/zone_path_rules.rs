// @generated from contracts/zone-path/spec.json and cases.json — do not edit.
// Regenerated on every build; this file lives in OUT_DIR, not the tree.

/// Stable owner identifier used by exact-pinned projections.
pub const ZONE_PATH_CONTRACT_ID: &str = "urn:sudo:nexus-vfs:zone-path:v1";
/// Required JSON Schema dialect for the portable projection.
pub const ZONE_PATH_META_SCHEMA_ID: &str = "urn:sudo:nexus-vfs:meta:zone-path:v1";
/// Required JSON Schema vocabulary that enforces ZonePath semantics.
pub const ZONE_PATH_REQUIRED_VOCABULARY: &str = "urn:sudo:nexus-vfs:vocab:zone-path:v1";
/// The only spelling of the zone-relative root.
pub const ZONE_PATH_ROOT: &str = "/";
/// The platform-independent path separator.
pub const ZONE_PATH_SEPARATOR: char = '/';
/// Segments refused exactly, without decoding or normalization.
pub const ZONE_PATH_FORBIDDEN_SEGMENTS: &[&str] = &[".", ".."];
/// Characters that cannot occur in a ZonePath.
pub const ZONE_PATH_FORBIDDEN_CHARACTERS: &[char] = &['\0', '\\'];
/// Owner cases derived from the portable fixture file.
pub const ZONE_PATH_VECTORS: &[ZonePathVector] = &[
    ZonePathVector { id: "root", class: "boundary", path: "/", should_accept: true },
    ZonePathVector { id: "single-segment", class: "positive", path: "/artifact", should_accept: true },
    ZonePathVector { id: "nested", class: "positive", path: "/sessions/sess_123/artifacts/result.json", should_accept: true },
    ZonePathVector { id: "unicode-nfc", class: "positive", path: "/资料/café.txt", should_accept: true },
    ZonePathVector { id: "unicode-nfd", class: "positive", path: "/资料/cafe\u{301}.txt", should_accept: true },
    ZonePathVector { id: "percent-looking-literal", class: "positive", path: "/literal/%2e%2e/value", should_accept: true },
    ZonePathVector { id: "mixed-case-preserved", class: "positive", path: "/Case/Sensitive", should_accept: true },
    ZonePathVector { id: "terminal-newline-is-literal", class: "positive", path: "/artifact/.\n", should_accept: true },
    ZonePathVector { id: "terminal-newline-parent-looking-is-literal", class: "positive", path: "/artifact/..\n", should_accept: true },
    ZonePathVector { id: "unicode-scalar-above-bmp", class: "positive", path: "/emoji/😀", should_accept: true },
    ZonePathVector { id: "empty", class: "boundary", path: "", should_accept: false },
    ZonePathVector { id: "relative", class: "negative", path: "artifact/file", should_accept: false },
    ZonePathVector { id: "leading-repeated-separator", class: "negative", path: "//artifact", should_accept: false },
    ZonePathVector { id: "interior-repeated-separator", class: "negative", path: "/artifact//file", should_accept: false },
    ZonePathVector { id: "all-separators-not-root", class: "boundary", path: "///", should_accept: false },
    ZonePathVector { id: "trailing-separator", class: "negative", path: "/artifact/", should_accept: false },
    ZonePathVector { id: "current-directory-segment", class: "negative", path: "/artifact/./file", should_accept: false },
    ZonePathVector { id: "parent-directory-segment", class: "negative", path: "/artifact/../file", should_accept: false },
    ZonePathVector { id: "root-current-directory", class: "boundary", path: "/.", should_accept: false },
    ZonePathVector { id: "root-parent-directory", class: "boundary", path: "/..", should_accept: false },
    ZonePathVector { id: "nul", class: "negative", path: "/artifact/\0/file", should_accept: false },
    ZonePathVector { id: "backslash", class: "negative", path: "/artifact\\file", should_accept: false },
    ZonePathVector { id: "backslash-parent-looking", class: "negative", path: "/artifact\\..\\file", should_accept: false },
];
/// JSON Schema projection generated from the owner source.
pub const ZONE_PATH_SCHEMA_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/zone_path_schema.json"));
/// Required meta-schema generated from the owner source.
pub const ZONE_PATH_META_SCHEMA_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/zone_path_meta_schema.json"));
