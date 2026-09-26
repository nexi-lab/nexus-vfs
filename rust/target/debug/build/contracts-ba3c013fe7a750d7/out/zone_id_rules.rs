// @generated from contracts/zone-id/spec.json — do not edit.
// Regenerated on every build; this file lives in OUT_DIR, not the tree.

/// Stable owner identifier for this contract revision family.
pub const ZONE_ID_CONTRACT_ID: &str = "urn:sudo:nexus-vfs:zone-id:v1";
/// Shortest permitted zone id.
pub const ZONE_ID_MIN_LEN: usize = 3;
/// Longest permitted zone id.
pub const ZONE_ID_MAX_LEN: usize = 63;
/// Every character a zone id may contain.
pub const ZONE_ID_CHARSET: &str = "abcdefghijklmnopqrstuvwxyz0123456789-";
/// Character a zone id may not start with.
pub const ZONE_ID_NO_LEADING: char = '-';
/// Character a zone id may not end with.
pub const ZONE_ID_NO_TRAILING: char = '-';
/// Ids the kernel owns; tenants may not create them.
pub const ZONE_ID_RESERVED: &[&str] = &[
        crate::constants::ROOT_ZONE_ID,
        crate::constants::CONTROL_ZONE_ID,
    ];
/// JSON Schema projection of the portable lexical form.
pub const ZONE_ID_SCHEMA_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/zone_id_schema.json"));

/// Cases derived from the spec: `(id, should_be_accepted)`.
pub const ZONE_ID_VECTORS: &[(&str, bool)] = &[
    ("aaa", true),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true),
    ("cloud-user-1001", true),
    ("550e8400-e29b-41d4-a716-446655440000", true),
    ("aa", false),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false),
    ("-leading", false),
    ("trailing-", false),
    ("Has-Upper", false),
    ("has_char", false),
    ("org:550e8400-e29b-41d4-a716-446655440000", false),
    ("abc\n", false),
];
/// Portable JSON form of the generated lexical vectors.
pub const ZONE_ID_VECTORS_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/zone_id_vectors.json"));
