//! Generates the zone-id rules from `contracts/zone-id/spec.json`.
//!
//! The generated file goes to `OUT_DIR` and is `include!`d by `src/zone_id.rs`.
//! It is deliberately never written into the tree: a generated artifact that
//! exists as a file is a generated artifact someone can hand-edit, and the edit
//! survives review by looking like ordinary source. Here there is nothing to
//! edit — the rules are recomputed on every build, so the only way to change
//! them is to change the spec.
//!
//! Only the rule *data* is generated. The checking logic is written once, in
//! `zone_id.rs`, in Rust. That split is on purpose: data is what drifts between
//! consumers (one place says 63, another says 64), and logic in two languages is
//! never the same text anyway. What keeps the logic honest across languages is
//! the conformance vectors this script also emits, which every consumer's tests
//! must agree with.

use std::path::PathBuf;

fn main() {
    let spec_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/zone-id/spec.json")
        .canonicalize()
        .expect("contracts/zone-id/spec.json must exist — it is the SSOT for this crate's zone-id rules");

    // Re-run when the spec changes, and only then.
    println!("cargo:rerun-if-changed={}", spec_path.display());

    let raw = std::fs::read_to_string(&spec_path).expect("spec.json is unreadable");
    let spec: serde_json::Value = serde_json::from_str(&raw).expect("spec.json is not valid JSON");

    let min = spec["length"]["min"].as_u64().expect("length.min");
    let max = spec["length"]["max"].as_u64().expect("length.max");
    let charset = spec["charset"]["allowed"]
        .as_str()
        .expect("charset.allowed");
    let no_leading = spec["edges"]["no_leading"]
        .as_str()
        .expect("edges.no_leading");
    let no_trailing = spec["edges"]["no_trailing"]
        .as_str()
        .expect("edges.no_trailing");

    // Reserved ids are named by constant, not by value: constants.rs owns the
    // strings. Restating them here would be the duplication this file exists to
    // remove.
    let reserved: Vec<String> = spec["reserved"]["constants"]
        .as_array()
        .expect("reserved.constants")
        .iter()
        .map(|v| v.as_str().expect("reserved constant name").to_string())
        .collect();

    let reserved_refs = reserved
        .iter()
        .map(|name| format!("        crate::constants::{name},"))
        .collect::<Vec<_>>()
        .join("\n");

    let generated = format!(
        "// @generated from contracts/zone-id/spec.json — do not edit.\n\
         // Regenerated on every build; this file lives in OUT_DIR, not the tree.\n\
         \n\
         /// Shortest permitted zone id.\n\
         pub const ZONE_ID_MIN_LEN: usize = {min};\n\
         /// Longest permitted zone id.\n\
         pub const ZONE_ID_MAX_LEN: usize = {max};\n\
         /// Every character a zone id may contain.\n\
         pub const ZONE_ID_CHARSET: &str = {charset:?};\n\
         /// Character a zone id may not start with.\n\
         pub const ZONE_ID_NO_LEADING: char = {no_leading:?};\n\
         /// Character a zone id may not end with.\n\
         pub const ZONE_ID_NO_TRAILING: char = {no_trailing:?};\n\
         /// Ids the kernel owns; tenants may not create them.\n\
         pub const ZONE_ID_RESERVED: &[&str] = &[\n{reserved_refs}\n    ];\n",
        min = min,
        max = max,
        charset = charset,
        no_leading = no_leading.chars().next().expect("no_leading is one char"),
        no_trailing = no_trailing.chars().next().expect("no_trailing is one char"),
        reserved_refs = reserved_refs,
    );

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("zone_id_rules.rs");
    std::fs::write(&out, generated).expect("failed to write generated zone-id rules");
}
