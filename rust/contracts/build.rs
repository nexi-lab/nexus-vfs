//! Generates primitive contract rules from their canonical JSON specs.
//!
//! Generated Rust files go to `OUT_DIR` and are `include!`d by the owning
//! modules. They are deliberately never written into the tree: the only way to
//! change the validator data is to change its spec.

use std::path::{Path, PathBuf};

fn read_spec(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path).expect("contract spec is unreadable");
    serde_json::from_str(&raw).expect("contract spec is not valid JSON")
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let zone_id_spec_path = manifest_dir
        .join("../../contracts/zone-id/spec.json")
        .canonicalize()
        .expect("contracts/zone-id/spec.json must exist — it is the SSOT for this crate's zone-id rules");
    let zone_path_spec_path = manifest_dir
        .join("../../contracts/zone-path/spec.json")
        .canonicalize()
        .expect("contracts/zone-path/spec.json must exist — it is the SSOT for this crate's zone-path rules");

    println!("cargo:rerun-if-changed={}", zone_id_spec_path.display());
    println!("cargo:rerun-if-changed={}", zone_path_spec_path.display());

    generate_zone_id_rules(&zone_id_spec_path);
    generate_zone_path_rules(&zone_path_spec_path);
}

fn generate_zone_id_rules(spec_path: &Path) {
    let spec = read_spec(spec_path);
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
        no_leading = no_leading.chars().next().expect("no_leading is one char"),
        no_trailing = no_trailing.chars().next().expect("no_trailing is one char"),
    );

    let bad_char = if charset.contains('_') { '!' } else { '_' };
    let vectors = format!(
        "/// Cases derived from the spec: `(id, should_be_accepted)`.\n\
         pub const ZONE_ID_VECTORS: &[(&str, bool)] = &[\n\
             ({shortest:?}, true),\n\
             ({longest:?}, true),\n\
             (\"cloud-user-1001\", true),\n\
             (\"550e8400-e29b-41d4-a716-446655440000\", true),\n\
             ({too_short:?}, false),\n\
             ({too_long:?}, false),\n\
             ({leading:?}, false),\n\
             ({trailing:?}, false),\n\
             (\"Has-Upper\", false),\n\
             ({bad_char_case:?}, false),\n\
             (\"org:550e8400-e29b-41d4-a716-446655440000\", false),\n\
         ];\n",
        shortest = "a".repeat(min as usize),
        longest = "a".repeat(max as usize),
        too_short = "a".repeat((min - 1) as usize),
        too_long = "a".repeat((max + 1) as usize),
        leading = format!("{no_leading}leading"),
        trailing = format!("trailing{no_trailing}"),
        bad_char_case = format!("has{bad_char}char"),
    );

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("zone_id_rules.rs");
    std::fs::write(out, format!("{generated}\n{vectors}"))
        .expect("failed to write generated zone-id rules");
}

fn generate_zone_path_rules(spec_path: &Path) {
    let spec = read_spec(spec_path);
    let root = spec["root"].as_str().expect("root");
    let must_start_with = spec["must_start_with"].as_str().expect("must_start_with");
    let charset = spec["component"]["allowed"]
        .as_str()
        .expect("component.allowed");
    let component_max = spec["component"]["max_length"]
        .as_u64()
        .expect("component.max_length");
    let forbidden = spec["component"]["forbidden"]
        .as_array()
        .expect("component.forbidden")
        .iter()
        .map(|value| value.as_str().expect("forbidden component"))
        .collect::<Vec<_>>();
    let depth_max = spec["depth"]["max"].as_u64().expect("depth.max");
    let length_max = spec["length"]["max"].as_u64().expect("length.max");
    let empty_components = spec["empty_components"]
        .as_bool()
        .expect("empty_components");
    let trailing_slash = spec["trailing_slash"].as_bool().expect("trailing_slash");
    let reserved = spec["reserved_prefix_constants"]
        .as_array()
        .expect("reserved_prefix_constants")
        .iter()
        .map(|value| value.as_str().expect("reserved prefix constant"))
        .collect::<Vec<_>>();

    let forbidden_values = forbidden
        .iter()
        .map(|value| format!("    {value:?},"))
        .collect::<Vec<_>>()
        .join("\n");
    let reserved_refs = reserved
        .iter()
        .map(|name| format!("    crate::constants::{name},"))
        .collect::<Vec<_>>()
        .join("\n");

    let generated = format!(
        "// @generated from contracts/zone-path/spec.json — do not edit.\n\
         // Regenerated on every build; this file lives in OUT_DIR, not the tree.\n\
         pub const ZONE_PATH_ROOT: &str = {root:?};\n\
         pub const ZONE_PATH_START: &str = {must_start_with:?};\n\
         pub const ZONE_PATH_COMPONENT_CHARSET: &str = {charset:?};\n\
         pub const ZONE_PATH_COMPONENT_MAX_LEN: usize = {component_max};\n\
         pub const ZONE_PATH_FORBIDDEN_COMPONENTS: &[&str] = &[\n{forbidden_values}\n];\n\
         pub const ZONE_PATH_MAX_DEPTH: usize = {depth_max};\n\
         pub const ZONE_PATH_MAX_LEN: usize = {length_max};\n\
         pub const ZONE_PATH_ALLOW_EMPTY_COMPONENTS: bool = {empty_components};\n\
         pub const ZONE_PATH_ALLOW_TRAILING_SLASH: bool = {trailing_slash};\n\
         pub const ZONE_PATH_RESERVED_PREFIXES: &[&str] = &[\n{reserved_refs}\n];\n"
    );

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("zone_path_rules.rs");
    std::fs::write(out, generated).expect("failed to write generated zone-path rules");
}
