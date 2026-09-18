use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

fn main() {
    if let Err(error) = run() {
        eprintln!("contractgen: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let check = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [arg] if arg == "--check" => true,
        args => return Err(format!("usage: contractgen [--check], got {args:?}")),
    };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repository = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "contracts crate is not under rust/contracts".to_string())?;
    let zone_id_dir = repository.join("contracts/zone-id");
    let zone_path_dir = repository.join("contracts/zone-path");
    let constants = fs::read_to_string(manifest_dir.join("src/constants.rs"))
        .map_err(|error| format!("cannot read constants.rs: {error}"))?;

    let zone_id_spec = read_json(&zone_id_dir.join("spec.json"))?;
    let zone_path_spec = read_json(&zone_path_dir.join("spec.json"))?;
    let outputs = generated_outputs(
        &zone_id_dir,
        &zone_path_dir,
        &zone_id_spec,
        &zone_path_spec,
        &constants,
    )?;

    let mut drifted = Vec::new();
    for (path, value) in outputs {
        let rendered = render_json(&value)?;
        if check {
            match fs::read_to_string(&path) {
                Ok(existing) if normalize_newlines(&existing) == rendered => {}
                _ => drifted.push(path),
            }
        } else {
            fs::write(&path, rendered)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        }
    }

    if drifted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "generated contract files are stale:\n{}\nrun `cargo run -p contracts --bin contractgen`",
            drifted
                .iter()
                .map(|path| format!("  {}", path.display()))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

fn generated_outputs(
    zone_id_dir: &Path,
    zone_path_dir: &Path,
    zone_id_spec: &Value,
    zone_path_spec: &Value,
    constants: &str,
) -> Result<BTreeMap<PathBuf, Value>, String> {
    let min = number(zone_id_spec, &["length", "min"])?;
    let max = number(zone_id_spec, &["length", "max"])?;
    let charset = string(zone_id_spec, &["charset", "allowed"])?;
    let no_leading = string(zone_id_spec, &["edges", "no_leading"])?;
    let no_trailing = string(zone_id_spec, &["edges", "no_trailing"])?;
    let reserved_names = strings(zone_id_spec, &["reserved", "constants"])?;
    let reserved = reserved_names
        .iter()
        .map(|name| constant_value(constants, name))
        .collect::<Result<Vec<_>, _>>()?;

    let format_pattern = zone_id_pattern(charset, no_leading, no_trailing);
    let format_schema = json!({
        "type": "string",
        "minLength": min,
        "maxLength": max,
        "pattern": format_pattern
    });
    let tenant_schema = json!({
        "$schema": SCHEMA_DIALECT,
        "$id": "https://nexus-vfs.dev/contracts/zone-id/tenant-zone-id-create.schema.gen.json",
        "title": "TenantZoneIdCreate",
        "description": "Zone id admitted for creation of a tenant or data zone.",
        "allOf": [format_schema.clone(), {"not": {"enum": reserved}}]
    });
    let reference_schema = |title: &str, id: &str, description: &str| {
        json!({
            "$schema": SCHEMA_DIALECT,
            "$id": format!("https://nexus-vfs.dev/contracts/zone-id/{id}"),
            "title": title,
            "description": description,
            "anyOf": [format_schema.clone(), {"enum": reserved}]
        })
    };

    let root = string(zone_path_spec, &["root"])?;
    let path_start = string(zone_path_spec, &["must_start_with"])?;
    let path_charset = string(zone_path_spec, &["component", "allowed"])?;
    let component_max = number(zone_path_spec, &["component", "max_length"])?;
    let forbidden = strings(zone_path_spec, &["component", "forbidden"])?;
    let max_depth = number(zone_path_spec, &["depth", "max"])?;
    let max_length = number(zone_path_spec, &["length", "max"])?;
    let reserved_prefix_names = strings(zone_path_spec, &["reserved_prefix_constants"])?;
    let reserved_prefixes = reserved_prefix_names
        .iter()
        .map(|name| constant_value(constants, name))
        .collect::<Result<Vec<_>, _>>()?;
    let path_pattern = zone_path_pattern(
        root,
        path_start,
        path_charset,
        component_max,
        max_depth,
        &forbidden,
        &reserved_prefixes,
    )?;

    let path_schema = json!({
        "$schema": SCHEMA_DIALECT,
        "$id": "https://nexus-vfs.dev/contracts/zone-path/zone-path.schema.gen.json",
        "title": "ZonePath",
        "description": "Canonical zone-relative wire path. This is not a product ResourceRef.",
        "type": "string",
        "maxLength": max_length,
        "pattern": path_pattern
    });

    Ok(BTreeMap::from([
        (
            zone_id_dir.join("tenant-zone-id-create.schema.gen.json"),
            tenant_schema,
        ),
        (
            zone_id_dir.join("system-zone-id.schema.gen.json"),
            reference_schema(
                "SystemZoneId",
                "system-zone-id.schema.gen.json",
                "Zone id accepted only by trusted boot and control paths.",
            ),
        ),
        (
            zone_id_dir.join("existing-zone-id-ref.schema.gen.json"),
            reference_schema(
                "ExistingZoneIdRef",
                "existing-zone-id-ref.schema.gen.json",
                "Reference to an existing or historical zone identity; grants no create authority.",
            ),
        ),
        (
            zone_id_dir.join("remote-learned-zone-id.schema.gen.json"),
            {
                let mut schema = reference_schema(
                    "RemoteLearnedZoneId",
                    "remote-learned-zone-id.schema.gen.json",
                    "Identity learned through join or discovery. The caller must separately verify the remote incarnation and trust relationship.",
                );
                schema["x-nexus-vfs-requires-verified-remote"] = Value::Bool(true);
                schema
            },
        ),
        (zone_path_dir.join("zone-path.schema.gen.json"), path_schema),
    ]))
}

fn zone_id_pattern(charset: &str, no_leading: &str, no_trailing: &str) -> String {
    let edge_chars = charset
        .chars()
        .filter(|character| !no_leading.contains(*character) && !no_trailing.contains(*character))
        .collect::<String>();
    format!(
        "^[{}][{}]*[{}]$",
        regex_class(&edge_chars),
        regex_class(charset),
        regex_class(&edge_chars)
    )
}

fn zone_path_pattern(
    root: &str,
    start: &str,
    charset: &str,
    component_max: u64,
    max_depth: u64,
    forbidden: &[String],
    reserved_prefixes: &[String],
) -> Result<String, String> {
    if root != "/" || start != "/" {
        return Err("contractgen currently requires '/' as the zone-path root and prefix".into());
    }
    let forbidden_lookahead = forbidden
        .iter()
        .map(|component| regex_literal(component))
        .collect::<Vec<_>>()
        .join("|");
    let reserved_lookahead = reserved_prefixes
        .iter()
        .map(|prefix| {
            let trimmed = prefix.trim_start_matches('/').trim_end_matches('/');
            format!("{}(?:/|$)", regex_literal(trimmed))
        })
        .collect::<Vec<_>>()
        .join("|");
    let reserved = if reserved_lookahead.is_empty() {
        String::new()
    } else {
        format!("(?!{reserved_lookahead})")
    };
    Ok(format!(
        "^(?:/|/{reserved}(?!(?:{forbidden_lookahead})(?:/|$))[{class}]{{1,{component_max}}}(?:/(?!(?:{forbidden_lookahead})(?:/|$))[{class}]{{1,{component_max}}}){{0,{remaining}}})$",
        class = regex_class(charset),
        remaining = max_depth.saturating_sub(1),
    ))
}

fn regex_class(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\\' | ']' | '^' | '-' => format!("\\{character}"),
            _ => character.to_string(),
        })
        .collect()
}

fn regex_literal(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                format!("\\{character}")
            }
            _ => character.to_string(),
        })
        .collect()
}

fn constant_value(source: &str, name: &str) -> Result<String, String> {
    let marker = format!("pub const {name}: &str = \"");
    let tail = source
        .split_once(&marker)
        .map(|(_, tail)| tail)
        .ok_or_else(|| format!("constant {name} is not a string constant in constants.rs"))?;
    tail.split_once('"')
        .map(|(value, _)| value.to_string())
        .ok_or_else(|| format!("constant {name} has no closing quote"))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("invalid JSON in {}: {error}", path.display()))
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value, String> {
    path.iter().try_fold(value, |current, key| {
        current
            .get(*key)
            .ok_or_else(|| format!("missing spec field {}", path.join(".")))
    })
}

fn string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str, String> {
    value_at(value, path)?
        .as_str()
        .ok_or_else(|| format!("spec field {} is not a string", path.join(".")))
}

fn number(value: &Value, path: &[&str]) -> Result<u64, String> {
    value_at(value, path)?
        .as_u64()
        .ok_or_else(|| format!("spec field {} is not an unsigned integer", path.join(".")))
}

fn strings(value: &Value, path: &[&str]) -> Result<Vec<String>, String> {
    value_at(value, path)?
        .as_array()
        .ok_or_else(|| format!("spec field {} is not an array", path.join(".")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("spec field {} contains a non-string", path.join(".")))
        })
        .collect()
}

fn render_json(value: &Value) -> Result<String, String> {
    let sorted = sort_json(value);
    serde_json::to_string_pretty(&sorted)
        .map(|text| format!("{text}\n"))
        .map_err(|error| format!("cannot render generated JSON: {error}"))
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

fn normalize_newlines(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    format!("{}\n", normalized.trim_end_matches('\n'))
}
