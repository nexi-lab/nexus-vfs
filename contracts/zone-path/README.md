# ZonePath owner contract

`spec.json` is the canonical editable source for `urn:sudo:nexus-vfs:zone-path:v1`. A ZonePath is an absolute path inside a separately identified zone. It is not a global path with a ZoneId embedded as its first segment.

The contract is strict and opt-in for new boundaries:

- `/` is the root and the shortest valid path;
- separators are single `/` characters, with no trailing separator except at root;
- exact `.` and `..` segments, NUL, and backslash are rejected;
- input contains only Unicode scalar values and has a UTF-8 representation; Unicode is neither normalized nor case-folded;
- percent-looking text is literal and is not decoded;
- validation does not normalize and must happen before authorization, routing, or storage.

Legacy `validate_path_fast`, raw syscalls, and persisted keys intentionally keep their existing behavior. They are not retroactively declared to be ZonePath-conformant.

`contracts::zone_path::ZonePathRef::parse` is the owner runtime parser. New consumers must call it, or a derived validator with the same fixtures, at their ingress before authorization, routing, or storage. This contract does not map a `(zone_id, path)` pair onto a global mount alias: mount selection and authorization are separate consumer responsibilities.

The projection declares `urn:sudo:nexus-vfs:meta:zone-path:v1` as its dialect. That generated meta-schema marks `urn:sudo:nexus-vfs:vocab:zone-path:v1` as required and defines the `sudoZonePath` assertion keyword. The keyword carries the generated path rules, including Unicode-scalar enforcement. Validators that have not registered that vocabulary must refuse to compile the projection instead of silently ignoring any owner rule.

`cases.json` is the owner fixture set. `schema.json` and `meta-schema.json` are generated from `spec.json` by `rust/contracts/build.rs` and checked byte-for-byte by the default Rust test job. `.gitattributes` pins owner JSON files to LF so their raw SHA-256 digests are platform-independent. The default Node job uses Ajv Draft 2020-12 with the required vocabulary to validate every fixture and explicit lone-surrogate negatives.

Regenerate the value schema with:

```bash
cargo run -p contracts --example zone_path_projection > contracts/zone-path/schema.json
```

Regenerate the required meta-schema with:

```bash
cargo run -p contracts --example zone_path_meta_schema > contracts/zone-path/meta-schema.json
```

Check the portable projection with:

```bash
npm test --prefix contracts/zone-path
```
