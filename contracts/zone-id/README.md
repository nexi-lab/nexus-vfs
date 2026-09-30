# ZoneId owner contract

`spec.json` is the canonical editable source for `urn:sudo:nexus-vfs:zone-id:v1`. Rust constants and conformance vectors are generated from it at compile time.

`schema.json` is a generated projection of the portable lexical form: 3–63 lowercase ASCII alphanumeric or hyphen characters, with no leading or trailing hyphen. It intentionally does not copy the values of kernel-owned reserved constants. Tenant creation must additionally call `contracts::zone_id::validate_zone_id`, which resolves the constant names listed in `spec.json`; reference consumers must apply the reserved/system-zone policy of their own boundary.

`vectors.json` is generated from the same owner source, including length boundaries and a terminal-newline portability case. The default Rust test job checks both generated files byte-for-byte, and the owner schema job validates the portable vectors with Ajv Draft 2020-12.

Regenerate the lexical schema with:

```bash
cargo run -p contracts --example zone_id_projection > contracts/zone-id/schema.json
```

Regenerate the portable vectors with:

```bash
cargo run -p contracts --example zone_id_vectors > contracts/zone-id/vectors.json
```
