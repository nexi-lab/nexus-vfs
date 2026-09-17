import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import Ajv2020 from 'ajv/dist/2020.js'

const here = new URL('./', import.meta.url)
const readJson = async (path) => JSON.parse(await readFile(new URL(path, here), 'utf8'))
const [
  zonePathSchema,
  zonePathMetaSchema,
  zonePathFixtures,
  zonePathSpec,
  zoneIdSchema,
  zoneIdSpec,
  zoneIdVectors,
] = await Promise.all([
  readJson('schema.json'),
  readJson('meta-schema.json'),
  readJson('cases.json'),
  readJson('spec.json'),
  readJson('../zone-id/schema.json'),
  readJson('../zone-id/spec.json'),
  readJson('../zone-id/vectors.json'),
])
const zonePathKeyword = zonePathSpec.projection.zone_path_keyword
const requiredVocabulary = zonePathSpec.projection.required_vocabulary
assert.equal(zonePathSchema.$schema, zonePathMetaSchema.$id)
assert.equal(zonePathMetaSchema.$vocabulary[requiredVocabulary], true)
assert.deepEqual(zonePathSchema[zonePathKeyword], {
  scope: zonePathSpec.representation.scope,
  absolute: zonePathSpec.representation.absolute,
  root: zonePathSpec.representation.root,
  separator: zonePathSpec.representation.separator,
  empty: zonePathSpec.representation.empty,
  repeated_separators: zonePathSpec.representation.repeated_separators,
  trailing_separator: zonePathSpec.representation.trailing_separator,
  forbidden_exact_segments: zonePathSpec.segments.forbidden_exact,
  forbidden_characters: zonePathSpec.segments.forbidden_characters,
  unicode_scalar_values_only: zonePathSpec.encoding.unicode_scalar_values_only,
  unicode_normalization: zonePathSpec.encoding.unicode_normalization,
  case_folding: zonePathSpec.encoding.case_folding,
  percent_decoding: zonePathSpec.encoding.percent_decoding,
  automatic_normalization: zonePathSpec.normalization.automatic,
})

function validatesZonePath(rules, value) {
  if (rules.unicode_scalar_values_only && !value.isWellFormed()) return false
  if (rules.empty === 'reject' && value.length === 0) return false
  if (rules.absolute && !value.startsWith(rules.separator)) return false
  if (value === rules.root) return true
  if (rules.trailing_separator === 'root-only' && value.endsWith(rules.separator)) {
    return false
  }
  if (
    rules.repeated_separators === 'reject' &&
    value.includes(rules.separator.repeat(2))
  ) {
    return false
  }
  if ([...value].some((character) => rules.forbidden_characters.includes(character))) {
    return false
  }
  return !value
    .split(rules.separator)
    .slice(1)
    .some((segment) => rules.forbidden_exact_segments.includes(segment))
}

function addOwnerAnnotations(validator) {
  validator.addKeyword({ keyword: 'x-sudo-owner', schemaType: 'object', valid: true })
  validator.addKeyword({ keyword: 'x-sudo-semantics', schemaType: 'object', valid: true })
  return validator
}

const unsupported = new Ajv2020({ strict: false })
assert.throws(
  () => unsupported.compile(zonePathSchema),
  /no schema with key or ref/,
  'an engine without the required ZonePath dialect must fail closed',
)

const missingVocabulary = addOwnerAnnotations(new Ajv2020({ strict: true }))
missingVocabulary.addMetaSchema(zonePathMetaSchema)
assert.throws(
  () => missingVocabulary.compile(zonePathSchema),
  /unknown keyword/,
  'an engine without the required ZonePath vocabulary must fail closed',
)

const ajv = addOwnerAnnotations(new Ajv2020({ strict: true }))
ajv.addKeyword({
  keyword: zonePathKeyword,
  schemaType: 'object',
  type: 'string',
  errors: false,
  validate: validatesZonePath,
})
ajv.addMetaSchema(zonePathMetaSchema)

const validateZonePath = ajv.compile(zonePathSchema)
if (!Array.isArray(zonePathFixtures.cases) || zonePathFixtures.cases.length === 0) {
  throw new Error('ZonePath fixture set is empty')
}
for (const fixture of zonePathFixtures.cases) {
  if (fixture.expected !== 'accept' && fixture.expected !== 'reject') {
    throw new Error(`${fixture.id}: unsupported expected outcome ${fixture.expected}`)
  }
  const expected = fixture.expected === 'accept'
  const actual = validateZonePath(fixture.path)
  if (actual !== expected) {
    throw new Error(
      `${fixture.id}: expected accepted=${expected}, schema said accepted=${actual}: ${ajv.errorsText(validateZonePath.errors)}`,
    )
  }
}
for (const value of [
  `/${String.fromCharCode(0xd800)}`,
  `/ok/${String.fromCharCode(0xdfff)}`,
]) {
  assert.equal(validateZonePath(value), false, 'schema accepted a lone UTF-16 surrogate')
}

const validateZoneIdLexical = ajv.compile(zoneIdSchema)
assert.equal(zoneIdVectors.provenance.contract_id, zoneIdSchema.$id)
assert.equal(zoneIdVectors.provenance.canonical_source, 'contracts/zone-id/spec.json')
if (!Array.isArray(zoneIdVectors.cases) || zoneIdVectors.cases.length === 0) {
  throw new Error('ZoneId vector set is empty')
}
for (const fixture of zoneIdVectors.cases) {
  const expected = fixture.expected === 'accept'
  if (fixture.expected !== 'accept' && fixture.expected !== 'reject') {
    throw new Error(`${fixture.id}: unsupported expected outcome ${fixture.expected}`)
  }
  const actual = validateZoneIdLexical(fixture.value)
  if (actual !== expected) {
    throw new Error(
      `${fixture.id}: expected lexical acceptance=${expected}, schema said accepted=${actual}: ${ajv.errorsText(validateZoneIdLexical.errors)}`,
    )
  }
}
assert.equal(validateZoneIdLexical('root'), true, 'lexical projection must allow root references')
assert.deepEqual(
  zoneIdSchema['x-sudo-semantics'].reserved_constants,
  zoneIdSpec.reserved.constants,
)
assert.equal(
  zoneIdSchema['x-sudo-semantics'].reserved_values_in_lexical_projection,
  false,
)

console.log(
  `Owner schemas agree with ${zonePathFixtures.cases.length} ZonePath fixtures and ${zoneIdVectors.cases.length} ZoneId lexical cases`,
)
