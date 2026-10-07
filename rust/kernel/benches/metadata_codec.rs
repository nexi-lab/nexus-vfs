//! What the `FileMetadata` value encoding costs inside a redb metastore op.
//!
//! This began as "does the hand-rolled positional codec earn its keep?"
//! (nexi-lab/nexus-vfs#371). It did not: bincode over the serde derives
//! measured inside noise of it, so the codec is gone and its encoder with it.
//! What is left worth pinning is the standing claim in
//! `core::meta_store::serialize_metadata` — that the encoding is a few percent
//! of the ~5 µs redb read it sits inside, so nobody needs to hand-write one
//! again — plus the JSON arm that the original "too slow for hot path" comment
//! was right about.
//!
//! The legacy decoder is not measured here. It is still live code —
//! `LocalMetaStore::open` runs it once per record to migrate a store written
//! before the switch — but its cost is the arithmetic of the numbers below:
//! one legacy decode plus one bincode encode per record, so a 100k-record
//! store migrates in tens of milliseconds, once. Measuring it would mean
//! making a private function public, which is not worth it; the frozen record
//! it decodes lives in `core::meta_store`'s own tests.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use kernel::abc::meta_store::FileMetadata;

/// A replicated transcript row with every optional field populated — the worst
/// case for an encoding that frames `Option`s.
fn populated() -> FileMetadata {
    FileMetadata {
        path: "/agents/aurora-mbp/transcript".to_string(),
        size: 48_192,
        content_id: Some("blake3:9f2c4ae1".to_string()),
        gen: 37,
        version: 12,
        entry_type: 0,
        zone_id: Some("sharedzone".to_string()),
        mime_type: Some("application/jsonl".to_string()),
        created_at_ms: Some(1_759_000_000_000),
        modified_at_ms: Some(1_759_000_900_000),
        last_writer_address: Some("100.64.0.7:2126".to_string()),
        target_zone_id: Some("sharedzone".to_string()),
        target_subtree: Some("/agents".to_string()),
        link_target: Some("/elsewhere".to_string()),
        owner_id: Some("sk-agent-aurora".to_string()),
    }
}

/// A DT_MOUNT row — the other shape the store is full of.
fn mount_entry() -> FileMetadata {
    FileMetadata {
        path: "/agents".to_string(),
        entry_type: 2,
        zone_id: Some("sharedzone".to_string()),
        target_zone_id: Some("sharedzone".to_string()),
        target_subtree: Some("/agents".to_string()),
        ..Default::default()
    }
}

fn codecs(c: &mut Criterion) {
    for (label, meta) in [("populated", populated()), ("mount", mount_entry())] {
        let bin = bincode::serialize(&meta).expect("bincode encode");
        let json = serde_json::to_vec(&meta).expect("json encode");

        // The other half of the old codec's "compact" claim. Facts, not
        // timings, so print rather than measure.
        println!(
            "[{label}] encoded bytes: bincode={} json={}",
            bin.len(),
            json.len()
        );

        let mut group = c.benchmark_group(format!("encode/{label}"));
        group.bench_function("bincode", |b| {
            b.iter(|| black_box(bincode::serialize(black_box(&meta)).unwrap()))
        });
        group.bench_function("json", |b| {
            b.iter(|| black_box(serde_json::to_vec(black_box(&meta)).unwrap()))
        });
        group.finish();

        let mut group = c.benchmark_group(format!("decode/{label}"));
        group.bench_function("bincode", |b| {
            b.iter(|| black_box(bincode::deserialize::<FileMetadata>(black_box(&bin)).unwrap()))
        });
        group.bench_function("json", |b| {
            b.iter(|| black_box(serde_json::from_slice::<FileMetadata>(black_box(&json)).unwrap()))
        });
        group.finish();
    }
}

criterion_group!(benches, codecs);
criterion_main!(benches);
