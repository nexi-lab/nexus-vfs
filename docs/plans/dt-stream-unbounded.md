# Plan: Complete DT_STREAM as an unbounded log (Kafka tiered-storage)

**Issue:** nexi-lab/nexus-vfs #229. **Owner:** me (kernel-tier, nexus-vfs). **Repo to edit:** nexus-vfs (kernel-tier lives here). **Branch:** cut fresh off `origin/main` (nexus-vfs integration branch = `main`, NOT develop). A scratch research branch `research/dt-stream-unbounded` may exist off an older main — rebase/recut off latest `origin/main`.
**Status:** DESIGNED + audited (2026-08-19). NOT built. Non-blocking (sudocode does manual hybrid short-term). P1 next.

> This file is the durable brain-dump — context was cleared after writing it. Re-read fully before touching code. All file:line refs are nexus-vfs @ main ~`2a62e6a56` (re-grep, lines drift).

---

## 1. Problem (confirmed in code, 3 research agents cross-verified)

DT_STREAM claims Kafka/Redis-Streams/NATS log semantics but only implements the HOT half. Two bounded-volatile backends (`MemoryStreamBackend`, `SharedMemoryStreamBackend` — `Full`/`Oversized` at fixed capacity) + one durable backend `WalStreamCore` that is **UNBOUNDED-IN-RAFT**:
- Every append = `Command::AppendStreamEntry` → `node.propose` (SC raft) → inserted into replicated redb tree `sm_stream_entries`, **insert-only, zero retention/delete anywhere**.
- The WHOLE `sm_stream_entries` tree is serialized verbatim into every SM snapshot; replayed in full to every joining SC node. → unbounded raft log + unbounded SM + unbounded join transfer.
- SC log `RaftStorage::compact` / `store_snapshot` are **implemented but DORMANT** (only test callers).

Consumers that NEED unbounded-durable: **audit** (wal, cap 0) and **A2A mailbox / chat-with-me** (wal when federated; else falls to bounded 64 KiB volatile — the gap). memory/shm consumers (LLM SSE, event bus, cross-proc wakeup) are correctly bounded — DO NOT touch them. No session-transcript consumer exists yet (nexus-2's #84, blocked on this).

## 2. Design — tiered storage mapped to nexus two-pillar + WAL-seq

WAL offset = `seq` (monotonic message #, assigned by the SM at raft-commit) = **exactly Kafka's offset**. Complete ONLY the WAL backend into an unbounded log; ABI unchanged.

1. **Hot tail**: recent seq window stays in `sm_stream_entries` (SC, strongly-consistent, local read, drives wakeup) = Kafka active segment.
2. **Seal + spill** (background, off the append hot path): when hot tail exceeds a size/count threshold, seal a contiguous seq range `[base,end)` into an immutable segment blob → write to CAS (`CASEngine.write_content(bytes) → content_id`, **content-addressed** BLAKE3, dedup+integrity free) → record a **segment index** entry in the metastore `{stream}/segments/{base} → {end, content_id, size}` → **delete the sealed rows from `sm_stream_entries`** (bounds SM state). = Kafka roll + upload-to-tiered + delete-local.
3. **Transparent hot/cold read** (ABI unchanged): inside `WalStreamCore::read_at(seq)`: `seq ≥ earliest_hot` → read `sm_stream_entries` (as today); else binary-search the segment index for the segment covering `seq` → fetch CAS blob (local `read_content` / remote `PeerBlobClient::fetch`+ReadBlob or `StreamReadAt`) → extract the frame at `seq`, return `{data, next_offset=seq+1}`. `sys_stat.size` = global end seq (unchanged).
4. **Per-stream retention** (attribute): **keep-forever** (audit/transcript — cold segments never deleted, seq≥0 always resolves) vs **trim** (mailbox — MaxBytes/MaxAge deletes cold segments + advances `earliest_seq`; read below it → new `StreamError::Truncated(earliest, req)` = Kafka OffsetOutOfRange).

### Decision: NO manifest-as-object (settled by principles 2 + 3, not preconception)
Segment index is METADATA, structurally identical to the existing "CAS index: content_id→location" / DT_REG's `content_id`. Putting it in the ObjectStore as a manifest object = boundary leak (metadata into the content pillar) + a 2nd SSOT for stream metadata. Metastore is already the SSOT for stream metadata (inodes, CAS index, hot entries) → the segment index is a metastore side-table beside them. Boundedness worry dissolved: large segments → slow index growth; trim drops index entries with segments; index is small metadata = exactly what raft snapshots hold bounded.

### SC/EC: does NOT affect us
`append_stream_entry` is **SC by design** (`zone_meta_store.rs:409-413`): an ordered log needs a single serialization point (SM assigns offset at apply). EC plane = LWW metadata registers (`set_metadata`), **never streams**. Our `SealStreamSegment` command is also SC (must be totally ordered wrt appends). All stream ops stay SC. Bonus: EC plane already has a WORKING `compact` + `SnapshotEcState` catch-up (`transport_loop.rs:842-852`, `ec_compact_floor`) — a proven precedent for P2's SC snapshot+compact.

## 3. Phasing

- **P1 (unblocks audit + transcript):** seal+spill + segment index + transparent cold read + keep-forever retention. Seal = deterministic SC raft command `SealStreamSegment{stream, base, end, content_id}` (writes index, deletes hot rows) → raft-safe, converges. Bounds SM state + snapshot CONTENT. (Raft LOG still replays historical append+seal = insert-then-delete, deterministic — wasteful but correct.)
- **P2 (bounds raft LOG + join):** wire the DORMANT `store_snapshot`+`compact` — snapshot carries bounded SM (hot tail + index), compact advances `first_index`, joiner installs snapshot + pulls cold from CAS. MUST satisfy raft-rs semantics 100% (snapshot at applied index; compact ≤ snapshot index; wiped-follower inbound-quiescence already handled per federation §6). HIGHEST RISK — adversarial tests.
- **P3 (independent, non-blocking):** trim retention + `Truncated`/OffsetOutOfRange read contract (new `StreamError` variant + KernelError variant + gRPC wire code — today InvalidOffset→IOError→gRPC InternalError, no distinct code); open search to streams (`service.rs:302` `if entry_type != DT_REG { continue }` in the sibling nexus repo search-plugin — cold segments as searchable DT_REG objects).

## 4. Key code pointers (re-grep; lines drift)

**Stream core / backends (nexus-vfs):**
- Trait `StreamBackend` + `StreamError{Closed,Full,Empty,ClosedEmpty,Oversized,InvalidOffset}`: `rust/kernel/src/core/stream/backend.rs:7-30`.
- `MemoryStreamBackend` (bounded, DO NOT change): `rust/kernel/src/core/stream/mod.rs:101-252`; Full/Oversized `:143-157`.
- `WalStreamCore` (THE target): `rust/kernel/src/core/stream/wal.rs` — `new` :69, key `/__wal_stream__/{path}/{seq}` :79-81, `WAL_STREAM_KEY_PREFIX` :39, push (fail-loud, waits SC commit) :165-181, read_at→get_stream_entry :103-119, tail=store count :148-150, `watch_path_from_wal_stream_key` :49-54.
- Backend selection (io_profile waterfall): `rust/kernel/src/kernel/mod.rs` — `install_stream_backend` :2051-2101 (`shared_memory`/`wal`/`memory`), `install_wal_stream` :1971-1981, `wal_backend_for` :2009-2019, `routed_zone_id` :2001-2007, `setattr_stream` :1883-1935. All-`wal` w/o federation → hard error :2097-2100.
- `StreamManager`: `rust/kernel/src/core/stream/manager.rs` — resolve chokepoint :111-117, materialize_miss :123-130, materializer seam :26 / set_materializer :94, read_at_blocking (condvar park) :253-314, wake_waiters :223-231. `arm_stream_materializer`: `rust/kernel/src/kernel/mod.rs:2039-2049`.
- RemoteStreamBackend `stream/remote.rs` = DEAD CODE (never constructed). StdioStreamCore = no StreamBackend impl, no prod caller.

**Raft state machine / snapshot (nexus-vfs `rust/raft`):**
- Append SC: `zone_meta_store.rs:402-441` (`Command::AppendStreamEntry` → `node.propose`), SC-by-design comment :409-413. MetaStore trait: `rust/kernel/src/abc/meta_store.rs` append_stream_entry :403 / get_stream_entry :415 / stream_tail :430.
- Apply (SOLE writer, insert-only): `rust/raft/src/raft/state_machine.rs:1497-1528`; tail sidecar `__stream_tail__{prefix}` :599-601; tree `TREE_STREAM_ENTRIES="sm_stream_entries"` :590, field :715. **Offset assigned here at apply in committed order.**
- Snapshot: create `state_machine.rs:1905-1954` (serializes whole tree :1920-1926); `Snapshot` struct :1323-1339 (`stream_entries` field :1328-1329); restore :1956-2044 (:1998-2008). Raft wiring: receiver `raft/node.rs:1790-1810` (restore :1805-1808); `raft/storage.rs` store_snapshot :193 / apply_snapshot :272 / snapshot() :475 / **compact :348-366 (DORMANT)**; restart rehydrate `zone_registry.rs:665-680`. Dormant proof: compact/store_snapshot only test callers (`storage.rs:588`/`:856`).
- EC precedent for P2: `replication_log.rs:339` compact; `transport_loop.rs:842-852` drain + `ec_compact_floor` :1021, retention `NEXUS_EC_WAL_RETENTION` :148-156; `SnapshotEcState` catch-up test `rust/raft/tests/test_ec_snapshot_catchup.rs`. Streams excluded from EC: `state_machine.rs:1713-1725`.

**CAS / ObjectStore reuse (nexus-vfs) — the cold segment store:**
- `LocalCASTransport` (cleanest opaque blob-by-id, NO forced CDC): `rust/kernel/src/core/cas/transport.rs:35` — write_blob :107 / write_blob_with_hash(bytes,id) :150 / read_blob :95 / exists :179 / blob_size :193 / remove_blob :250. Local layout 2-level fanout :20/:64 (plain files, not redb).
- `CASEngine` (+BLAKE3 +CDC +remote): `rust/kernel/src/core/cas/engine.rs:74` — write_content :170 / write_content_tracked :178 / read_content :132 / read_content_with_origins(id,origins) :142 / content_exists :199.
- `ObjectStore` pillar trait: `rust/kernel/src/abc/object_store.rs:80` — write_content :135 / read_content :152. Pluggable HAL: `rust/kernel/src/hal/object_store_provider.rs:92` + `DefaultObjectStoreProvider` `rust/backends/src/provider.rs:56` (cas-local/s3/gcs/remote/path_local). content_id = BLAKE3 64-hex. CDC optional >16 MiB (`rust/kernel/src/core/cas/chunking.rs:29-35`); `write_blob` bypasses CDC.
- **CONSTRAINT: CAS read hard-verifies id==BLAKE3(bytes)** (`chunking.rs:133-141`) → **cold segments MUST be content-addressed** (segment-id = BLAKE3(segment bytes)); then the whole CAS + remote-fetch stack reuses AS-IS. (Non-content ids would need a new `BlobFetcher` resolver branch — avoid.)
- Remote fetch: `ReadBlob` RPC `proto/nexus/raft/transport.proto:116`; server `raft/transport/server.rs:1517` → `KernelBlobFetcher::read` `raft/blob_fetcher_handler.rs:90`; client `PeerBlobClient::fetch(addr,content_id)` `rust/transport/src/peer_blob.rs:188`. DT_STREAM own `StreamReadAt(path,offset)→(data,next_offset,eof)`: `rust/kernel/src/core/stream/remote.rs:9` + gRPC `rust/transport/src/grpc.rs:1219-1290`.

**Error surfacing (P3 relevance):** `stream_mgr_err` `rust/kernel/src/kernel/mod.rs:2732-2751` (Full→StreamFull, Oversized→StreamFull, **InvalidOffset→IOError, no dedicated variant**); gRPC `map_kernel_err` `rust/transport/src/grpc.rs:202-223` (all stream errors → InternalError, no distinct wire code). P3 adds a clean `Truncated` path.
**Read/offset contract:** sys_read DT_STREAM arm `rust/kernel/src/kernel/syscall_impl.rs:357-383`; `SysReadResult.stream_next_offset` `mod.rs:177-179`; stream_read_batch `ipc.rs:206-215`; sys_stat.size stream tail `syscall_impl.rs:1325-1328`.

**Consumers (audit + mailbox live in the SIBLING nexus repo `C:/Users/songym/cursor-projects/nexus-para-pc-3/rust/services/`, NOT nexus-vfs):**
- Audit: `rust/services/src/audit/mod.rs:396-418` (`"wal"`, capacity 0).
- A2A mailbox: `managed_agent/proc_entry.rs:40,90` (`create_dt_stream(cwm,"wal,memory",CHAT_STREAM_CAPACITY=65536)`); `/proc/{pid}/chat-with-me` wal-over-root `rust/contracts/src/constants.rs:28-48`. Wakeup: `rust/raft/src/stream_wakeup.rs:95-112`.

## 5. 10-principle audit verdict (all pass; manifest-decision drove it)
1a simplest ✓ (reuse CAS+index+dormant-snapshot, zero new subsystems). 1b no ABI change ✓ (sys_* + io_profile unchanged; retention = optional attr). 1c/2b right files ✓ (all kernel-tier nexus-vfs). 1d SRP/orthogonal ✓ (cold tier extends WalStreamCore; trait unchanged). 2a no boundary leak ✓ (data→ObjectStore, index/hot→Metastore). 3 SSOT ✓ (stream meta only in metastore; bytes only in CAS content-addressed). 4 DRY ✓ (reuse CAS/index/ReadBlob/StreamReadAt/dormant snapshot+compact). 5 durable-only ✓. 6 perf ✓ (hot O(1) local unchanged; seal background; cold read rare/historical). 7 raft 100% ⚠️✓ (seal=deterministic converging cmd; P2 strict raft-rs; SC-only confirmed) — HIGHEST RISK, adversarial tests. 8 systematic ✓ (completes the primitive its doc already claims). 9 e2e depth ✓ (see §6). 10 no tombstones ✓.

## 6. Test plan (e2e depth — real cluster binary)
- P1: write past old MemoryStream capacity on a wal stream → assert seal fires → cold read at seq 0 returns correct frame → `sm_stream_entries` bounded (row count stays ≤ hot window across a large log) → `sys_stat.size` = global tail. Dedup: identical segments share one CAS blob. Integrity: corrupt a CAS blob → read fails loud.
- Cross-node: founder writes a long wal stream past several seals → joiner cold-reads seq 0 (pulls cold segment via ReadBlob from origin/CAS). Reuse the `a2a_wakeup.rs` federation harness (`boot_federation`, gate on `Static topology applied`).
- P2: large log → take snapshot + compact → assert snapshot size bounded (hot tail + index only, NOT all data) → fresh joiner installs snapshot and serves a cold read without replaying the full log. Adversarial: seal racing a concurrent append (sequencer) and a concurrent cold+hot read at the seam — no gap, no dup, no offset skew.

## 7. Workflow reminders (my standing bars)
- Build env Windows: export LIB/INCLUDE/PATH for VS Build Tools (else LNK1181); PROTOC shim. Commit with `-c core.hooksPath=/dev/null` (para-pc legacy hook exit-49).
- ONE PR, granular commits (single effort). English only, no Co-Authored-By, no squash (`gh pr merge --merge --admin`). Preserve history.
- Merge only when ALL CI green; nexus-vfs CI = `cargo test`/`cargo clippy`/`cargo fmt`/cluster-binary builds. NO flaky — root-cause, don't re-run.
- E2E-first acceptance; put the e2e in CI to guard regression.
- Delete replaced code cleanly, no "rust replacement for the retired" tombstones.
- Monitor the PR to green merge (7-point checklist). This UNBLOCKS nexus-2's #84 transcript — ping them when P1 lands.
- Coordinate: DT_STREAM primitive is MINE; transcript consumer is nexus-2's #84. Don't build the consumer. `/sessions/<id>/transcript.jsonl` = one logical DT_STREAM; segmentation is a kernel detail (resolves the single-file-vs-rotation open question).

## 8. Immediate next steps (P1)
1. Re-grep all §4 pointers on latest `origin/main` (lines drift). Cut branch `feat/dt-stream-unbounded-p1` off `origin/main`.
2. Add `SealStreamSegment` command + apply (write segment-index side-table `sm_stream_segments` or `{__wal_stream__/<id>/segments/<base>}`, delete sealed `sm_stream_entries` rows) in `state_machine.rs`; thread through `zone_meta_store.rs` + MetaStore trait.
3. Segment write to CAS (`CASEngine.write_content`) + `WalStreamCore` seal trigger (size/count threshold, background) + `earliest_hot` tracking.
4. `WalStreamCore::read_at` cold branch: index binary-search → CAS read (local + remote via existing fetch) → frame extract. keep-forever default.
5. E2E per §6 (P1 + cross-node). All green → PR → merge → notify nexus-2.
