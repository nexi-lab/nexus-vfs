//! Real-filesystem regression for an interrupted publication's final-path residue.
//! The partial file is an explicitly injected crash state, not a production trace.

use std::io;

use kernel::core::cas::transport::LocalCASTransport;

fn interrupted_final_object() -> (tempfile::TempDir, LocalCASTransport, Vec<u8>, String) {
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let complete = b"complete immutable object; the final bytes must all be present".to_vec();
    let hash = lib::hash::hash_content(&complete);
    let path = transport.blob_path(&hash);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Inject the on-disk result of termination after final-path creation and
    // before write_all completes. No mock replaces the actual transport or FS.
    std::fs::write(path, &complete[..9]).unwrap();
    (root, transport, complete, hash)
}

#[test]
fn a_partial_final_object_is_not_a_successful_deduplication_hit() {
    let (_root, transport, complete, hash) = interrupted_final_object();
    let result = transport.write_blob_tracked(&complete);
    assert!(
        result.is_err(),
        "partial final object must not be accepted as a dedup hit: {result:?}"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(transport.read_blob(&hash).unwrap(), &complete[..9]);
}

#[test]
fn prehashed_writes_also_refuse_a_partial_final_object() {
    let (_root, transport, complete, hash) = interrupted_final_object();
    let result = transport.write_blob_with_hash(&complete, &hash);
    assert!(
        result.is_err(),
        "prehashed write must not accept a partial final object: {result:?}"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(transport.read_blob(&hash).unwrap(), &complete[..9]);
}

#[test]
fn mismatched_prehashed_input_is_refused_before_creating_an_object() {
    let root = tempfile::tempdir().unwrap();
    let transport = LocalCASTransport::new(root.path(), true).unwrap();
    let claimed = lib::hash::hash_content(b"different bytes");
    let result = transport.write_blob_with_hash(b"actual bytes", &claimed);
    assert!(
        result.is_err(),
        "mismatched prehashed input must be refused: {result:?}"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(!transport.blob_path(&claimed).exists());
}
