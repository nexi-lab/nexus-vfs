//! Regression test for nexi-lab/nexus-vfs#350 — a kernel error reaches a client as a
//! sentence, never as Rust's internal vocabulary.
//!
//! `map_kernel_err` ended in `other => format!("{:?}", other)`, so a variant with a
//! hand-written arm arrived as a sentence and every other one arrived as
//! `IOError("Directory not empty: /ws/a")`: a variant name wrapped around a quoted,
//! escaped string, inside a protocol message. The same fact spelled two ways
//! depending on which arm happened to exist.
//!
//! The message now comes from `KernelError`'s `Display`, and the boundary decides only
//! the RPC code — so this file tests the wire text by testing `Display`, which is the
//! same string.
//!
//! What keeps a NEW variant from regressing this is not the list below: it is that
//! `Display`'s match has no catch-all arm, so a variant added without a sentence does
//! not compile. The list is here for the shape of each message, and to pin the one
//! wording a client parses.

use kernel::kernel::KernelError;

/// Every variant, so the assertions below speak for the whole type.
fn one_of_each() -> Vec<KernelError> {
    vec![
        KernelError::InvalidPath("/bad\0path".into()),
        KernelError::FileNotFound("/ws/missing".into()),
        KernelError::FileExists("/ws/there".into()),
        KernelError::IOError("Directory not empty: /ws/a".into()),
        KernelError::TrieError("no route for /x".into()),
        KernelError::PipeFull("/pipes/p".into()),
        KernelError::PipeEmpty("/pipes/p".into()),
        KernelError::PipeClosed("/pipes/p".into()),
        KernelError::PipeExists("/pipes/p".into()),
        KernelError::PipeNotFound("/pipes/p".into()),
        KernelError::StreamFull("/streams/s".into()),
        KernelError::StreamEmpty("/streams/s".into()),
        KernelError::StreamClosed("/streams/s".into()),
        KernelError::StreamExists("/streams/s".into()),
        KernelError::StreamNotFound("/streams/s".into()),
        KernelError::StreamTruncated(64, 12),
        KernelError::WouldBlock("/streams/s".into()),
        KernelError::PermissionDenied("zone b not in token".into()),
        KernelError::BackendError("s3: read-only bucket".into()),
        KernelError::Federation("no leader for zone b".into()),
    ]
}

#[test]
fn no_kernel_error_reaches_a_client_as_a_debug_dump() {
    for e in one_of_each() {
        let rendered = e.to_string();
        // `IOError("…")` — the exact shape #350 reported. A variant name followed by a
        // parenthesised quoted string is Debug, not a message.
        assert!(
            !rendered.contains("(\""),
            "a Debug wrapper reached the wire: {rendered:?}"
        );
        // Debug of a two-field tuple variant renders as `StreamTruncated(64, 12)`.
        assert!(
            !rendered.contains("StreamTruncated"),
            "a variant name reached the wire: {rendered:?}"
        );
        assert!(
            !rendered.trim().is_empty(),
            "a variant rendered to nothing, so the failure would arrive with no reason"
        );
    }
}

#[test]
fn the_payload_survives_because_that_is_what_a_caller_reads() {
    // The HTTP layer maps a non-recursive rmdir of a non-empty directory to 409 by
    // looking for this substring. It is the one message with a parser downstream, so
    // a prefix in front of it would be a silent behaviour change two repos away.
    let e = KernelError::IOError("Directory not empty: /ws/a".into());
    assert_eq!(e.to_string(), "Directory not empty: /ws/a");

    // Both numbers stay, and in the wording the wire already carried: a reader that
    // trimmed past resets to `earliest`.
    let t = KernelError::StreamTruncated(64, 12);
    assert_eq!(t.to_string(), "offset 12 trimmed; earliest 64");
}

#[test]
fn a_kernel_error_is_a_std_error() {
    // It could not be boxed as `dyn Error` or lifted with `?` into an `anyhow` chain
    // before, which is part of why call sites hand-formatted it.
    fn boxed(e: KernelError) -> Box<dyn std::error::Error> {
        Box::new(e)
    }
    assert_eq!(
        boxed(KernelError::FileNotFound("/ws/x".into())).to_string(),
        "file not found: /ws/x"
    );
}
