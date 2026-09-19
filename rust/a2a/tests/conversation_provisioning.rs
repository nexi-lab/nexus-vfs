//! `ensure_conversation` must build the real inodes, not merely plausible paths.
//!
//! The unit tests beside the policy are pure string work: they prove the paths
//! COMPOSE, and by construction cannot see what `sys_setattr` actually created.
//! That gap is not hypothetical — this provisioner was first written with
//! `DT_LINK = 3`, which is DT_PIPE's discriminant. It compiled, every path test
//! stayed green, and the chat-list index would have been a pipe: the syscall
//! dispatches on the integer, so there is no compile error and no runtime error
//! to notice. The ENTRY TYPES are therefore the assertion here, not the paths.

use a2a::{
    agent_conversation_link_path, conversation_id, conversation_reader_path,
    conversation_transcript_path, ensure_conversation, is_a2a_mailbox_path, CONVERSATIONS_BASE,
};
use kernel::kernel::{Kernel, StatResult};

/// Entry-type discriminants, mirroring `kernel::abc::meta_store`.
///
/// Spelled out here rather than imported so the test states the expected wire
/// value independently of the constant the code under test uses — importing the
/// same const would make a wrong value agree with itself.
const DT_DIR: u8 = 1;
const DT_STREAM: u8 = 4;
const DT_LINK: u8 = 6;

fn stat(kernel: &Kernel, path: &str) -> StatResult {
    kernel
        .sys_stat(path, contracts::ROOT_ZONE_ID)
        .unwrap_or_else(|| panic!("{path} must exist after ensure_conversation"))
}

/// The chat-list entry must be a DT_LINK pointing at the shared conversation.
///
/// This is the assertion that would have caught `DT_LINK = 3`: a DT_PIPE at
/// this path satisfies "the path exists" and every path-composition test, but
/// carries no `link_target` and is not a pointer to anything.
#[test]
fn chat_list_entry_is_a_link_to_the_shared_conversation() {
    let kernel = Kernel::new();
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("provision conversation");

    let cid = conversation_id("win-ai", "mac-ai");
    let expected_target = format!("{CONVERSATIONS_BASE}/{cid}");

    for name in ["win-ai", "mac-ai"] {
        let alias = agent_conversation_link_path(name, &cid);
        let meta = stat(&kernel, &alias);
        assert_eq!(
            meta.entry_type, DT_LINK,
            "{alias} must be a DT_LINK (got entry_type={}), not a pipe or a plain entry",
            meta.entry_type
        );
        assert_eq!(
            meta.link_target.as_deref(),
            Some(expected_target.as_str()),
            "{alias} must point at the shared conversation"
        );
    }
}

/// Both participants are indexed — a conversation is not owned by whoever
/// provisioned it, so indexing only the caller would leave the peer unable to
/// find it by listing its own chat list.
#[test]
fn both_participants_are_indexed_whichever_side_provisions() {
    let cid = conversation_id("win-ai", "mac-ai");

    // Provision from each side in turn; the peer's index must appear either way.
    for (caller, peer) in [("win-ai", "mac-ai"), ("mac-ai", "win-ai")] {
        let kernel = Kernel::new();
        ensure_conversation(&kernel, caller, peer).expect("provision conversation");
        for name in [caller, peer] {
            let alias = agent_conversation_link_path(name, &cid);
            assert_eq!(
                stat(&kernel, &alias).entry_type,
                DT_LINK,
                "provisioning from {caller} must still index {name}"
            );
        }
    }
}

/// The transcript is a DT_STREAM, and the gate recognises it as an A2A mailbox.
///
/// The second half is the integration invariant: what we PROVISION must be what
/// the fail-closed predicate ADMITS, or the `from`-guarantee silently skips the
/// very logs this creates.
#[test]
fn transcript_is_a_stream_the_gate_recognises() {
    let kernel = Kernel::new();
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("provision conversation");

    let cid = conversation_id("win-ai", "mac-ai");
    let transcript = conversation_transcript_path(&cid);

    assert_eq!(
        stat(&kernel, &transcript).entry_type,
        DT_STREAM,
        "{transcript} must be a DT_STREAM — an append-only log, not a plain file"
    );
    assert!(
        is_a2a_mailbox_path(&transcript),
        "the path we provision must be admitted by the fail-closed gate: {transcript}"
    );
}

/// Every parent directory is materialised, so the chat list can be listed.
///
/// `setattr_create_link` validates its target and puts the row; it does NOT
/// create parents. Without the explicit dirent layer the DT_LINK lands under a
/// directory nothing can `readdir` — and being listable is the entire point of
/// the index, so a missing parent is a silent loss of the feature rather than
/// an error.
#[test]
fn the_directory_layer_is_materialised() {
    let kernel = Kernel::new();
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("provision conversation");

    let cid = conversation_id("win-ai", "mac-ai");
    for dir in [
        CONVERSATIONS_BASE.to_string(),
        format!("{CONVERSATIONS_BASE}/{cid}"),
        "/agents".to_string(),
        "/agents/win-ai".to_string(),
        "/agents/win-ai/conversations".to_string(),
        "/agents/mac-ai/conversations".to_string(),
    ] {
        assert_eq!(
            stat(&kernel, &dir).entry_type,
            DT_DIR,
            "{dir} must be a directory so its children are listable"
        );
    }
}

/// Provisioning twice is a no-op, and the two participants derive the SAME
/// conversation from opposite argument orders.
///
/// Both halves matter for a send that races: each side calls this with itself
/// first, so an order-sensitive id would create two conversations and each peer
/// would write into a log the other never reads.
#[test]
fn provisioning_is_idempotent_and_order_free() {
    let kernel = Kernel::new();
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("first provision");
    ensure_conversation(&kernel, "mac-ai", "win-ai").expect("reversed order must be a no-op");
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("repeat must be a no-op");

    let cid = conversation_id("win-ai", "mac-ai");
    assert_eq!(
        cid,
        conversation_id("mac-ai", "win-ai"),
        "the pair is unordered — both sides must land on one conversation"
    );
    assert_eq!(
        stat(&kernel, &conversation_transcript_path(&cid)).entry_type,
        DT_STREAM,
        "the transcript must survive re-provisioning unchanged"
    );
}

/// The reader register is NOT created here — its absence is what means
/// "start at offset 0" for a brand-new participant.
///
/// Pinned because the opposite is the tempting mistake: seeding an empty
/// register looks tidier, but a register carries the holder and lease of
/// whoever is actually consuming, and only that process can fill those in. A
/// pre-seeded empty one is indistinguishable from a live consumer that has read
/// nothing, which is exactly the ambiguity the register exists to remove.
#[test]
fn the_reader_register_is_left_to_the_consumer() {
    let kernel = Kernel::new();
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("provision conversation");

    let cid = conversation_id("win-ai", "mac-ai");
    let reader = conversation_reader_path(&cid, "win-ai");
    assert!(
        kernel.sys_stat(&reader, contracts::ROOT_ZONE_ID).is_none(),
        "{reader} must not be pre-created — absence is what reads as offset 0"
    );
}
