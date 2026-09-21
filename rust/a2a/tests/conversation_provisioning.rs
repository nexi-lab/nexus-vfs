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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kernel::core::dispatch::FileEvent;
use kernel::kernel::syscall::{KernelSyscall, ReaddirOpts};
use kernel::kernel::{
    Kernel, KernelError, OperationContext, StatResult, SysCopyResult, SysReadResult,
    SysRenameResult, SysSetAttrResult, SysUnlinkResult, SysWriteResult,
};

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

/// A real kernel that counts the `sys_setattr` calls made through it.
///
/// Provisioning is idempotent at every step, so "the second call still returns
/// Ok" is true whether or not the early return exists — the only thing that
/// distinguishes them is how many syscalls the second call MAKES. Counting is
/// the direct observation; everything else is a proxy.
struct CountingKernel {
    inner: Kernel,
    setattrs: AtomicUsize,
}

impl CountingKernel {
    fn new() -> Self {
        Self {
            inner: Kernel::new(),
            setattrs: AtomicUsize::new(0),
        }
    }

    fn setattrs(&self) -> usize {
        self.setattrs.load(Ordering::Relaxed)
    }

    fn reset(&self) {
        self.setattrs.store(0, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
impl KernelSyscall for CountingKernel {
    fn sys_setattr(
        &self,
        path: &str,
        entry_type: i32,
        backend_name: &str,
        backend: Option<Arc<dyn kernel::abc::object_store::ObjectStore>>,
        metastore: Option<Arc<dyn kernel::meta_store::MetaStore>>,
        raft_backend: Option<Box<dyn std::any::Any + Send + Sync>>,
        io_profile: &str,
        zone_id: &str,
        is_external: bool,
        capacity: usize,
        read_fd: Option<i32>,
        write_fd: Option<i32>,
        mime_type: Option<&str>,
        modified_at_ms: Option<i64>,
        content_id: Option<&str>,
        size: Option<u64>,
        version: Option<u32>,
        created_at_ms: Option<i64>,
        link_target: Option<&str>,
        source: Option<&str>,
        remote_metastore: Option<Arc<dyn kernel::meta_store::MetaStore>>,
    ) -> Result<SysSetAttrResult, KernelError> {
        self.setattrs.fetch_add(1, Ordering::Relaxed);
        self.inner.sys_setattr(
            path,
            entry_type,
            backend_name,
            backend,
            metastore,
            raft_backend,
            io_profile,
            zone_id,
            is_external,
            capacity,
            read_fd,
            write_fd,
            mime_type,
            modified_at_ms,
            content_id,
            size,
            version,
            created_at_ms,
            link_target,
            source,
            remote_metastore,
        )
    }

    // Everything else forwards untouched — only the write-shaped call is counted.
    fn sys_read(
        &self,
        path: &str,
        ctx: &OperationContext,
        timeout_ms: u64,
        offset: u64,
    ) -> Result<SysReadResult, KernelError> {
        KernelSyscall::sys_read(&self.inner, path, ctx, timeout_ms, offset)
    }
    fn sys_write(
        &self,
        path: &str,
        ctx: &OperationContext,
        content: &[u8],
        offset: u64,
    ) -> Result<SysWriteResult, KernelError> {
        KernelSyscall::sys_write(&self.inner, path, ctx, content, offset)
    }
    fn sys_unlink(
        &self,
        path: &str,
        ctx: &OperationContext,
        recursive: bool,
    ) -> Result<SysUnlinkResult, KernelError> {
        KernelSyscall::sys_unlink(&self.inner, path, ctx, recursive)
    }
    fn sys_stat(&self, path: &str, zone_id: &str) -> Option<StatResult> {
        KernelSyscall::sys_stat(&self.inner, path, zone_id)
    }
    fn sys_rename(
        &self,
        old_path: &str,
        new_path: &str,
        ctx: &OperationContext,
    ) -> Result<SysRenameResult, KernelError> {
        KernelSyscall::sys_rename(&self.inner, old_path, new_path, ctx)
    }
    fn sys_copy(
        &self,
        src_path: &str,
        dst_path: &str,
        ctx: &OperationContext,
    ) -> Result<SysCopyResult, KernelError> {
        KernelSyscall::sys_copy(&self.inner, src_path, dst_path, ctx)
    }
    fn sys_lock(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u64,
        holder_info: &str,
    ) -> Result<Option<String>, KernelError> {
        KernelSyscall::sys_lock(
            &self.inner,
            path,
            lock_id,
            max_holders,
            ttl_secs,
            holder_info,
        )
    }
    fn sys_unlock(&self, path: &str, lock_id: &str, force: bool) -> Result<bool, KernelError> {
        KernelSyscall::sys_unlock(&self.inner, path, lock_id, force)
    }
    fn sys_readdir(
        &self,
        parent_path: &str,
        zone_id: &str,
        is_admin: bool,
        opts: ReaddirOpts,
    ) -> Vec<(String, u8)> {
        KernelSyscall::sys_readdir(&self.inner, parent_path, zone_id, is_admin, opts)
    }
    fn sys_watch(&self, pattern: &str, timeout_ms: u64) -> Option<FileEvent> {
        KernelSyscall::sys_watch(&self.inner, pattern, timeout_ms)
    }
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

    // Each side's entry is named after the OTHER participant — that is what
    // makes the directory listable into peers rather than into hashes.
    for (name, peer) in [("win-ai", "mac-ai"), ("mac-ai", "win-ai")] {
        let alias = agent_conversation_link_path(name, peer);
        assert_eq!(
            alias,
            format!("/agents/{name}/conversations/{peer}"),
            "the chat-list leaf must be the peer's name, not the cid"
        );
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
    // Provision from each side in turn; the peer's index must appear either way.
    for (caller, peer) in [("win-ai", "mac-ai"), ("mac-ai", "win-ai")] {
        let kernel = Kernel::new();
        ensure_conversation(&kernel, caller, peer).expect("provision conversation");
        // Each participant's entry is named after the OTHER one, so the pair is
        // walked in both directions rather than reusing a single name.
        for (owner, other) in [(caller, peer), (peer, caller)] {
            let alias = agent_conversation_link_path(owner, other);
            assert_eq!(
                stat(&kernel, &alias).entry_type,
                DT_LINK,
                "provisioning from {caller} must still index {owner}'s conversation with {other}"
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

/// An existing conversation must SHORT-CIRCUIT, not re-walk the tree.
///
/// A sender calls this on every send, and each step inside is individually
/// idempotent — so "it still returns Ok" holds with or without the early
/// return and proves nothing about it. What the early return actually changes
/// IS observable: once the transcript exists, the function stops looking at
/// anything else. Deleting a chat-list link and watching it stay deleted is
/// exactly that difference, and it is the only cheap way to assert the hot
/// path does not pay eleven `sys_setattr` round trips per message.
///
/// It also pins the trade-off honestly rather than leaving it in a comment.
/// The early return is sound against an INTERRUPTED create — the transcript is
/// written last, so its presence implies the directories and both links — but
/// it does NOT repair a structure damaged afterwards. Nothing deletes these
/// entries in practice; if something ever starts to, this test is where that
/// assumption is written down and will fail.
#[test]
fn an_existing_conversation_short_circuits_instead_of_rewalking() {
    let kernel = CountingKernel::new();

    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("first provision");
    let building = kernel.setattrs();
    assert!(
        building > 1,
        "the first call must actually build the structure, got {building} setattr(s)"
    );

    kernel.reset();
    ensure_conversation(&kernel, "win-ai", "mac-ai").expect("second provision");

    assert_eq!(
        kernel.setattrs(),
        0,
        "a conversation that already exists must cost ZERO setattr — one sys_stat \
         and out. A sender calls this on every send, so without the early return \
         each message re-walks the whole structure ({building} syscalls) to \
         re-establish what the first send already built."
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
