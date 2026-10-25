// Fail closed if a reused build-script output came from another worktree or
// schema. include_bytes! also gives rustc the actual current contract inputs.
const fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0;
    while i < left.len() {
        if left[i] != right[i] {
            return false;
        }
        i += 1;
    }
    true
}
macro_rules! bind_input {
    ($snapshot:literal, $source:literal, $label:literal) => {
        const _: () = assert!(
            same_bytes(
                include_bytes!(concat!(env!("OUT_DIR"), "/", $snapshot)),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../proto/",
                    $source
                ))
            ),
            concat!(
                "stale generated Raft ",
                $label,
                " contract; regenerate from this worktree"
            )
        );
    };
}
bind_input!(
    "raft-transport.source.proto",
    "nexus/raft/transport.proto",
    "transport"
);
bind_input!(
    "raft-commands.source.proto",
    "nexus/raft/commands.proto",
    "command"
);
bind_input!(
    "raft-metadata.source.proto",
    "nexus/core/metadata.proto",
    "metadata"
);
