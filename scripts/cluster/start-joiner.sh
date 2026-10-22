#!/usr/bin/env bash
# One node per joining host; scode clients never launch their own joiner daemon.
# Required: start-common.sh inputs plus NEXUS_PEERS=<founder-host:port>.
# On first boot set NEXUS_JOIN_TOKEN privately; later boots reuse the node cert.
# Fresh daemon discovery requests voter membership. This entry alone does not
# select learner membership. A learner needs a verified pre-join workflow that
# preserves the discovered mount subtrees and actual Raft ConfState.
# Never copy another node's private key or identity to initialize a joiner.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./start-common.sh
source "$script_dir/start-common.sh"

: "${NEXUS_PEERS:?Set a reachable host:port for the existing founder}"
[[ -z "${NEXUS_CLUSTER_INIT:-}${NEXUS_CLUSTER_INIT_MOUNTS:-}" ]] ||
    launcher_error 'A joiner never declares founder zones or mounts.'
export NEXUS_PEERS
if [[ "${1:-}" == '--publish-node-record' ]]; then
    shift
    publish_node_record joiner "$@"
    exit
fi
exec "$NEXUSD_BIN" "$@"
