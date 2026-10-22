#!/usr/bin/env bash
# Exactly ONE founder per federation, shared by every local scode client.
# Required: start-common.sh inputs plus NEXUS_CLUSTER_INIT=<zone>.
# NEXUS_ACCEPT_ENROLLMENTS=true allows the Mac joiner to enroll over the overlay.
# Keep stdout private: the daemon may print an enrollment token at boot.
# The same declaration resumes existing state; it does not reset membership.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./start-common.sh
source "$script_dir/start-common.sh"

: "${NEXUS_CLUSTER_INIT:?Set the founded zone, e.g. sharedzone}"
[[ -z "${NEXUS_PEERS:-}" ]] || launcher_error 'A founder cannot also set NEXUS_PEERS; use start-joiner.sh to join another founder.'
[[ -z "${NEXUS_JOIN_TOKEN:-}" ]] || launcher_error 'A founder does not consume a join token.'
export NEXUS_CLUSTER_INIT
if [[ "${1:-}" == '--publish-node-record' ]]; then
    shift
    publish_node_record founder --zone "$NEXUS_CLUSTER_INIT" "$@"
    exit
fi
# A single zone automatically gets disjoint /agents, /conversations, /sessions
# subtrees from the daemon's subsystem declarations. Do not repeat that list here.
exec "$NEXUSD_BIN" "$@"
