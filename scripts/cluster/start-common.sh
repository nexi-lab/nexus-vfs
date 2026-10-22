#!/usr/bin/env bash
# Shared Windows (Git Bash) / macOS cluster launcher configuration.
# Source this from start-founder.sh or start-joiner.sh.
# Set NEXUSD_BIN, NEXUS_ADVERTISE_ADDR, NEXUS_DATA_DIR, NEXUS_IDENTITY_DIR.
# The node owns TLS, bootstrap/resume, and the replicated mount defaults.
# Optional plugins/mount-driver arguments can be passed to either role script.
# This launcher never builds, migrates task files, or installs an OS service.

set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

launcher_error() { printf '[nexus-launcher] %s\n' "$*" >&2; exit 1; }

: "${NEXUSD_BIN:?Set NEXUSD_BIN to the verified nexusd-cluster binary}"
: "${NEXUS_ADVERTISE_ADDR:?Set a reachable host:port for this node}"
: "${NEXUS_DATA_DIR:?Set a persistent data directory for this node}"
: "${NEXUS_IDENTITY_DIR:?Set its separate persistent identity directory}"
[[ -x "$NEXUSD_BIN" ]] || launcher_error "Binary is not executable: $NEXUSD_BIN"

data_path=${NEXUS_DATA_DIR%/}
identity_path=${NEXUS_IDENTITY_DIR%/}
[[ "$identity_path" != "$data_path" && "$identity_path" != "$data_path/"* ]] ||
    launcher_error 'Identity must live outside data; do not wipe either to change roles.'

if [[ -n "${NEXUS_FEDERATION_ZONES:-}${NEXUS_FEDERATION_MOUNTS:-}" ]]; then
    launcher_error 'Retired NEXUS_FEDERATION_* inputs are set; use NEXUS_CLUSTER_INIT for the founder and NEXUS_PEERS for joiners.'
fi
for unsafe_flag in NEXUS_NO_TLS NEXUS_INSECURE_NO_AUTH; do
    case "${!unsafe_flag:-false}" in
        1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]) launcher_error "Unset $unsafe_flag for the shared authenticated federation." ;;
    esac
done

# Inputs below are the daemon's published CLI/env contract, not a second parser.
export NEXUS_ADVERTISE_ADDR NEXUS_DATA_DIR NEXUS_IDENTITY_DIR

# Explicit owner activation after authenticated readiness + old-mailbox drain.
# This is the same entry for both roles; clients never publish their own record.
publish_node_record() {
    local role="$1"
    shift
    local publisher="$script_dir/publish-node-record.py"
    if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* ]]; then
        publisher="$(cygpath -m "$publisher")"
    fi
    "${NEXUS_RECORD_PYTHON:-python3}" "$publisher" \
        --role "$role" --agents-dir "$NEXUS_DATA_DIR/agents" "$@"
}
