# Shared node owner entrypoints

`start-founder.sh` and `start-joiner.sh` own the launch declaration for one
authenticated cluster node shared by local clients. Both source `start-common.sh`.
They do not compile binaries, install a service, create another mailbox watcher,
copy identities, or change an existing node's Raft membership.

Use an absolute, verified `NEXUSD_BIN`, `NEXUS_DATA_DIR`, and a separate
`NEXUS_IDENTITY_DIR`. Keep both persistent directories and the original `.node_id`
when restarting. Set `NEXUS_ADVERTISE_ADDR` to this node's reachable overlay
`host:port`. Optional arguments go directly to `nexusd-cluster`.

```bash
export NEXUSD_BIN=/absolute/path/to/nexusd-cluster
export NEXUS_DATA_DIR=/absolute/path/to/node/data
export NEXUS_IDENTITY_DIR=/absolute/path/to/node/identity
export NEXUS_ADVERTISE_ADDR=100.64.0.27:2126
export NEXUS_CLUSTER_INIT=sharedzone
bash scripts/cluster/start-founder.sh
```

Exactly one founder initializes a new shared zone. For a joining node, unset
`NEXUS_CLUSTER_INIT` / `NEXUS_CLUSTER_INIT_MOUNTS` and set `NEXUS_PEERS` to the
existing founder. On first enrollment supply `NEXUS_JOIN_TOKEN` privately; later
boots reuse the existing node certificate. Protect logs: initial boot can print
an enrollment token. Never commit tokens or copy a founder's identity or CA key.

The joiner entrypoint by itself requests the daemon's default voter enrollment.
An existing learner must first have a separately verified pre-join workflow;
restarting with this script must preserve its actual learner ConfState. The word
`joiner` in a client discovery record describes deployment topology, not a Raft
membership mutation.

## Explicit local discovery publication

Publication is a separate owner action after authenticated readiness and the
participating clients' natural old-mailbox drain. A client does not publish the
node record. This command validates first and leaves discovery unchanged:

```bash
export NEXUS_RECORD_PYTHON=/absolute/path/to/python3
bash scripts/cluster/start-founder.sh --publish-node-record \
  --agent nexus-win-codex \
  --client /absolute/path/to/mailbox_cli \
  --node-id-sha256 SHA256_OF_THIS_DATA_DIRECTORY_NODE_ID
```

Use `start-joiner.sh` for the existing joining host and additionally pass
`--zone sharedzone`. The founder takes `--zone` from `NEXUS_CLUSTER_INIT`.
Only append `--publish` after reviewing the validation receipt. This does not
start or restart a daemon. The node owner's already-signed bundle is loaded from
`$NEXUS_DATA_DIR/agents/<agent>/credential.json`; the script does not mint it.

An older `mailbox_cli` may not print a zone in its `stat` output. Use an existing
verified standard grpcurl instead of weakening readiness checks or rebuilding
the daemon:

```bash
bash scripts/cluster/start-joiner.sh --publish-node-record \
  --zone sharedzone --agent nexus-mac-codex \
  --grpcurl /absolute/path/to/grpcurl \
  --proto /absolute/path/to/exact-revision/vfs.proto \
  --node-id-sha256 SHA256_OF_THIS_DATA_DIRECTORY_NODE_ID
```

The public proto must match the running revision. grpcurl uses the existing
bundle's CA, certificate, key and `server_name` for mTLS. Each of `/agents`,
`/conversations`, and `/sessions` must pass Stat and Readdir; each Stat must
report the exact requested zone. They are distinct subtrees, not aliases of
one storage path. The dial endpoint defaults to `127.0.0.1:2126`. Use
`--endpoint 127.0.0.1:PORT` for a separately owned local Node; hostnames, remote
addresses, wildcard listeners, URLs and invalid ports are refused. TLS still
authenticates the bundle's server name rather than assuming an IP SAN. Changing
the port does not bypass the Node identity pin, authenticated mount probes, or
no-clobber publication. An existing record cannot be retargeted this way.

### Enrolled remote clients

A device may run SudoCode as an ordinary client of the same authority without
running another Node or becoming a Raft voter. Its operator must first issue a
distinct Agent credential through the existing native issuer and deliver only
that client's bundle. Do not copy another Agent's identity, a Node credential or
a private CA. This is not cross-domain federation.

For a verified loopback transport to that existing Node, invoke the publisher
directly with `--role client`, `--ca-cert-sha256` (the SHA256 of the exact public
CA PEM bytes supplied by the operator), and the client's local `--agents-dir`.
No local `.node_id` is created or fabricated. The existing mTLS probes still
authenticate the server and client and require accessible native subtrees before
writing discovery. This command does not establish or supervise the transport.

By default all three Stat responses must report `--zone`. If the existing
deployment reports different zones, the operator may explicitly pin a client
subtree with `--mount-zone /agents=EXPECTED_ZONE`. Unknown paths, duplicate
declarations and use with founder/joiner publication are refused. Every subtree
is still checked; there is no ignore-zone flag or automatic acceptance of an
observed value. The receipt retains all expected zones and actual responses.
These values describe the observed Stat contract, not a new authorization rule:
stored inode metadata may differ from current routing. Diagnose a discrepancy
separately; the publisher neither changes mounts nor repairs inode metadata.
Prove actual bidirectional A2A separately before claiming remote Agent acceptance.

Client publication retains the same private, atomic, no-clobber Node record
writer. The `client` role records placement only; it grants no Node authority and
must not be passed to a Node founder/joiner startup flow.

The record is `$HOME/.nexus/run/node.json` for the node-owning OS user, outside
both the legacy `~/.nexus-vfs` service root and sudocode configuration. Version 1
contains `endpoint`, `agents_dir`, `role`, and `zone`. The publisher checks the
local `.node_id` hash for a founder/joiner, or the operator-supplied public CA
file hash for a client, creates a private directory and file (0700/0600 on
POSIX; protected current-user-only DACL on Windows), and uses no-clobber atomic
publication. Repeating the same declaration is idempotent; a different record
is refused. It never retargets another owner's existing record.

The Python standard library is the only publisher dependency. Git Bash is
supported on Windows. `NEXUS_RECORD_PYTHON` selects an existing Python executable;
no Python package install is needed. Run the portable fixture with:

```bash
python scripts/cluster/test_node_record.py
```

Keep evidence and originals before removing disposable build worktrees. These
entrypoints are canonical repository source; project-specific shortcuts should
delegate here rather than maintain another implementation.
