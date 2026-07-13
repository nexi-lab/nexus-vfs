#!/usr/bin/env python3
"""The shape moss runs, exercised in a container.

moss spawns nexusd as a child process inside its own server container, on the
container's loopback, and stores every enterprise tenant's secrets in it at
`/secrets/{namespace}/{key}.json` — where the namespace is `org:{orgId}:system`.
The colon matters, and it is why this test cannot live on a Windows host: the
VFS maps a path onto a host filename, and Windows rejects `:` outright. Every
probe of that layout so far had to substitute a colon-free namespace, which
means **moss's real path shape has never actually been tested**. It is here.

Four things, each of which moss depends on and none of which a host-side test
could establish:

  1. moss's INVOCATION still boots on the current binary. moss passes
     `--bootstrap-mode static`, a flag Phase G deleted; the flag has to go, and
     when it does, the rest of moss's arguments must still work. This is the
     migration, run before moss runs it.

  2. moss's REAL PATH SHAPE round-trips — colons and all — and `Readdir` lists
     it, at both the namespace and the key level. This is the evidence behind
     telling moss its SQLite index (~/.moss/nexus/secrets_index.db) is a
     redundant second SSOT. A recommendation to delete code should not rest on
     a test that had to change the input to pass.

  3. moss's ZERO-CHANGE PROMISE holds: a plaintext, tokenless daemon on the
     container's loopback still boots, with no flags. The loopback invariant
     must not break the deployment it was written to protect.

  4. The invariant BITES where it matters. Inside a container, `0.0.0.0` is
     what makes a socket reachable from the container network — the exact
     mistake ("add nexus to moss-network") that turns an unauthenticated store
     into a cross-tenant breach. On a host that distinction is academic; here
     it is the whole point.

Exit 0 on success. Anything else is a finding.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import grpc

REPO_PROTO = Path("/work/proto")

# moss's real namespace. `secretSubject.ts::orgNamespacePrefix` → `org:{orgId}:`
NAMESPACE = "org:acme:system"
SECRETS = {"openai": '{"key":"sk-fake"}', "anthropic": '{"key":"x"}', "slack": '{"key":"y"}'}

# moss's arguments, minus the one flag it must drop (`--bootstrap-mode static`,
# deleted in Phase G). Everything else is verbatim from nexusManager.ts:84-88.
MOSS_ARGS = ["--bind-addr", "127.0.0.1:2126", "--no-tls"]


def load_stubs():
    out = Path(tempfile.mkdtemp(prefix="stubs-"))
    subprocess.run(
        [
            sys.executable, "-m", "grpc_tools.protoc",
            f"-I{REPO_PROTO}",
            f"--python_out={out}", f"--grpc_python_out={out}",
            str(REPO_PROTO / "nexus" / "grpc" / "vfs" / "vfs.proto"),
        ],
        check=True, capture_output=True,
    )
    sys.path.insert(0, str(out))
    for pkg in ("nexus", "nexus/grpc", "nexus/grpc/vfs"):
        (out / pkg / "__init__.py").touch()
    from nexus.grpc.vfs import vfs_pb2, vfs_pb2_grpc
    return vfs_pb2, vfs_pb2_grpc


pb, pbg = load_stubs()


def boot(args: list[str], env_extra: dict[str, str] | None = None, wait_port: int | None = None):
    """Start nexusd. Returns (proc, came_up, output)."""
    data = Path(tempfile.mkdtemp(prefix="nexus-data-"))
    env = dict(os.environ)
    env.update(NEXUS_DATA_DIR=str(data / "d"), NEXUS_IDENTITY_DIR=str(data / "i"), RUST_LOG="warn")
    env.pop("NEXUS_API_KEY_SECRET", None)
    env.pop("NEXUS_INSECURE_NO_AUTH", None)
    env.update(env_extra or {})

    proc = subprocess.Popen(
        ["nexusd-cluster", *args], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    port = wait_port or int(args[args.index("--bind-addr") + 1].rsplit(":", 1)[1])
    deadline = time.time() + 90
    while time.time() < deadline:
        if proc.poll() is not None:
            return proc, False, (proc.stdout.read() if proc.stdout else "")
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return proc, True, ""
        time.sleep(0.5)
    return proc, False, "timed out without serving and without exiting"


def kill(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=25)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=25)


def stub(port: int):
    ch = grpc.insecure_channel(f"127.0.0.1:{port}")
    return pbg.NexusVFSServiceStub(ch)


def main() -> int:
    failures: list[str] = []

    # ── 1 + 2 + 3: moss's invocation, moss's paths, moss's zero-change promise
    print("1. boot with moss's arguments (minus the deleted --bootstrap-mode)")
    print(f"   nexusd-cluster {' '.join(MOSS_ARGS)}")
    proc, up, out = boot(MOSS_ARGS)
    if not up:
        print("   [FAIL] moss's invocation does not boot on this binary")
        print(out)
        kill(proc)
        return 1
    print("   [ok] boots — and with no auth flags, which is moss's zero-change promise")

    try:
        s = stub(2126)

        print(f"2. write moss's real path shape — /secrets/{NAMESPACE}/*.json (note the colons)")
        for key, body in SECRETS.items():
            r = s.Write(pb.WriteRequest(
                path=f"/secrets/{NAMESPACE}/{key}.json",
                content=body.encode(),
                auth_token="",  # moss passes an empty token; loopback posture is Open
            ))
            if r.is_error:
                failures.append(f"write {key}: {r.error_payload!r}")
        if failures:
            print("   [FAIL] moss's own path shape does not round-trip")
        else:
            print(f"   [ok] {len(SECRETS)} secrets written with an empty token")

        print("3. read one back")
        r = s.Read(pb.ReadRequest(path=f"/secrets/{NAMESPACE}/openai.json", auth_token=""))
        if r.is_error or r.content.decode() != SECRETS["openai"]:
            failures.append(f"read back mismatch: is_error={r.is_error} content={r.content!r}")
            print("   [FAIL]")
        else:
            print("   [ok] byte-exact")

        print("4. Readdir — the claim that moss's SQLite index is redundant")
        rd = s.Readdir(pb.ReaddirRequest(path=f"/secrets/{NAMESPACE}", auth_token=""))
        names = sorted(e.name for e in rd.entries)
        if rd.is_error or len(names) != len(SECRETS):
            failures.append(f"Readdir(key level) is_error={rd.is_error} -> {names}")
            print(f"   [FAIL] {names}")
        else:
            print(f"   [ok] key level  -> {[n.rsplit('/', 1)[-1] for n in names]}")

        rd2 = s.Readdir(pb.ReaddirRequest(path="/secrets", auth_token=""))
        ns = [e.name for e in rd2.entries]
        if rd2.is_error or not any(NAMESPACE in n for n in ns):
            failures.append(f"Readdir(namespace level) is_error={rd2.is_error} -> {ns}")
            print(f"   [FAIL] {ns}")
        else:
            print(f"   [ok] namespace level -> {ns}")
            print("   ⇒ the index at ~/.moss/nexus/secrets_index.db is a redundant second SSOT")
    finally:
        kill(proc)

    # ── 4: the invariant, where it actually means something
    print("5. bind 0.0.0.0 inside the container — reachable from the container network")
    print("   (this is the 'add nexus to moss-network' mistake, made deliberately)")
    proc, up, out = boot(["--bind-addr", "0.0.0.0:2127", "--no-tls"])
    kill(proc)
    if up:
        failures.append("an unauthenticated daemon came up on 0.0.0.0 — THE INVARIANT IS BROKEN")
        print("   [FAIL] it came up. Any container on this network is now a system admin.")
    elif "refusing to start" not in out:
        failures.append(f"it refused, but not for the right reason:\n{out}")
        print("   [FAIL] refused for the wrong reason")
    else:
        print("   [ok] refused to boot — the one-config-line breach cannot happen")

    print("6. same bind, but authenticating (the Tier 1 shape moss would adopt)")
    proc, up, out = boot(
        ["--bind-addr", "0.0.0.0:2128", "--no-tls"],
        {"NEXUS_API_KEY_SECRET": "moss-shape-probe"},
    )
    kill(proc)
    if not up:
        failures.append(f"a credential policy must permit a reachable bind:\n{out}")
        print("   [FAIL]")
    else:
        print("   [ok] boots — a credential policy answers the question anywhere")

    print()
    if failures:
        print("FAIL")
        for f in failures:
            print(" -", f)
        return 1
    print("PASS — moss's shape works unchanged, and the invariant bites where it matters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
