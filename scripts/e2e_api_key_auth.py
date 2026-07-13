#!/usr/bin/env python3
"""End-to-end proof that `sk-` API-key authentication actually gates the daemon.

This drives the real thing: a real `nexusd-cluster` process, real key
minting through raft consensus, and real gRPC calls over the wire. Nothing is
stubbed — if the provider is not wired, or the store is not bound, or the gate
does not reject, this fails.

The journey, each step consuming the previous step's output:

  1. MINT   an agent key with the offline CLI. It commits through raft, and the
            key exists in the clear exactly once — in stdout.
  2. LIST   the store back from a *separate process*, proving the record is
            durable state and not something the minting process held in memory.
  3. SERVE  boot the daemon against that same data directory.
  4. AUTH   Ping with the minted key → authenticated.
  5. DENY   Ping with an empty token → UNAUTHENTICATED. This is the security
            win the whole workstream exists for: today a bare cluster answers
            *any* token, including none, as a system admin.
  6. DENY   Ping with a well-formed but unknown `sk-` key → UNAUTHENTICATED.
            Proves the store is actually consulted, not just the format.
  7. REVOKE stop the daemon, revoke the key, boot again → the same key that
            worked in step 4 is now refused.

Run:
    python scripts/e2e_api_key_auth.py [--binary target/release/nexusd-cluster]
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import grpc

_REPO = Path(__file__).resolve().parents[1]


def _load_vfs_stubs():
    """Generate the client stubs from this repo's own proto.

    The proto is the SSOT for the wire, and it lives here — so the test
    compiles it rather than importing a pre-generated copy from a sibling
    checkout. That keeps the E2E self-contained (CI needs no second repo) and
    means a wire change cannot drift past it.
    """
    out = Path(tempfile.mkdtemp(prefix="nexus-vfs-stubs-"))
    subprocess.run(
        [
            sys.executable, "-m", "grpc_tools.protoc",
            f"-I{_REPO / 'proto'}",
            f"--python_out={out}",
            f"--grpc_python_out={out}",
            str(_REPO / "proto" / "nexus" / "grpc" / "vfs" / "vfs.proto"),
        ],
        check=True,
        capture_output=True,
    )
    sys.path.insert(0, str(out))
    # protoc emits `nexus/grpc/vfs/vfs_pb2.py` with package-relative imports.
    for pkg in ("nexus", "nexus/grpc", "nexus/grpc/vfs"):
        (out / pkg / "__init__.py").touch()
    from nexus.grpc.vfs import vfs_pb2, vfs_pb2_grpc  # noqa: PLC0415

    return vfs_pb2, vfs_pb2_grpc


vfs_pb2, vfs_pb2_grpc = _load_vfs_stubs()

SECRET = "e2e-api-key-secret"
AGENT = "mac-ai"
ZONE = "sharedzone"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Daemon:
    """The daemon under test, on a private data dir and port."""

    def __init__(self, binary: Path, data_dir: Path, identity_dir: Path, port: int):
        self.binary = binary
        self.data_dir = data_dir
        self.identity_dir = identity_dir
        self.port = port
        self.proc: subprocess.Popen | None = None

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            NEXUS_DATA_DIR=str(self.data_dir),
            NEXUS_IDENTITY_DIR=str(self.identity_dir),
            NEXUS_API_KEY_SECRET=SECRET,
            # Plaintext so an external client can connect at all. mTLS is the
            # peer plane; the sk- token plane is what is under test here.
            NEXUS_NO_TLS="true",
            RUST_LOG=os.environ.get("RUST_LOG", "warn"),
        )
        return env

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        """Run an offline subcommand (the daemon must not be holding the lock)."""
        return subprocess.run(
            [str(self.binary), *args],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [str(self.binary), "--bind-addr", f"127.0.0.1:{self.port}"],
            env=self.env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=30)
        self.proc = None

    def wait_serving(self, timeout: float = 90.0) -> None:
        """Poll until the gRPC port answers. A refusal counts as serving — it
        means the provider is up and saying no, which is the point."""
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                out = self.proc.stdout.read() if self.proc.stdout else ""
                raise RuntimeError(f"daemon exited early (rc={self.proc.returncode}):\n{out}")
            try:
                ping(self.port, "")
                return  # answered (however it answered)
            except grpc.RpcError as e:
                if e.code() in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
                    return
                last = e
            time.sleep(0.5)
        raise RuntimeError(f"daemon never served on :{self.port} — last error {last}")


def ping(port: int, token: str) -> vfs_pb2.PingResponse:
    with grpc.insecure_channel(f"127.0.0.1:{port}") as ch:
        stub = vfs_pb2_grpc.NexusVFSServiceStub(ch)
        return stub.Ping(vfs_pb2.PingRequest(auth_token=token), timeout=20)


def expect_rejected(port: int, token: str, what: str) -> None:
    try:
        ping(port, token)
    except grpc.RpcError as e:
        if e.code() is grpc.StatusCode.UNAUTHENTICATED:
            print(f"   [ok] {what} → UNAUTHENTICATED")
            return
        raise AssertionError(f"{what}: expected UNAUTHENTICATED, got {e.code()}: {e.details()}")
    raise AssertionError(f"{what}: the daemon ANSWERED. Auth is not gating.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--binary",
        type=Path,
        default=Path("target/release/nexusd-cluster")
        if os.name != "nt"
        else Path("target/release/nexusd-cluster.exe"),
    )
    args = ap.parse_args()
    if not args.binary.is_file():
        print(f"binary not found: {args.binary}", file=sys.stderr)
        print("build it: cargo build --release -p nexus-cluster", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="nexus-auth-e2e-"))
    d = Daemon(args.binary, tmp / "data", tmp / "identity", free_port())
    try:
        # ── 1. Mint ──────────────────────────────────────────────────────
        print("1. mint an agent key (offline CLI, committed through raft)")
        r = d.cli(
            "auth", "mint",
            "--subject-type", "agent",
            "--subject-id", AGENT,
            "--zone", f"{ZONE}:rw",
            "--name", "e2e",
        )
        assert r.returncode == 0, f"mint failed:\n{r.stdout}\n{r.stderr}"
        key = r.stdout.strip()
        assert key.startswith("sk-") and len(key) >= 32, f"malformed key: {key!r}"
        print(f"   [ok] {key[:12]}…")

        # ── 2. List (a separate process reads it back) ────────────────────
        print("2. list it back from a separate process — the record is durable")
        r = d.cli("auth", "list")
        assert r.returncode == 0, f"list failed:\n{r.stderr}"
        assert f"agent:{AGENT}" in r.stdout, f"minted key not in the store:\n{r.stdout}"
        assert key not in r.stdout, "the clear-text key must never appear in the store"
        print(f"   [ok] {r.stdout.strip().splitlines()[0][:78]}…")

        # ── 3. Serve ─────────────────────────────────────────────────────
        print("3. boot the daemon against that data dir")
        d.start()
        d.wait_serving()
        print(f"   [ok] serving on :{d.port}")

        # ── 4. The minted key authenticates ──────────────────────────────
        print("4. Ping with the minted key")
        resp = ping(d.port, key)
        print(f"   [ok] authenticated — version={resp.version!r} zone={resp.zone_id!r}")

        # ── 5. No credential is nobody ───────────────────────────────────
        print("5. Ping with an EMPTY token (a bare cluster answers this as admin)")
        expect_rejected(d.port, "", "empty token")

        # ── 6. A well-formed unknown key is nobody ───────────────────────
        print("6. Ping with a well-formed but unknown sk- key")
        expect_rejected(d.port, "sk-" + "0" * 40, "unknown key")

        # ── 7. Revocation ────────────────────────────────────────────────
        print("7. revoke the key, boot again — the same key is now refused")
        d.stop()
        r = d.cli("auth", "revoke", "--key", key)
        assert r.returncode == 0 and "revoked" in r.stdout, f"revoke failed:\n{r.stdout}{r.stderr}"
        d.start()
        d.wait_serving()
        expect_rejected(d.port, key, "revoked key")

        print("\nPASS — sk- API-key authentication gates the daemon end to end.")
        return 0
    finally:
        d.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
