#!/usr/bin/env python3
"""End-to-end proof that an A2A mailbox wakes a peer's `sys_watch` across a real
federation — the cross-machine interrupt the whole A2A design rests on.

Two real `nexusd-cluster` daemons on loopback, wired exactly like a Win<->Mac
deployment:

  * FOUNDER — owns the `sharedzone` federation zone, mounted at `/agents`
    (`NEXUS_FEDERATION_ZONES` / `NEXUS_FEDERATION_MOUNTS`).
  * JOINER  — reaches that zone PURELY by boot-time DiscoverZones (bootstrap
    matrix row 3: `--peers <founder>`, and NO federation env — a non-empty
    mounts env alongside `--peers` is a fail-loud ambiguous boot).

Nothing is stubbed: real raft JoinZone, real wal DT_STREAM replication over the
raft log, real gRPC. The journey, each step consuming the previous step's
output:

  1. BOOT    founder (sharedzone owner) + joiner (discovers sharedzone).
  2. HEALTH  founder writes a file under /agents; the joiner reads the exact
             bytes back — proves the shared zone replicates + routes cross-node.
  3. CREATE  the mailbox owner plants /agents/<owner>/chat-with-me as a wal
             DT_STREAM (io_profile "wal,memory" → replicated, not the local ring).
  4. OPEN    the SENDER (a peer that never created it) opens the mailbox — it
             materializes a WalStreamCore over its own replica's metastore, the
             cross-node open that lets it write a mailbox it did not create.
  5. SEND    the sender appends an envelope (a replicated AppendStreamEntry),
             exactly how you message someone in A2A: write their chat-with-me.
  6. WAKE    the OWNER's parked Watch returns — the apply-side stream-wakeup
             observer fired on the owner's `sharedzone` replica. THIS regresses
             if the observer is armed off the env mounts (a joiner has none)
             instead of off the zones it actually joined.
  7. READ    the owner reads the envelope back from its own replica — byte-exact.
  8. REVERSE swap roles. Proves symmetry: both nodes arm the wakeup on the
             shared zone AND both can open + send to a peer-owned mailbox.

Run:
    python scripts/e2e_a2a_wakeup.py [--binary target/release/nexusd-cluster]
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import grpc

_REPO = Path(__file__).resolve().parents[1]

DT_STREAM = 4
ZONE = "sharedzone"
MOUNT = "/agents"


def _load_vfs_stubs():
    """Generate the client stubs from this repo's own proto (the wire SSOT)."""
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
    for pkg in ("nexus", "nexus/grpc", "nexus/grpc/vfs"):
        (out / pkg / "__init__.py").touch()
    from nexus.grpc.vfs import vfs_pb2, vfs_pb2_grpc  # noqa: PLC0415

    return vfs_pb2, vfs_pb2_grpc


vfs_pb2, vfs_pb2_grpc = _load_vfs_stubs()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── gRPC helpers — one short-lived channel per call, like e2e_api_key_auth ────

def _stub(port: int):
    ch = grpc.insecure_channel(f"127.0.0.1:{port}")
    return ch, vfs_pb2_grpc.NexusVFSServiceStub(ch)


def ping(port: int) -> "vfs_pb2.PingResponse":
    ch, s = _stub(port)
    with ch:
        return s.Ping(vfs_pb2.PingRequest(auth_token=""), timeout=20)


def mkdir(port: int, path: str) -> None:
    ch, s = _stub(port)
    with ch:
        r = s.Mkdir(vfs_pb2.MkdirRequest(path=path, parents=True, exist_ok=True), timeout=20)
        if r.is_error:
            raise RuntimeError(f"mkdir {path}: {r.error_payload!r}")


def write_file(port: int, path: str, data: bytes) -> None:
    ch, s = _stub(port)
    with ch:
        r = s.Write(vfs_pb2.WriteRequest(path=path, content=data), timeout=20)
        if r.is_error:
            raise RuntimeError(f"write {path}: {r.error_payload!r}")


def read_file(port: int, path: str) -> bytes:
    ch, s = _stub(port)
    with ch:
        r = s.Read(vfs_pb2.ReadRequest(path=path, timeout_ms=5000), timeout=20)
        if r.is_error:
            raise RuntimeError(f"read {path}: {r.error_payload!r}")
        return r.content


def stat(port: int, path: str) -> "vfs_pb2.StatResponse":
    ch, s = _stub(port)
    with ch:
        return s.Stat(vfs_pb2.StatRequest(path=path), timeout=20)


def readdir_ok(port: int, path: str) -> bool:
    ch, s = _stub(port)
    with ch:
        r = s.Readdir(vfs_pb2.ReaddirRequest(path=path), timeout=20)
        return not r.is_error


def create_stream(port: int, path: str) -> None:
    ch, s = _stub(port)
    with ch:
        r = s.Setattr(
            vfs_pb2.SetattrRequest(path=path, entry_type=DT_STREAM, io_profile="wal,memory"),
            timeout=20,
        )
        if r.is_error:
            raise RuntimeError(f"create_stream {path}: {r.error_payload!r}")


def stream_write(port: int, path: str, data: bytes) -> int:
    ch, s = _stub(port)
    with ch:
        r = s.StreamWriteNowait(vfs_pb2.StreamWriteRequest(path=path, data=data), timeout=20)
        if r.is_error:
            raise RuntimeError(f"stream_write {path}: {r.error_payload!r}")
        return r.offset


def stream_collect_all(port: int, path: str) -> bytes:
    ch, s = _stub(port)
    with ch:
        r = s.StreamCollectAll(vfs_pb2.IpcPathRequest(path=path), timeout=20)
        if r.is_error:
            raise RuntimeError(f"stream_collect_all {path}: {r.error_payload!r}")
        return r.data


def watch_in_thread(port: int, path: str, timeout_ms: int) -> "list":
    """Park a blocking Watch in a thread; result[0] is the WatchResponse."""
    result: list = []

    def _run():
        ch, s = _stub(port)
        with ch:
            try:
                result.append(
                    s.Watch(
                        vfs_pb2.WatchRequest(path=path, timeout_ms=timeout_ms),
                        timeout=timeout_ms / 1000 + 15,
                    )
                )
            except grpc.RpcError as e:  # noqa: BLE001
                result.append(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return [t, result]


class Daemon:
    """A real `nexusd-cluster` on a private data dir / identity dir / port."""

    def __init__(self, name: str, binary: Path, root: Path, port: int, *, founder: bool, founder_port: int | None = None):
        self.name = name
        self.binary = binary
        self.data_dir = root / f"{name}-data"
        self.identity_dir = root / f"{name}-identity"
        self.port = port
        self.founder = founder
        self.founder_port = founder_port
        self.proc: subprocess.Popen | None = None

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            NEXUS_DATA_DIR=str(self.data_dir),
            NEXUS_IDENTITY_DIR=str(self.identity_dir),
            NEXUS_ADVERTISE_ADDR=f"127.0.0.1:{self.port}",
            NEXUS_NO_TLS="true",
            NEXUS_INSECURE_NO_AUTH="true",
            RUST_LOG=os.environ.get("RUST_LOG", "warn"),
        )
        if self.founder:
            # Static founder (matrix row 1): owns the shared zone + mount.
            env["NEXUS_FEDERATION_ZONES"] = ZONE
            env["NEXUS_FEDERATION_MOUNTS"] = f"{MOUNT}={ZONE}"
        else:
            # Row-3 joiner: DiscoverZones off --peers, NO federation env.
            env["NEXUS_PEERS"] = f"127.0.0.1:{self.founder_port}"
        return env

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

    def _drain(self) -> str:
        return self.proc.stdout.read() if (self.proc and self.proc.stdout) else ""

    def wait_serving(self, timeout: float = 90.0) -> None:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"[{self.name}] exited early (rc={self.proc.returncode}):\n{self._drain()}")
            try:
                ping(self.port)
                return
            except grpc.RpcError as e:
                last = e
            time.sleep(0.5)
        raise RuntimeError(f"[{self.name}] never served on :{self.port} — last {last}")

    def wait_mounted(self, path: str, timeout: float = 90.0) -> None:
        """Poll until `path` resolves (the shared mount is installed/joined)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"[{self.name}] exited (rc={self.proc.returncode}):\n{self._drain()}")
            try:
                if readdir_ok(self.port, path):
                    return
            except grpc.RpcError:
                pass
            time.sleep(0.5)
        raise RuntimeError(f"[{self.name}] never mounted {path} within {timeout}s")


def _await_replicated(port: int, path: str, timeout: float = 30.0) -> None:
    """Poll Stat on `port` until `path` exists (metadata replicated in)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if stat(port, path).found:
                return
        except grpc.RpcError:
            pass
        time.sleep(0.3)
    raise AssertionError(f"{path} never replicated to :{port} within {timeout}s")


def _mailbox_round(owner: Daemon, sender: Daemon, agent: str) -> None:
    """One real A2A direction: `agent` owns the mailbox on `owner`; a `sender`
    peer that never created it opens + writes it; `owner` wakes + reads.

    This mirrors production A2A — you send by writing to the RECIPIENT's
    chat-with-me — and exercises the two cross-node paths a woken peer needs:
    the sender materializes a wal backend for a mailbox it did not create
    (open), and its write proposes a replicated AppendStreamEntry that both
    wakes the owner's parked Watch and lands in the owner's own replica for the
    read-back.
    """
    mailbox = f"{MOUNT}/{agent}/chat-with-me"
    envelope = f'{{"from":"{sender.name}","to":"{agent}","body":"ping from {sender.name}"}}'.encode()

    print(f"   {owner.name} creates {mailbox} (wal DT_STREAM)")
    mkdir(owner.port, f"{MOUNT}/{agent}")
    create_stream(owner.port, mailbox)

    print(f"   wait for the mailbox to replicate to {sender.name}")
    _await_replicated(sender.port, mailbox)

    print(f"   {sender.name} opens the peer-owned mailbox (materializes wal backend)")
    create_stream(sender.port, mailbox)  # reopen -> install_stream_backend -> wal

    print(f"   {owner.name} parks Watch on its mailbox")
    t, result = watch_in_thread(owner.port, mailbox, timeout_ms=20000)
    time.sleep(1.5)  # ensure the watch is parked before the write

    print(f"   {sender.name} sends an envelope ({len(envelope)} bytes)")
    stream_write(sender.port, mailbox, envelope)

    t.join(timeout=25)
    assert result, f"{owner.name} Watch thread produced no result"
    resp = result[0]
    if isinstance(resp, grpc.RpcError):
        raise AssertionError(f"{owner.name} Watch errored: {resp.code()} {resp.details()}")
    assert resp.matched, (
        f"{owner.name} Watch TIMED OUT — the apply-side stream-wakeup observer "
        f"did not fire on {owner.name}'s {ZONE} replica"
    )
    print(f"   [ok] {owner.name} WOKE — event_type={resp.event_type!r} path={resp.path!r}")

    got = stream_collect_all(owner.port, mailbox)
    assert envelope in got, f"{owner.name} read {got!r}, expected to contain {envelope!r}"
    print(f"   [ok] {owner.name} read the envelope back byte-exact")


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

    tmp = Path(tempfile.mkdtemp(prefix="nexus-a2a-e2e-"))
    fport, jport = free_port(), free_port()
    founder = Daemon("founder", args.binary, tmp, fport, founder=True)
    joiner = Daemon("joiner", args.binary, tmp, jport, founder=False, founder_port=fport)
    try:
        # ── 1. Boot ──────────────────────────────────────────────────────
        print("1. boot founder (sharedzone owner) then joiner (DiscoverZones)")
        founder.start()
        founder.wait_serving()
        founder.wait_mounted(MOUNT)
        print(f"   [ok] founder serving on :{fport}, {MOUNT} mounted")
        joiner.start()
        joiner.wait_serving()
        joiner.wait_mounted(MOUNT)
        print(f"   [ok] joiner serving on :{jport}, {MOUNT} joined via DiscoverZones")

        # ── 2. Federation health — write on founder, read on joiner ──────
        print("2. federation health — founder writes /agents, joiner reads it back")
        health = f"{MOUNT}/health-founder.txt"
        payload = b"federation-health-probe-v1"
        write_file(founder.port, health, payload)
        _await_replicated(joiner.port, health)
        got = read_file(joiner.port, health)
        assert got == payload, f"joiner read {got!r}, expected {payload!r}"
        print("   [ok] joiner read the founder's bytes back — zone replicates + routes")

        # ── 3-7. A2A: joiner owns mailbox, founder (peer) sends ──────────
        print("3-7. A2A: joiner mailbox; founder (peer) opens + sends; joiner wakes + reads")
        _mailbox_round(owner=joiner, sender=founder, agent="joiner-ai")

        # ── 8. Reverse — founder owns mailbox, joiner (peer) sends ───────
        print("8. reverse A2A: founder mailbox; joiner (peer) opens + sends; founder wakes + reads")
        _mailbox_round(owner=founder, sender=joiner, agent="founder-ai")

        print("\nPASS — the A2A mailbox wakes a peer's sys_watch across the federation.")
        return 0
    finally:
        joiner.stop()
        founder.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
