#!/usr/bin/env python3
"""The daemon refuses to serve an unauthenticated socket on a reachable address.

The invariant:

    Serving without authentication is legal only on loopback. Binding a
    reachable address requires either an `sk-` credential policy or mTLS.

Why it exists: an unauthenticated nexusd on 127.0.0.1 is a trusted local
backend — the same shape as a Unix socket, and exactly how moss runs it. An
unauthenticated nexusd on 0.0.0.0 is an open door, and the two are ONE CONFIG
LINE apart. Change a bind address, or put the container on a shared network,
and an unauthenticated store becomes reachable by anything that can route to
it. Nothing used to stop that, and nothing warned.

Unit tests pin the decision function. This pins the *daemon*: that the process
actually refuses to come up, that the refusal names a remedy, and — just as
importantly — that the shape moss depends on still boots with no flags at all.

Four paths, four outcomes:

    loopback  + no-tls + no secret   → boots (moss's shape; zero flags)
    reachable + no-tls + no secret   → REFUSES, and says what to do
    reachable + no-tls + --insecure  → boots, shouting
    reachable + no-tls + secret      → boots, authenticating

Plus a fifth path pinning the `serve-local` shorthand — the mode the
embedders spawn — to the first outcome: `serve-local --port P` must be
exactly `--bind-addr 127.0.0.1:P --no-tls`, booting with no flags.

Run:
    python scripts/e2e_loopback_invariant.py
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

BOOT_BUDGET_S = 75.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_daemon(binary: Path, args: list[str], env_extra: dict[str, str], tmp: Path) -> tuple[bool, str]:
    """Boot the daemon and report (came_up, output).

    'Came up' means it reached the point of serving rather than exiting. We
    detect it by the port answering — a refusal to *authenticate* still counts
    as coming up; what we are separating here is boot vs no-boot.
    """
    data = tmp / f"d{next(_seq)}"
    env = dict(os.environ)
    env.update(
        NEXUS_DATA_DIR=str(data / "data"),
        NEXUS_IDENTITY_DIR=str(data / "id"),
        RUST_LOG=os.environ.get("RUST_LOG", "warn"),
    )
    # A stale NEXUS_API_KEY_SECRET in the ambient environment would silently
    # authenticate a case meant to have no policy at all.
    env.pop("NEXUS_API_KEY_SECRET", None)
    env.pop("NEXUS_INSECURE_NO_AUTH", None)
    env.update(env_extra)

    proc = subprocess.Popen(
        [str(binary), *args],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        # The daemon's refusal is prose with typographic punctuation. Decoding
        # it under the console's legacy codepage turns a real failure into a
        # UnicodeDecodeError, which is a worse bug than the one being tested.
        encoding="utf-8",
        errors="replace",
    )
    try:
        deadline = time.time() + BOOT_BUDGET_S
        # The bind port is either explicit (`--bind-addr host:port`) or,
        # for the `serve-local` shorthand, the loopback `--port`.
        if "--bind-addr" in args:
            port = int(args[args.index("--bind-addr") + 1].rsplit(":", 1)[1])
        else:
            port = int(args[args.index("--port") + 1])
        while time.time() < deadline:
            if proc.poll() is not None:
                return False, proc.stdout.read() if proc.stdout else ""
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return True, ""  # serving
            time.sleep(0.5)
        return False, "timed out without serving and without exiting"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=25)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=25)


def _counter():
    i = 0
    while True:
        i += 1
        yield i


_seq = _counter()


def main() -> int:
    ap = argparse.ArgumentParser()
    default = "target/release/nexusd-cluster" + (".exe" if os.name == "nt" else "")
    ap.add_argument("--binary", type=Path, default=Path(default))
    args = ap.parse_args()
    if not args.binary.is_file():
        print(f"binary not found: {args.binary}", file=sys.stderr)
        print("build it: cargo build --release -p nexus-cluster", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="loopback-inv-"))
    failures: list[str] = []
    try:
        # ── 1. The shape moss runs. Must boot, with no flags. ─────────
        print("1. loopback + --no-tls + no secret  (moss's shape)")
        up, out = run_daemon(
            args.binary,
            ["--bind-addr", f"127.0.0.1:{free_port()}", "--no-tls"],
            {},
            tmp,
        )
        if up:
            print("   [ok] boots — a trusted local backend needs no flags")
        else:
            failures.append(f"loopback must boot with no flags, but it did not:\n{out}")
            print("   [FAIL] refused to boot")

        # ── 2. One config line away. Must refuse. ────────────────────
        print("2. 0.0.0.0 + --no-tls + no secret   (the open door)")
        up, out = run_daemon(
            args.binary,
            ["--bind-addr", f"0.0.0.0:{free_port()}", "--no-tls"],
            {},
            tmp,
        )
        if up:
            failures.append("an unauthenticated daemon came up on 0.0.0.0 — THE INVARIANT IS BROKEN")
            print("   [FAIL] it came up. Anything that can route here is now a system admin.")
        else:
            print("   [ok] refused to boot")
            # A refusal that does not say what to do is a wall, not a guard.
            for remedy in ("NEXUS_API_KEY_SECRET", "--insecure-no-auth", "loopback", "--no-tls"):
                if remedy not in out:
                    failures.append(f"the refusal never mentions {remedy!r}:\n{out}")
            if "refusing to start" not in out:
                failures.append(f"the refusal does not say it is refusing:\n{out}")
            else:
                print("   [ok] and the error names every way out")

        # ── 3. The escape hatch. Boots, loudly. ─────────────────────
        print("3. 0.0.0.0 + --insecure-no-auth      (already-open CI cluster)")
        up, out = run_daemon(
            args.binary,
            ["--bind-addr", f"0.0.0.0:{free_port()}", "--no-tls", "--insecure-no-auth"],
            {},
            tmp,
        )
        if up:
            print("   [ok] boots — the exposure is now something the deployment said out loud")
        else:
            failures.append(f"--insecure-no-auth must still allow a reachable bind:\n{out}")
            print("   [FAIL] refused even with the escape hatch")

        # ── 4. Authenticating. Boots, and the posture is ApiKey. ─────
        print("4. 0.0.0.0 + NEXUS_API_KEY_SECRET    (authenticating callers)")
        up, out = run_daemon(
            args.binary,
            ["--bind-addr", f"0.0.0.0:{free_port()}", "--no-tls"],
            {"NEXUS_API_KEY_SECRET": "e2e-loopback-invariant"},
            tmp,
        )
        if up:
            print("   [ok] boots — a credential policy answers the question anywhere")
        else:
            failures.append(f"a secret must permit a reachable bind:\n{out}")
            print("   [FAIL] refused even with a credential policy")

        # ── 5. The serve-local shorthand. Same posture as (1). ───────
        # `serve-local --port P` must be exactly `--bind-addr
        # 127.0.0.1:P --no-tls`: the trusted-local-backend shape the
        # embedders (sudowork / moss / sudocode) spawn, booting with no
        # `--insecure-no-auth`. This pins the shorthand to outcome (1) so
        # it can never drift from the hand-written triplet it replaces.
        print("5. serve-local --port               (the embedders' shorthand)")
        up, out = run_daemon(
            args.binary,
            ["serve-local", "--port", str(free_port())],
            {},
            tmp,
        )
        if up:
            print("   [ok] boots — serve-local == loopback + no-tls, no flags")
        else:
            failures.append(f"serve-local must boot on loopback with no flags:\n{out}")
            print("   [FAIL] serve-local refused to boot")

        print()
        if failures:
            print("FAIL")
            for f in failures:
                print(" -", f)
            return 1
        print("PASS — no auth is legal only on loopback, and the daemon enforces it.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
