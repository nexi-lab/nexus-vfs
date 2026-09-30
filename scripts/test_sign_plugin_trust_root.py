"""`sign_plugin.py --trust-root` must refuse a key the kernel does not trust.

The check it adds is the one the old self-verify could not make: that verified the
signature against a pubkey derived from the SAME privkey, so every valid key passed.
A release signed with the wrong key therefore published successfully and was refused
by every daemon at load time, with nothing in the release log hinting why.

Run: python scripts/test_sign_plugin_trust_root.py
Exits non-zero on the first failure and says which case failed.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
SIGNER = HERE / "sign_plugin.py"


def keypair() -> tuple[str, bytes]:
    """A fresh (base64 privkey for the env var, raw 32-byte pubkey)."""
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw_priv).decode(), raw_pub


def pub_file(dir_: Path, raw_pub: bytes, name: str) -> Path:
    """A trusted_keys/*.pub in the committed format: comments, then base64."""
    p = dir_ / name
    p.write_text(
        "# test key\n"
        "# Ed25519 public key, 32 raw bytes base64-encoded\n"
        "\n" + base64.b64encode(raw_pub).decode() + "\n",
        encoding="utf-8",
    )
    return p


def run_signer(plugin: Path, privkey_b64: str, trust_root: Path | None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PLUGIN_SIGNING_PRIVKEY=privkey_b64)
    cmd = [sys.executable, str(SIGNER), str(plugin)]
    if trust_root is not None:
        cmd += ["--trust-root", str(trust_root)]
    return subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        plugin = d / "libnexus_search_plugin.so"
        plugin.write_bytes(b"\x7fELF not really, bytes are bytes to a signature")

        trusted_priv, trusted_pub = keypair()
        other_priv, _ = keypair()
        root = pub_file(d, trusted_pub, "nexus-team.pub")

        # 1. The right key: signs, verifies against the committed pubkey, exits 0.
        r = run_signer(plugin, trusted_priv, root)
        if r.returncode != 0:
            failures.append(f"trusted key was refused: {r.returncode} {r.stderr.strip()}")
        if not (plugin.with_suffix(".so.sig").exists() or Path(str(plugin) + ".sig").exists()):
            failures.append("no .sig written for the trusted key")

        # 2. The WRONG key: the signature is perfectly valid, which is exactly why the
        #    old self-verify passed it. This must fail, and name the cause.
        r = run_signer(plugin, other_priv, root)
        if r.returncode == 0:
            failures.append(
                "an untrusted key was ACCEPTED — the release would publish a plugin "
                "every daemon refuses at load"
            )
        elif "NOT the one committed" not in (r.stdout + r.stderr):
            failures.append(f"untrusted key failed without naming the cause: {r.stderr.strip()}")

        # 3. Without --trust-root, behaviour is unchanged (the plugin-image build path
        #    signs with a local dev root and must keep working).
        r = run_signer(plugin, other_priv, None)
        if r.returncode != 0:
            failures.append(f"signing without --trust-root regressed: {r.stderr.strip()}")

        # 4. A malformed trust root is an error, not a silent pass.
        bad = d / "bad.pub"
        bad.write_text("# only comments\n", encoding="utf-8")
        r = run_signer(plugin, trusted_priv, bad)
        if r.returncode == 0:
            failures.append("a trust root with no pubkey line was accepted")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print("ok — trusted key signs, untrusted key is refused by name, no-flag path unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
