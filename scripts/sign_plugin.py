#!/usr/bin/env python3
"""Detach-sign a plugin binary with the kernel team's Ed25519 key.

Half 2 of the cross-repo plugin-signing 0->1. The verifier side lives in
the nexus-vfs repository, at `rust/kernel/src/kernel/plugins/loader.rs`
+ `rust/kernel/trusted_keys/nexus-team.pub`.

Format contract is held by `nexus-plugin-abi`:
    SIGNATURE_FILE_SUFFIX = ".sig"
    SIGNATURE_LENGTH      = 64   # raw Ed25519 signature, no header
    PUBKEY_LENGTH         = 32   # raw Ed25519 pubkey, base64 in .pub file
Constants here are hardcoded to match. If you ever bump one, bump the
other side in the same coordinated PR — drift fails verify silently
across every existing signed plugin.

Private key source: `PLUGIN_SIGNING_PRIVKEY` env var, base64 of exactly
32 raw bytes. Set as a GitHub Actions secret on `nexi-lab/nexus`. The
private key is never written to disk or echoed; it stays in process
memory only for the duration of the sign call.

Output: `<plugin>` is left untouched; `<plugin>.sig` is written
alongside it with exactly 64 raw bytes (no base64, no PEM, no minisign
frame). The kernel-side verifier reads `<plugin>` and `<plugin>.sig`
in tandem and Ed25519-verifies one against the other.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Pinned format constants — must match `nexus-plugin-abi::signing` in nexus-vfs.
SIGNATURE_FILE_SUFFIX = ".sig"
SIGNATURE_LENGTH = 64
PUBKEY_LENGTH = 32
PRIVKEY_LENGTH = 32

PRIVKEY_ENV = "PLUGIN_SIGNING_PRIVKEY"


def load_privkey_from_env() -> Ed25519PrivateKey:
    """Pull the signing key from `PLUGIN_SIGNING_PRIVKEY` and validate it."""
    raw_b64 = os.environ.get(PRIVKEY_ENV)
    if not raw_b64:
        raise SystemExit(
            f"environment variable {PRIVKEY_ENV} is empty or unset — "
            f"set it to base64 of {PRIVKEY_LENGTH} raw Ed25519 private bytes"
        )
    try:
        raw = base64.b64decode(raw_b64.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SystemExit(f"{PRIVKEY_ENV}: not valid base64: {exc}") from exc
    if len(raw) != PRIVKEY_LENGTH:
        raise SystemExit(f"{PRIVKEY_ENV}: decoded length {len(raw)} != expected {PRIVKEY_LENGTH}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_one(privkey: Ed25519PrivateKey, plugin: Path) -> Path:
    """Sign one plugin file in place and return the path of the `.sig` written."""
    if not plugin.is_file():
        raise SystemExit(f"plugin not found or not a file: {plugin}")
    payload = plugin.read_bytes()
    signature = privkey.sign(payload)
    if len(signature) != SIGNATURE_LENGTH:
        # Defence in depth: cryptography always returns 64 for Ed25519, but
        # an SSOT mismatch (someone bumped the constant on one side and not
        # the other) would silently emit a sig the verifier can't read.
        raise SystemExit(f"signature length {len(signature)} != expected {SIGNATURE_LENGTH}")

    sig_path = plugin.with_name(plugin.name + SIGNATURE_FILE_SUFFIX)
    sig_path.write_bytes(signature)

    # Self-check the just-written sig so an IO truncation or encoding accident is
    # caught here rather than in a cluster log.
    #
    # This canNOT catch the wrong keypair, and the comment here used to claim it
    # could: the pubkey is derived from the same privkey, so every valid key passes.
    # `--trust-root` is the check that catches that, and it is the one that matters —
    # a signature made with an untrusted key ships happily and is refused at load.
    pubkey: Ed25519PublicKey = privkey.public_key()
    try:
        pubkey.verify(sig_path.read_bytes(), payload)
    except InvalidSignature as exc:
        raise SystemExit(f"self-verify failed for {sig_path} — signing pipeline is broken") from exc

    return sig_path


def load_trust_root(path: Path) -> Ed25519PublicKey:
    """Parse a `trusted_keys/*.pub` the way the runtime verifier does.

    Same rule as `parse_pubkey_file` in `rust/kernel/src/kernel/plugins/loader.rs`:
    skip `#`-prefixed and blank lines, take the first remaining line as base64 of
    exactly `PUBKEY_LENGTH` raw bytes. Kept deliberately identical — a signer that
    accepted a file the loader rejects would pass a check the daemon then fails.
    """
    if not path.is_file():
        raise SystemExit(f"trust root not found: {path}")
    line = next(
        (
            stripped
            for raw in path.read_text(encoding="utf-8").splitlines()
            if (stripped := raw.strip()) and not stripped.startswith("#")
        ),
        None,
    )
    if line is None:
        raise SystemExit(f"no base64 pubkey line in {path}")
    try:
        raw = base64.b64decode(line, validate=True)
    except Exception as exc:  # any decode failure gives the caller the same answer
        raise SystemExit(f"{path}: base64 decode failed: {exc}") from exc
    if len(raw) != PUBKEY_LENGTH:
        raise SystemExit(f"{path}: pubkey length {len(raw)} != expected {PUBKEY_LENGTH}")
    return Ed25519PublicKey.from_public_bytes(raw)


def assert_signed_by_trust_root(plugin: Path, sig_path: Path, trust_root: Path) -> None:
    """Fail unless the signature verifies against the COMMITTED pubkey.

    Without this, signing with a key the kernel does not trust succeeds, the release
    publishes, and the failure appears much later as a plugin the daemon refuses to
    load — with nothing in the release log hinting why. The kernel trusts only the
    keys committed under `rust/kernel/trusted_keys/`, so that file is the authority
    on whether a signature is worth shipping.
    """
    pubkey = load_trust_root(trust_root)
    try:
        pubkey.verify(sig_path.read_bytes(), plugin.read_bytes())
    except InvalidSignature as exc:
        raise SystemExit(
            f"{plugin} was signed with a key that is NOT the one committed at "
            f"{trust_root}. The signature is valid, so it would publish and then be "
            f"refused by every daemon at load time. Check which privkey is in "
            f"PLUGIN_SIGNING_PRIVKEY: it must pair with that .pub."
        ) from exc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Ed25519 detach-sign one or more plugin binaries.",
    )
    p.add_argument(
        "plugins",
        nargs="+",
        type=Path,
        help="plugin binaries to sign (`.so` / `.dylib` / `.dll`)",
    )
    p.add_argument(
        "--trust-root",
        type=Path,
        help=(
            "a trusted_keys/*.pub the signature must verify against. Use it in release "
            "pipelines: without it, signing with a key the kernel does not trust "
            "succeeds and the plugin is refused at load time instead."
        ),
    )
    args = p.parse_args(argv)

    privkey = load_privkey_from_env()
    for plugin in args.plugins:
        sig_path = sign_one(privkey, plugin)
        if args.trust_root is not None:
            assert_signed_by_trust_root(plugin, sig_path, args.trust_root)
        # public_bytes(Raw, Raw) rather than public_bytes_raw(): the
        # latter needs cryptography>=40, which Debian bookworm's
        # python3-cryptography (38.x, used in plugin image builds)
        # predates. Identical output.
        raw_pub = privkey.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        sha = base64.b64encode(raw_pub).decode()
        print(f"signed {plugin} -> {sig_path} (pubkey {sha[:8]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
