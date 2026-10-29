"""Qualify the exact optimized binary through the existing real mTLS fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def prepare(root, output):
    output.mkdir(parents=True, exist_ok=False)
    command = [
        "cargo", "test", "--locked", "--release", "-p", "nexus-cluster",
        "--test", "node_enrollment", "--no-run", "--message-format=json",
    ]
    with (output / "prepare.stdout.log").open("w", encoding="utf-8") as stdout, (
        output / "prepare.stderr.log"
    ).open("w", encoding="utf-8") as stderr:
        result = subprocess.run(command, cwd=root, env=os.environ | {"CARGO_BUILD_JOBS": "1"},
                                stdout=stdout, stderr=stderr)
    result.check_returncode()
    artifacts = [json.loads(line) for line in (output / "prepare.stdout.log").read_text(encoding="utf-8").splitlines()]
    executables = [row for row in artifacts
                   if row.get("reason") == "compiler-artifact" and row.get("executable")]
    fixture, = [row for row in executables if row["target"]["name"] == "node_enrollment"]
    binary, = [row for row in executables if row["target"]["name"] == "nexusd-cluster"]
    prepared = {
        "fixture": fixture["executable"],
        "fixtureSha256": digest(fixture["executable"]),
        "expectedBinary": binary["executable"],
        "scriptSha256": digest(__file__),
        "fixtureSources": {name: digest(root / name) for name in [
            "rust/profiles/cluster/tests/node_enrollment.rs",
            "rust/profiles/cluster/tests/common/mod.rs",
            "rust-toolchain.toml", "Cargo.lock",
        ]},
    }
    (output / "prepared.json").write_text(json.dumps(prepared, indent=2), encoding="utf-8")


def run(root, output, binary):
    prepared = json.loads((output / "prepared.json").read_text(encoding="utf-8"))
    assert binary.resolve(strict=True) == Path(prepared["expectedBinary"]).resolve(strict=True)
    assert digest(prepared["fixture"]) == prepared["fixtureSha256"]
    assert digest(__file__) == prepared["scriptSha256"]
    proof = {
        "success": False, "binary": str(binary), "binarySha256": digest(binary),
        "fixtureSha256": prepared["fixtureSha256"], "cpuCount": os.cpu_count(),
        "scriptSha256": prepared["scriptSha256"], "fixtureSources": prepared["fixtureSources"],
        "sourceCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    }
    try:
        assert all(digest(root / name) == expected for name, expected in prepared["fixtureSources"].items())
        version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True)
        proof["version"] = version.stdout.strip()
        with (output / "tests.stdout.log").open("w", encoding="utf-8") as stdout, (
            output / "tests.stderr.log"
        ).open("w", encoding="utf-8") as stderr:
            result = subprocess.run([prepared["fixture"], "--test-threads=1"], cwd=root,
                                    stdout=stdout, stderr=stderr)
        proof["exitCode"] = result.returncode
        proof["binaryAfterSha256"] = digest(binary)
        proof["fixtureAfterSha256"] = digest(prepared["fixture"])
        assert proof["binaryAfterSha256"] == proof["binarySha256"]
        assert proof["fixtureAfterSha256"] == proof["fixtureSha256"]
        result.check_returncode()
        assert "6 passed; 0 failed; 0 ignored;" in (output / "tests.stdout.log").read_text(encoding="utf-8")
        proof["success"] = True
    finally:
        (output / "receipt.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
        print(json.dumps(proof), flush=True)
    assert proof["success"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "run"])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if args.mode == "prepare":
        prepare(root, output)
    else:
        assert args.binary is not None
        run(root, output, args.binary.resolve())


if __name__ == "__main__":
    main()
