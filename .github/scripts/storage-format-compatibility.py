"""Open current native fixtures using the actual pinned previous storage reader."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


PREVIOUS_READER = "8f6c072b9afef7e314b89161ea97315135767e9b"
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--fixture-binary", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
environment = os.environ.copy()
environment["NEXUS_REPLICA_FORMAT_FIXTURES"] = str(output / "fixtures")
environment["CARGO_TARGET_DIR"] = str(Path(environment.get("CARGO_TARGET_DIR", root / "target")).resolve())
# The previous reader is another revision of this same workspace. Cargo names a
# workspace member's artifacts by its path relative to the workspace root, so
# building it into the writer's target directory would replace the writer's
# artifacts with the old revision's under the same names and fresh-looking
# fingerprints, and every later build there would link them (CI: the next
# step's `contracts` lost a module). It gets a target directory of its own.
reader_environment = {**environment,
                      "CARGO_TARGET_DIR": str(Path(environment["CARGO_TARGET_DIR"]) / "previous-storage-reader")}
receipt = {"previousReader": PREVIOUS_READER, "success": False, "steps": []}


def run(name, command, cwd=root, build=False, env=environment):
    with (output / f"{name}.log").open("w", encoding="utf8") as log:
        result = subprocess.run(
            [str(arg) for arg in command], cwd=cwd, env=env,
            stdout=log, stderr=subprocess.STDOUT,
            creationflags=(subprocess.BELOW_NORMAL_PRIORITY_CLASS if build else
                           subprocess.NORMAL_PRIORITY_CLASS) if os.name == "nt" else 0,
        )
    receipt["steps"].append({"name": name, "exitCode": result.returncode})
    result.check_returncode()


try:
    receipt["writer"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if args.fixture_binary:
        producer = [args.fixture_binary.resolve()]
    else:
        producer = ["cargo", "test", "--locked", "-p", "raft@0.1.0", "--test", "test_durable_storage_admission", "--"]
    run("produce-fixtures", [*producer, "replica_format_fixtures_for_previous_reader", "--exact", "--test-threads=1"])
    present = subprocess.run(["git", "cat-file", "-e", PREVIOUS_READER + "^{commit}"], cwd=root, capture_output=True)
    if present.returncode:
        run("fetch-reader", ["git", "fetch", "--no-tags", "origin", PREVIOUS_READER])
    reader = output / "previous-reader"
    run("checkout-reader", ["git", "worktree", "add", "--detach", reader, PREVIOUS_READER])
    shutil.copyfile(root / "rust/raft/tests/fixtures/previous_storage_reader.rs",
                    reader / "rust/raft/tests/previous_storage_reader.rs")
    run("build-reader", ["cargo", "test", "--locked", "-p", "raft@0.1.0", "--test", "previous_storage_reader",
                         "--no-run", "--message-format=json"], reader, build=True, env=reader_environment)
    binaries = []
    for line in (output / "build-reader.log").read_text(encoding="utf8").splitlines():
        if line.startswith('{'):
            message = json.loads(line)
            if (message.get("reason") == "compiler-artifact" and message.get("executable")
                    and message.get("target", {}).get("name") == "previous_storage_reader"):
                binaries.append(message["executable"])
    assert len(binaries) == 1, binaries
    run("previous-reader", [binaries[0], "--test-threads=1"], reader, env=reader_environment)
    receipt["success"] = True
finally:
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf8")
    print(json.dumps({"receipt": str(output / "receipt.json"), "success": receipt["success"]}))
