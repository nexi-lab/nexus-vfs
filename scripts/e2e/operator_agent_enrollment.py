"""One private real mTLS journey for Cargo and optimized Windows artifacts.

Only this process's temporary Node is stopped. Receipts/logs survive; its private
keys and database are removed on either outcome. No installed Node is contacted.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def port_pair():
    # Stay below the ephemeral band, including the enrollment neighbour.
    for offset in range(12000):
        port = 20000 + (os.getpid() * 37 + offset) % 11999
        with socket.socket() as first, socket.socket() as second:
            try:
                first.bind(("127.0.0.1", port))
                second.bind(("127.0.0.1", port + 1))
            except OSError:
                continue
            return port
    raise RuntimeError("No private test port pair available")


class Journey:
    def __init__(self, args):
        self.daemon = args.daemon.resolve(strict=True)
        self.operator = args.operator.resolve(strict=True)
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.root = self.output / "owned-node"
        self.root.mkdir()  # Never reuse an earlier attempt's private state.
        self.data = self.root / "data"
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        self.address = f"127.0.0.1:{port_pair()}"
        self.grant = self.root / "grant.json"
        self.log = self.output / "daemon.log"
        self.process = None
        self.log_file = None
        # Do not inherit an operator's Node discovery/configuration or bypass.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("NEXUS_")}
        self.env.update(
            NEXUS_DATA_DIR=str(self.data),
            NEXUS_IDENTITY_DIR=str(self.root / "identity"),
            NEXUS_ADVERTISE_ADDR=self.address,
            NEXUS_CLUSTER_INIT="sharedzone",
            NEXUS_CLUSTER_INIT_MOUNTS="/agents=sharedzone",
            RUST_LOG="info,h2=warn,hyper=warn,tower=warn,tonic=warn",
            NO_COLOR="1",
        )
        self.proof = {
            "success": False, "stage": "prepared", "realMintAgentRpc": False,
            "daemonSha256": digest(self.daemon),
            "operatorSha256": digest(self.operator), "runnerSha256": digest(__file__),
            "platform": os.name, "endpoint": f"https://{self.address}",
        }
        repository = Path(__file__).resolve().parents[2]
        self.proof["sourceCommit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()

    def start(self):
        offset = self.log.stat().st_size if self.log.exists() else 0
        self.log_file = self.log.open("ab")
        self.process = subprocess.Popen(
            [str(self.daemon), "--bind-addr", self.address], env=self.env,
            stdout=self.log_file, stderr=subprocess.STDOUT,
        )
        for needle in ["CA holder armed MintAgent RPC", "Static topology applied"]:
            deadline = time.monotonic() + 120
            while True:
                text = self.log.read_bytes()[offset:].decode("utf-8", errors="replace")
                text = re.sub(r"\x1b\[[0-9;]*m", "", text)
                if needle in text:
                    break
                if self.process.poll() is not None:
                    raise RuntimeError(f"Owned Node exited before {needle}: {text[-6000:]}")
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Owned Node readiness: {needle}: {text[-6000:]}")
                time.sleep(0.05)

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
            self.process = None
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def request(self, label, claim, grant=None):
        result = subprocess.run(
            [str(self.operator), "--grant", str(grant or self.grant)],
            input=json.dumps(claim).encode(), capture_output=True, env=self.env, timeout=30,
        )
        (self.output / f"{label}.stdout.json").write_bytes(result.stdout)
        (self.output / f"{label}.stderr.log").write_bytes(result.stderr)
        assert result.returncode == 0, (label, result.stderr.decode(errors="replace"))
        return json.loads(result.stdout)

    def claim(self, actor, operation, workspace=None):
        return {"version": 1, "actor": "codex-" + actor * 32,
                "operationId": f"00000000-0000-4000-8000-00000000000{operation}",
                "threadId": f"10000000-0000-4000-8000-00000000000{actor}",
                "workspace": str(workspace or self.workspace)}

    def run(self):
        self.start()
        self.proof["stage"] = "initialize"
        initialized = subprocess.run(
            [str(self.operator), "--initialize", "--grant", str(self.grant),
             "--data-dir", str(self.data), "--endpoint", f"https://{self.address}",
             "--workspace-root", str(self.workspace)],
            env=self.env, capture_output=True, timeout=30,
        )
        assert initialized.returncode == 0, initialized.stderr.decode(errors="replace")
        assert json.loads(initialized.stdout)["issued"] is False
        policy = json.loads(self.grant.read_text(encoding="utf-8"))
        state = Path(policy["stateDirectory"])
        assert not state.exists(), "Preparation must perform no issuance"

        self.proof["stage"] = "preflight refusals"
        assert self.request("outside", self.claim("a", "1", self.root))["outcome"] == "not_submitted"
        wrong = self.root / "wrong-owner.json"
        wrong.write_text(json.dumps(policy | {"ownerCertificateSha256": "0" * 64}), encoding="utf-8")
        assert self.request("wrong-owner", self.claim("a", "1"), wrong)["outcome"] == "not_submitted"
        assert self.request("forged-owner", self.claim("a", "1") | {"owner": "another-owner"})["outcome"] == "not_submitted"
        assert not state.exists(), "Local refusals must not reserve an operation"

        self.proof["stage"] = "mint and exact replay"
        first = self.claim("a", "1")
        receipt = self.request("mint", first)
        assert receipt["actor"] == first["actor"], receipt
        self.proof["realMintAgentRpc"] = True
        credential = Path(receipt["credentialDirectory"])
        original = {name: (credential / name).read_bytes() for name in ["agent.pem", "agent-key.pem"]}
        assert self.request("replay", first) == receipt
        assert all((credential / name).read_bytes() == value for name, value in original.items())
        assert self.request("different-operation", self.claim("a", "2"))["outcome"] == "unknown"
        if os.name == "posix":
            assert self.grant.stat().st_mode & 0o777 == 0o600
            assert (credential / "agent-key.pem").stat().st_mode & 0o777 == 0o600

        self.proof["stage"] = "concurrent operation"
        racing = self.claim("b", "2")
        with ThreadPoolExecutor(max_workers=2) as pool:
            contenders = [pool.submit(self.request, f"race-{i}", racing) for i in range(2)]
            responses = [future.result() for future in contenders]
        assert any(response.get("actor") == racing["actor"] for response in responses)
        selected = self.request("race-replay", racing)
        assert all(response == selected or response.get("outcome") == "unknown" for response in responses)

        self.proof["stage"] = "Unknown across Node restart"
        self.stop()
        uncertain = self.claim("c", "3")
        assert self.request("node-down", uncertain)["outcome"] == "unknown"
        assert not (self.data / "agents" / uncertain["actor"]).exists()
        pending = state / (uncertain["actor"] + ".attempt.json")
        attempt = pending.read_bytes()
        self.start()
        assert self.request("unknown-after-restart", uncertain)["outcome"] == "unknown"
        assert pending.read_bytes() == attempt, "Recovery must retain the original operation"
        assert not (self.data / "agents" / uncertain["actor"]).exists(), "No offline mint or second RPC"
        self.proof.update(success=True, stage="complete", exactReceiptReplay=True,
                          concurrentOneOperation=True, unknownNeverResubmitted=True,
                          localRefusalsDoNotReserve=True)

    def finish(self):
        self.stop()
        shutil.rmtree(self.root)
        self.proof["ownedNodeStopped"] = True
        self.proof["privateKeysRemoved"] = True
        (self.output / "receipt.json").write_text(json.dumps(self.proof, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(self.proof), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--operator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    journey = Journey(parser.parse_args())
    try:
        journey.run()
    finally:
        journey.finish()


if __name__ == "__main__":
    main()
