"""One private real mTLS journey for Cargo and optimized Windows artifacts.

Only this process's temporary Nodes are stopped. Receipts/logs survive; their
private keys and databases are removed on either outcome. No installed Node is
contacted.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def port_pair(taken):
    # Stay below the ephemeral band, including the enrollment neighbour.
    for offset in range(12000):
        port = 20000 + (os.getpid() * 37 + offset) % 11999
        if {port, port + 1} & taken:
            continue
        with socket.socket() as first, socket.socket() as second:
            try:
                first.bind(("127.0.0.1", port))
                second.bind(("127.0.0.1", port + 1))
            except OSError:
                continue
            taken.update({port, port + 1})
            return port
    raise RuntimeError("No private test port pair available")


def node_id(data):
    return int.from_bytes((data / ".node_id").read_bytes(), "big")


class Node:
    """One private daemon and its data directory; never another process."""

    def __init__(self, journey, name, cluster):
        self.daemon = journey.daemon
        self.root = journey.root / name
        self.data = self.root / "data"
        self.address = f"127.0.0.1:{port_pair(journey.taken)}"
        self.log = journey.output / f"{name}.log"
        self.process = None
        self.log_file = None
        # Do not inherit an operator's Node discovery/configuration or bypass.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("NEXUS_")}
        self.env.update(
            NEXUS_DATA_DIR=str(self.data),
            NEXUS_IDENTITY_DIR=str(self.root / "identity"),
            NEXUS_ADVERTISE_ADDR=self.address,
            NEXUS_CLUSTER_INIT=cluster,
            NEXUS_CLUSTER_INIT_MOUNTS=f"/agents={cluster}",
            NEXUS_ACCEPT_ENROLLMENTS="1",
            RUST_LOG="info,h2=warn,hyper=warn,tower=warn,tonic=warn",
            NO_COLOR="1",
        )

    def start(self):
        offset = self.log.stat().st_size if self.log.exists() else 0
        self.log_file = self.log.open("ab")
        self.process = subprocess.Popen(
            [str(self.daemon), "--bind-addr", self.address], env=self.env,
            stdout=self.log_file, stderr=subprocess.STDOUT,
        )
        for needle in ["CA holder armed MintAgent RPC", "node-enrollment listener up",
                       "Static topology applied"]:
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

    def cli(self, label, output, *args, data=None):
        """Run one offline daemon subcommand against `data` (default: own)."""
        env = self.env | {"NEXUS_DATA_DIR": str(data or self.data)}
        if data is not None:
            env["NEXUS_IDENTITY_DIR"] = str(Path(data).parent / "identity")
        result = subprocess.run([str(self.daemon), *args], env=env, capture_output=True, timeout=60)
        (output / f"{label}.stdout.log").write_bytes(result.stdout)
        (output / f"{label}.stderr.log").write_bytes(result.stderr)
        return result

    def doctor(self, label, output, data=None):
        target = str(data or self.data)
        result = self.cli(label, output, "doctor", "--data-dir", target, data=data)
        return result.returncode, result.stdout.decode("utf-8", errors="replace")

    def enroll(self, label, output, data):
        """Have this Node, as CA holder, (re-)issue `data`'s certificate."""
        token = (self.data / "tls" / "join-token").read_text(encoding="utf-8").strip()
        result = self.cli(label, output, "enroll", self.address, token, data=data)
        assert result.returncode == 0, (label, result.stderr.decode(errors="replace"))


class Journey:
    def __init__(self, args):
        self.daemon = args.daemon.resolve(strict=True)
        self.operator = args.operator.resolve(strict=True)
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.root = self.output / "owned-node"
        self.root.mkdir()  # Never reuse an earlier attempt's private state.
        self.taken = set()
        self.node = Node(self, "founder", "sharedzone")
        self.nodes = [self.node]
        self.data = self.node.data
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        self.grant = self.root / "grant.json"
        self.proof = {
            "success": False, "stage": "prepared", "realMintAgentRpc": False,
            "daemonSha256": digest(self.daemon),
            "operatorSha256": digest(self.operator), "runnerSha256": digest(__file__),
            "platform": os.name, "endpoint": f"https://{self.node.address}",
        }
        repository = Path(__file__).resolve().parents[2]
        self.proof["sourceCommit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()

    def request(self, label, claim, grant=None):
        result = subprocess.run(
            [str(self.operator), "--grant", str(grant or self.grant)],
            input=json.dumps(claim).encode(), capture_output=True, env=self.node.env, timeout=30,
        )
        (self.output / f"{label}.stdout.json").write_bytes(result.stdout)
        (self.output / f"{label}.stderr.log").write_bytes(result.stderr)
        assert result.returncode == 0, (label, result.stderr.decode(errors="replace"))
        return json.loads(result.stdout)

    def claim(self, actor, operation, workspace=None, frontend="codex"):
        return {"version": 1, "actor": f"{frontend}-" + actor * 32,
                "operationId": f"00000000-0000-4000-8000-00000000000{operation}",
                "threadId": f"10000000-0000-4000-8000-00000000000{actor}",
                "workspace": str(workspace or self.workspace)}

    def variant(self, name, policy, **changes):
        """A grant file differing from the initialized one only in `changes`."""
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(policy | changes), encoding="utf-8")
        return path

    def refused(self, label, claim, grant, detail):
        response = self.request(label, claim, grant)
        assert response == {"outcome": "not_submitted", "detail": detail}, (label, response)

    def run(self):
        self.node.start()
        identity = f"nexus://zone/root/node/{node_id(self.data)}"
        self.proof["stage"] = "initialize"
        initialized = subprocess.run(
            [str(self.operator), "--initialize", "--grant", str(self.grant),
             "--data-dir", str(self.data), "--endpoint", f"https://{self.node.address}",
             "--workspace-root", str(self.workspace)],
            env=self.node.env, capture_output=True, timeout=30,
        )
        assert initialized.returncode == 0, initialized.stderr.decode(errors="replace")
        prepared = json.loads(initialized.stdout)
        assert prepared["issued"] is False and prepared["ownerNodeIdentity"] == identity, prepared
        policy = json.loads(self.grant.read_text(encoding="utf-8"))
        assert policy["ownerNodeIdentity"] == identity, policy
        state = Path(policy["stateDirectory"])
        assert not state.exists(), "Preparation must perform no issuance"

        self.proof["stage"] = "preflight refusals"
        assert self.request("outside", self.claim("a", "1", self.root))["outcome"] == "not_submitted"
        assert self.request("forged-owner", self.claim("a", "1") | {"owner": "another-owner"})["outcome"] == "not_submitted"
        assert self.request("unknown-frontend", self.claim("a", "1", frontend="agent"))["outcome"] == "not_submitted"
        uppercase = self.claim("a", "1", frontend="claude") | {"actor": "claude-" + "A" * 32}
        assert self.request("uppercase-actor", uppercase)["outcome"] == "not_submitted"
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

        self.proof["stage"] = "Claude Code actor"
        claude = self.claim("d", "4", frontend="claude")
        claude_receipt = self.request("claude-mint", claude)
        assert claude_receipt["actor"] == claude["actor"], claude_receipt
        assert self.request("claude-replay", claude) == claude_receipt
        assert (Path(claude_receipt["credentialDirectory"]) / "agent.pem").is_file()

        self.proof["stage"] = "unreachable issuer is not submitted"
        self.node.stop()
        retried = self.claim("c", "3")
        down = self.request("node-down", retried)
        assert down["outcome"] == "not_submitted" and "connect" in down["detail"], down
        assert not (state / (retried["actor"] + ".attempt.json")).exists(), "Nothing was reserved"
        assert not (self.data / "agents" / retried["actor"]).exists()
        self.node.start()
        recovered = self.request("node-up", retried)
        assert recovered["actor"] == retried["actor"], recovered
        assert self.request("node-up-replay", retried) == recovered

        self.proof["stage"] = "refusal after reservation is Unknown across Node restart"
        # Another state directory has no record of this already-claimed actor,
        # and its lost bundle no longer blocks the request: the issuer refuses it.
        elsewhere = self.variant("elsewhere", policy, stateDirectory=str(self.root / "elsewhere"))
        shutil.rmtree(credential)
        uncertain = self.request("refused-after-reservation", first, elsewhere)
        assert uncertain["outcome"] == "unknown" and "refusal" in uncertain["detail"], uncertain
        pending = self.root / "elsewhere" / (first["actor"] + ".attempt.json")
        attempt = pending.read_bytes()
        self.node.stop()
        # The founder's bootstrap certificate names its host in the CN.
        numeric_cn = f"CN=nexus-zone-root-node-{node_id(self.data)}\n"
        code, report = self.node.doctor("doctor-founder-bootstrap", self.output)
        assert code == 0 and f"names       = {identity}\n" in report, report
        assert numeric_cn not in report, report
        self.node.start()
        assert self.request("unknown-after-restart", first, elsewhere)["outcome"] == "unknown"
        assert pending.read_bytes() == attempt, "Recovery must retain the original operation"
        assert not credential.exists(), "No offline mint or second RPC"

        self.proof["stage"] = "renewed certificate keeps the grant"
        before = (self.data / "tls" / "node.pem").read_bytes()
        self.node.enroll("renew-founder", self.output, self.data)
        assert (self.data / "tls" / "node.pem").read_bytes() != before, "enroll re-issued the leaf"
        self.node.stop()
        self.node.start()  # Serve and present the renewed certificate.
        renewed = self.claim("e", "5")
        renewed_receipt = self.request("mint-after-renewal", renewed)
        assert renewed_receipt["actor"] == renewed["actor"], renewed_receipt

        self.proof["stage"] = "grant refuses another Node of the cluster"
        member = self.root / "member" / "data"
        self.node.enroll("enroll-member", self.output, member)
        assert node_id(member) != node_id(self.data)
        other_node = self.variant("other-node", policy, nodeDataDirectory=str(member))
        self.refused("other-node", self.claim("f", "6"), other_node, "operator Node identity changed")

        self.proof["stage"] = "grant refuses another cluster's CA for the same Node ID"
        foreign = Node(self, "foreign", "foreignzone")
        self.nodes.append(foreign)
        foreign.data.mkdir(parents=True)
        shutil.copyfile(self.data / ".node_id", foreign.data / ".node_id")
        foreign.start()  # Founds its own cluster and certifies the same Node ID.
        foreign.stop()
        code, report = self.node.doctor("doctor-foreign", self.output, foreign.data)
        assert code == 0 and f"names       = {identity}\n" in report, report
        other_ca = self.variant("other-ca", policy, nodeDataDirectory=str(foreign.data))
        self.refused("other-ca", self.claim("f", "6"), other_ca, "operator cluster CA changed")
        assert not (state / (self.claim("f", "6")["actor"] + ".attempt.json")).exists()

        self.proof["stage"] = "doctor diagnoses a certificate naming another Node"
        (member / ".node_id").write_bytes(secrets.token_bytes(8))
        code, report = self.node.doctor("doctor-mismatch", self.output, member)
        assert code == 2 and "ALARM  NODE_ID_MISMATCH" in report and "nexusd-cluster enroll" in report, report
        self.node.enroll("re-enroll-member", self.output, member)
        code, report = self.node.doctor("doctor-re-enrolled", self.output, member)
        assert code == 0 and f"node_id     = {node_id(member)}\n" in report, report
        self.node.stop()
        # The renewed certificate names the Node ID in the CN; same identity.
        code, report = self.node.doctor("doctor-founder-renewed", self.output)
        assert code == 0 and f"names       = {identity}\n" in report, report
        assert numeric_cn in report, report

        self.proof.update(success=True, stage="complete", exactReceiptReplay=True,
                          concurrentOneOperation=True, claudeActorMinted=True,
                          unreachableIssuerNotSubmitted=True, unknownNeverResubmitted=True,
                          localRefusalsDoNotReserve=True, renewedCertificateKeepsGrant=True,
                          anotherNodeRefused=True, anotherClusterCaRefused=True,
                          doctorDiagnosesNodeIdMismatch=True)

    def finish(self):
        for node in self.nodes:
            node.stop()
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
