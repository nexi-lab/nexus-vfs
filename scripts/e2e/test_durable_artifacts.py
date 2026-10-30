"""Reject mismatched or corrupted build artifacts before executing a fixture."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import durable_artifacts as artifacts


class DurableArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root/'Cargo.lock').write_text('fixture-lock')
        self.rows = []
        for name in sorted(artifacts.REQUIRED):
            binary = self.root/'target/debug'/name
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(name.encode())
            self.rows.append({'reason': 'compiler-artifact', 'target': {'name': name}, 'executable': str(binary)})
        self.input = self.root/'cargo-artifacts.json'
        self.input.write_text('\n'.join(json.dumps(row) for row in self.rows))
        self.bundle = self.root/'bundle'
        self.tree = patch.object(artifacts, 'source_tree', return_value='verified-source-tree')
        self.tree.start()
        self.addCleanup(self.tree.stop)
        self.clean = patch.object(artifacts.subprocess, 'run')
        self.clean.start()
        self.addCleanup(self.clean.stop)

    def pack(self):
        return artifacts.pack(self.input, self.bundle, self.root)

    def remove_executables(self):
        for row in self.rows:
            path = Path(row['executable']).resolve()
            assert path.is_relative_to(self.root/'target')
            path.unlink()

    def test_roundtrip_preserves_every_executable_and_its_digest(self):
        expected = self.pack()
        self.remove_executables()
        actual = artifacts.restore(self.bundle, self.root)
        self.assertEqual(actual, expected)
        for name, path in artifacts.load_executables(self.bundle/'artifacts.json', artifacts.REQUIRED).items():
            self.assertEqual(path.read_bytes(), name.encode())

    def test_missing_executable_is_rejected(self):
        self.input.write_text('\n'.join(json.dumps(row) for row in self.rows[:-1]))
        with self.assertRaises(AssertionError):
            self.pack()

    def test_wrong_tree_is_rejected_before_extracting(self):
        self.pack()
        self.remove_executables()
        with patch.object(artifacts, 'source_tree', return_value='different-tree'):
            with self.assertRaises(AssertionError):
                artifacts.restore(self.bundle, self.root)
        self.assertTrue(all(not Path(row['executable']).exists() for row in self.rows))

    def test_changed_lockfile_is_rejected(self):
        self.pack()
        (self.root/'Cargo.lock').write_text('different-lock')
        with self.assertRaises(AssertionError):
            artifacts.restore(self.bundle, self.root)

    def test_corrupt_archive_is_rejected_before_extracting(self):
        self.pack()
        self.remove_executables()
        with (self.bundle/'executables.tar').open('ab') as stream:
            stream.write(b'corruption')
        with self.assertRaises(AssertionError):
            artifacts.restore(self.bundle, self.root)
        self.assertTrue(all(not Path(row['executable']).exists() for row in self.rows))

    def test_changed_artifact_routes_are_rejected(self):
        self.pack()
        (self.bundle/'artifacts.json').write_text('{}\n')
        with self.assertRaises(AssertionError):
            artifacts.restore(self.bundle, self.root)


if __name__ == '__main__':
    unittest.main()
