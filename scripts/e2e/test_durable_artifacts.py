"""Reject mismatched or corrupted build artifacts before executing a fixture."""
import json
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

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


class ImmutableDownloadTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root/'received'

    def archive(self, names=None):
        stream = io.BytesIO()
        with warnings.catch_warnings(), zipfile.ZipFile(stream, 'w') as archive:
            warnings.simplefilter('ignore', UserWarning)
            for name in sorted(artifacts.BUNDLE_FILES) if names is None else names:
                archive.writestr(name, ('contents:'+name).encode())
        return stream.getvalue()

    def receive(self, contents, expected=None, artifact_id='1234'):
        def transfer(command, *, stdout, check):
            self.assertEqual(command, ['gh', 'api', 'repos/example/repository/actions/artifacts/1234/zip'])
            self.assertTrue(check)
            stdout.write(contents)

        with patch.object(artifacts.subprocess, 'run', side_effect=transfer) as request:
            artifacts.download(self.destination, 'example/repository', artifact_id,
                               expected or hashlib.sha256(contents).hexdigest())
            self.assertEqual(request.call_count, 1)

    def test_immutable_archive_id_and_digest_preserve_all_bundle_files(self):
        self.receive(self.archive())
        self.assertEqual({path.name for path in self.destination.iterdir()}, artifacts.BUNDLE_FILES)
        for name in artifacts.BUNDLE_FILES:
            self.assertEqual((self.destination/name).read_bytes(), ('contents:'+name).encode())

    def test_wrong_digest_fails_before_any_extraction(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.receive(self.archive(), expected='0'*64)
        self.assertFalse(self.destination.exists())

    def test_missing_duplicate_and_traversal_members_are_refused(self):
        valid = sorted(artifacts.BUNDLE_FILES)
        for names in (valid[:-1], valid+[valid[0]], valid+['../outside']):
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, 'bundle members'):
                self.receive(self.archive(names))
            self.assertFalse(self.destination.exists())
            self.assertFalse((self.root/'outside').exists())

    def test_missing_producer_outputs_refuse_before_network_access(self):
        for artifact_id, digest in (('', '0'*64), ('1234', ''), ('../1234', '0'*64)):
            with self.subTest(artifact_id=artifact_id, digest=digest):
                with patch.object(artifacts.subprocess, 'run') as request:
                    with self.assertRaises(ValueError):
                        artifacts.download(self.destination, 'example/repository', artifact_id, digest)
                    request.assert_not_called()
                self.assertFalse(self.destination.exists())

    def test_download_failure_preserves_failure_and_never_extracts(self):
        failure = artifacts.subprocess.CalledProcessError(1, ['gh', 'api'])
        with patch.object(artifacts.subprocess, 'run', side_effect=failure):
            with self.assertRaises(artifacts.subprocess.CalledProcessError):
                artifacts.download(self.destination, 'example/repository', '1234', '0'*64)
        self.assertFalse(self.destination.exists())

    def test_existing_bundle_is_preserved_before_download(self):
        self.destination.mkdir()
        marker = self.destination/'manifest.json'
        marker.write_bytes(b'original')
        with patch.object(artifacts.subprocess, 'run') as request:
            with self.assertRaises(FileExistsError):
                artifacts.download(self.destination, 'example/repository', '1234', '0'*64)
            request.assert_not_called()
        self.assertEqual(marker.read_bytes(), b'original')


if __name__ == '__main__':
    unittest.main()
