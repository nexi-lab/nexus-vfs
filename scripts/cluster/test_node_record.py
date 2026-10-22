"""Portable real-filesystem checks; never activate the user's node record."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).with_name('publish-node-record.py')
spec = importlib.util.spec_from_file_location('node_record', SOURCE)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

RECORD = dict(version=1, endpoint='127.0.0.1:2126',
              agents_dir='/example/agents', role='founder', zone='sharedzone')


class Publication(unittest.TestCase):
    def test_private_idempotent_and_no_clobber(self):
        with tempfile.TemporaryDirectory(prefix='nexus-record-') as temporary:
            target = Path(temporary) / 'run' / 'node.json'
            self.assertEqual(publisher.publish(RECORD, target), 'published')
            publisher.assert_private(target.parent)
            publisher.assert_private(target)
            original = target.read_bytes()
            self.assertEqual(json.loads(original), RECORD)
            self.assertEqual(publisher.publish(RECORD, target), 'already-published')
            with self.assertRaisesRegex(ValueError, 'refusing to retarget'):
                publisher.publish({**RECORD, 'zone': 'different'}, target)
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(list(target.parent.iterdir()), [target])

    def test_public_existing_parent_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='nexus-record-') as temporary:
            parent = Path(temporary) / 'run'
            parent.mkdir(mode=0o700)
            if os.name == 'nt':
                # Modify only this fixture DACL, without querying or setting SACL.
                subprocess.run(['icacls.exe', str(parent), '/grant', '*S-1-1-0:(RX)'],
                               check=True, capture_output=True)
            else:
                parent.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'not private'):
                publisher.publish(RECORD, parent / 'node.json')
            self.assertFalse((parent / 'node.json').exists())

    def test_competing_processes_cannot_replace_the_winner(self):
        with tempfile.TemporaryDirectory(prefix='nexus-record-race-') as temporary:
            parent = Path(temporary) / 'run'
            # Create the private parent once, so the race concerns record publish.
            if os.name == 'nt':
                publisher.private_windows_create(parent, directory=True)
            else:
                parent.mkdir(mode=0o700)
            target = parent / 'node.json'
            processes = [subprocess.Popen([sys.executable, __file__, '--publish-child',
                                          str(target), str(i)], stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE) for i in range(4)]
            results = [p.communicate(timeout=60) for p in processes]
            codes = [p.returncode for p in processes]
            self.assertEqual(codes.count(0), 1, (codes, results))
            self.assertTrue(all(code in (0, 2) for code in codes), (codes, results))
            self.assertIn(json.loads(target.read_bytes())['zone'], ['0', '1', '2', '3'])
            publisher.assert_private(target)
            self.assertEqual(list(parent.iterdir()), [target])


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--publish-child':
        try:
            publisher.publish({**RECORD, 'zone': sys.argv[3]}, Path(sys.argv[2]))
        except (ValueError, FileExistsError):
            sys.exit(2)
    else:
        unittest.main()
