"""Transfer source-bound runtime executables between build and acceptance jobs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

NATIVE_CASES = [
    ('availability', 'user_runtime', ['--exact', 'required_durable_backend_obeys_build_and_platform_at_startup']),
    ('owner', 'user_runtime', ['--exact', 'durable_cas_mount_reopens_immutable_content_with_the_owner_boundary']),
    ('expired-runtime', 'user_runtime', ['--exact', 'restart_with_expired_identity_waits_for_renewal_without_losing_owner_data']),
    ('runtime-rotation', 'user_runtime', ['--exact', 'rotation_keeps_existing_connections_and_expiry_refuses_them_until_a_valid_replacement']),
    ('runtime-replica-identity', 'user_runtime', ['--exact', 'rotation_preserves_the_signed_replica_identity']),
    ('runtime-replica-root', 'user_runtime', ['--exact', 'replica_listener_keeps_the_owner_boundary_and_local_root_across_restart']),
    ('runtime-listener-preparation', 'user_runtime', ['--exact', 'runtime_reserves_its_listener_before_creating_owner_storage']),
    ('expired-replica-runtime', 'user_runtime', ['--exact', 'replica_restart_with_expired_identity_recovers_after_renewal']),
    ('peer', 'cas_peer_blob', []),
    ('zone-content', 'zone_content_blob', []),
    ('content', 'conditional_content', []),
    ('stream', 'dt_stream_unbounded', ['--exact', 'joiner_cold_reads_a_sealed_log_and_reports_unavailable_segments']),
    ('protected', 'test_protected_zone_metadata', []),
]
REQUIRED = {name for _, name, _ in NATIVE_CASES} | {'nexusd-cluster'}
BUNDLE_FILES = {'executables.tar', 'artifacts.json', 'manifest.json'}


def digest(path):
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def source_tree(root):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, text=True).strip()


def download(directory, repository, artifact_id, archive_digest):
    """Fetch the producer's immutable artifact and verify its complete archive."""
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid artifact repository')
    if not re.fullmatch(r'[1-9][0-9]*', artifact_id):
        raise ValueError('missing or invalid producer artifact ID')
    if not re.fullmatch(r'[0-9a-f]{64}', archive_digest):
        raise ValueError('missing or invalid producer archive digest')
    if directory.exists():
        raise FileExistsError(directory)
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.durable-download-', dir=directory.parent) as temporary:
        archive_path = Path(temporary)/'artifact.zip'
        with archive_path.open('xb') as stream:
            subprocess.run(['gh', 'api', f'repos/{repository}/actions/artifacts/{artifact_id}/zip'],
                           stdout=stream, check=True)
        if digest(archive_path) != archive_digest:
            raise ValueError('producer artifact archive digest mismatch')
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if (len(members) != len(BUNDLE_FILES)
                    or {member.filename for member in members} != BUNDLE_FILES
                    or any(member.is_dir() for member in members)):
                raise ValueError('unexpected runtime bundle members')
            directory.mkdir()
            for member in members:
                with archive.open(member) as source, (directory/member.filename).open('xb') as output:
                    shutil.copyfileobj(source, output)


def load_executables(artifacts, required):
    selected = {}
    for line in artifacts.read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row.get('executable'):
            name = row['target']['name']
            if name in required:
                selected[name] = Path(row['executable']).resolve(strict=True)
    assert set(selected) == set(required), (set(selected), set(required))
    return selected


def pack(artifacts, directory, root):
    subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=root, check=True)
    directory.mkdir(parents=True, exist_ok=False)
    executables = load_executables(artifacts, REQUIRED)
    records = {}
    with tarfile.open(directory/'executables.tar', 'w') as archive:
        for name, path in sorted(executables.items()):
            assert path.is_relative_to(root/'target') and path.is_file() and not path.is_symlink()
            relative = path.relative_to(root).as_posix()
            records[name] = {'path': relative, 'sha256': digest(path)}
            archive.add(path, arcname=relative, recursive=False)
    shutil.copyfile(artifacts, directory/'artifacts.json')
    manifest = {'version': 1, 'sourceTree': source_tree(root), 'workspace': str(root),
                'cargoLockSha256': digest(root/'Cargo.lock'), 'executables': records,
                'archiveSha256': digest(directory/'executables.tar'),
                'artifactsSha256': digest(directory/'artifacts.json')}
    (directory/'manifest.json').write_text(json.dumps(manifest, indent=2))
    return manifest


def restore(directory, root):
    manifest = json.loads((directory/'manifest.json').read_text())
    assert manifest['version'] == 1 and manifest['workspace'] == str(root)
    assert manifest['sourceTree'] == source_tree(root)
    assert manifest['cargoLockSha256'] == digest(root/'Cargo.lock')
    assert manifest['archiveSha256'] == digest(directory/'executables.tar')
    assert manifest['artifactsSha256'] == digest(directory/'artifacts.json')
    assert set(manifest['executables']) == REQUIRED
    expected = {entry['path'] for entry in manifest['executables'].values()}
    assert len(expected) == len(REQUIRED)
    with tarfile.open(directory/'executables.tar') as archive:
        members = archive.getmembers()
        assert {member.name for member in members} == expected and len(members) == len(expected)
        for member in members:
            relative = PurePosixPath(member.name)
            assert not relative.is_absolute() and relative.parts[0] == 'target' and '..' not in relative.parts
            target = (root/member.name).resolve()
            assert target.is_relative_to(root/'target') and member.isfile()
            assert not target.exists()
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755)
    for entry in manifest['executables'].values():
        assert digest(root/entry['path']) == entry['sha256']
    actual = load_executables(directory/'artifacts.json', REQUIRED)
    assert all(actual[name] == root/entry['path'] for name, entry in manifest['executables'].items())
    return manifest


def native(directory):
    assert os.getpriority(os.PRIO_PROCESS, 0) == 0
    # The protected-record journey must actually exercise the previous reader;
    # omitting its external artifact must not turn that check into a CI pass.
    assert Path(os.environ['NEXUS_RECORD_GUARD_PRIOR_BINARY']).is_file()
    executables = load_executables(directory/'artifacts.json', REQUIRED)
    manifest = json.loads((directory/'manifest.json').read_text())
    assert manifest['sourceTree'] == source_tree(Path.cwd().resolve())
    assert all(digest(executables[name]) == entry['sha256']
               for name, entry in manifest['executables'].items())
    cases = []
    try:
        for label, name, selection in NATIVE_CASES:
            command = [str(executables[name]), *selection]
            listed = subprocess.check_output([*command, '--list'], text=True)
            count = sum(line.endswith(': test') for line in listed.splitlines())
            assert count > 0, (label, listed)
            result = subprocess.run([*command, '--test-threads=1'], capture_output=True, text=True)
            output = result.stdout + result.stderr
            (directory/('native-'+label+'.log')).write_text(output)
            print(output, flush=True)
            summary = re.search(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;', output)
            assert result.returncode == 0 and summary and int(summary[1]) == count
            cases.append({'case': label, 'tests': count, 'success': True})
    finally:
        (directory/'native-receipt.json').write_text(json.dumps({
            'success': len(cases) == len(NATIVE_CASES), 'cases': cases}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['pack', 'download', 'restore', 'native'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--repository', default='')
    parser.add_argument('--artifact-id', default='')
    parser.add_argument('--archive-digest', default='')
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if args.operation == 'pack':
        assert args.artifacts is not None
        pack(args.artifacts, args.directory, root)
    elif args.operation == 'download':
        download(args.directory, args.repository, args.artifact_id, args.archive_digest)
    elif args.operation == 'restore':
        restore(args.directory, root)
    else:
        native(args.directory)


if __name__ == '__main__':
    main()
