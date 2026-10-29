#!/usr/bin/env python3
"""Run the native durable-runtime journey with Moss's qualified sandbox tools."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--moss-tools', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--results', required=True, type=Path)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--runtime-prefix', required=True, type=Path)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or os.uname().machine != 'x86_64':
        parser.error('Use an isolated Linux AMD64 host with runsc namespace capabilities.')
    assert os.getpriority(os.PRIO_PROCESS, 0) == 0
    tools = args.moss_tools.resolve(strict=True)
    sys.path.insert(0, str(tools))
    sys.path.insert(0, str(tools / 'scripts/e2e/gvisor-sync'))
    from deploy.runtime.gvisor.fetch import fetch
    from deploy.runtime.gvisor.install import stage
    from qualify import digest, run_logged, runtime_command, verify_release

    executables = {}
    for line in args.artifacts.read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row.get('executable'):
            name = row['target']['name']
            if name in ('user_runtime', 'nexusd-cluster'):
                executables[name] = Path(row['executable']).resolve(strict=True)
    assert set(executables) == {'user_runtime', 'nexusd-cluster'}
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=False)
    metadata = tools / 'deploy/runtime/gvisor/distribution.lock.json'
    release = fetch(metadata, digest(metadata), args.cache.resolve(), args.offline)
    installed = stage(Path(release['archivePath']), release['archiveSha256'],
                      release['manifestSha256'], args.runtime_prefix.resolve())
    runtime = Path(installed['runsc'])
    files = verify_release(runtime, runtime.parent / 'manifest.json', release['manifestSha256'])
    proof = {
        'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'success': False, 'runtimeManifest': release['manifestSha256'],
        'runtimeArchive': release['archiveSha256'], 'releaseFiles': files,
        'executables': {name: digest(path) for name, path in executables.items()},
        'sources': {str(path.relative_to(tools)): digest(path) for path in [
            tools / 'deploy/runtime/gvisor/fetch.py', tools / 'deploy/runtime/gvisor/install.py',
            tools / 'deploy/runtime/gvisor/release.py', metadata,
            tools / 'scripts/e2e/gvisor-sync/qualify.py',
        ]},
        'fixtureSha256': digest(Path(__file__)), 'cases': [], 'hardwarePersistenceQualified': False,
    }
    try:
        work = args.work_dir.resolve()
        work.mkdir(parents=True, mode=0o700, exist_ok=False)
        bundle = work / 'bundle'
        rootfs = bundle / 'rootfs'
        rootfs.mkdir(parents=True)
        for directory in ['data', 'dev', 'proc', 'usr', 'bin', 'lib', 'lib64', 'tmp']:
            (rootfs / directory).mkdir()
        for name, source in executables.items():
            destination = rootfs / ('user_runtime' if name == 'user_runtime' else str(source).lstrip('/'))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
        state = work / 'state'
        state.mkdir()
        for platform in ['ptrace', 'systrap']:
            for is_directfs in [True, False]:
                label = platform + ('-direct' if is_directfs else '-lisafs')
                data = work / label
                data.mkdir()
                mounts = [
                    {'destination': '/proc', 'type': 'proc', 'source': 'proc'},
                    {'destination': '/dev', 'type': 'tmpfs', 'source': 'tmpfs', 'options': ['nosuid', 'mode=755']},
                    {'destination': '/data', 'type': 'bind', 'source': str(data), 'options': ['rbind', 'rw']},
                ]
                for path in ['/usr', '/bin', '/lib', '/lib64']:
                    mounts.append({'destination': path, 'type': 'bind', 'source': path, 'options': ['rbind', 'ro']})
                config = {
                    'ociVersion': '1.2.0', 'hostname': 'nexus-durable-runtime',
                    'process': {
                        'terminal': False, 'user': {'uid': 0, 'gid': 0}, 'cwd': '/',
                        'args': ['/user_runtime', '--exact', 'durable_cas_mount_reopens_immutable_content_with_the_owner_boundary', '--nocapture'],
                        'env': ['TMPDIR=/data', 'PATH=/usr/bin:/bin'],
                        'capabilities': {key: [] for key in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']},
                    },
                    'root': {'path': 'rootfs', 'readonly': True}, 'mounts': mounts,
                    'linux': {
                        'namespaces': [{'type': kind} for kind in ['pid', 'ipc', 'uts', 'mount', 'network']],
                        'devices': [
                            {'path': '/dev/' + name, 'type': 'c', 'major': 1, 'minor': minor, 'fileMode': 0o666, 'uid': 0, 'gid': 0}
                            for name, minor in [('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)]],
                    },
                }
                (bundle / 'config.json').write_text(json.dumps(config))
                try:
                    output = run_logged(results, label, runtime_command(
                        runtime, state, bundle, results / (label + '.debug.log'), label, platform, is_directfs), timeout=240)
                    assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in output, output
                    proof['cases'].append({'case': label, 'success': True})
                finally:
                    run_logged(results, label + '-cleanup', [str(runtime), '--root=' + str(state), 'delete', '--force', label])
                print(json.dumps(proof['cases'][-1]), flush=True)
        proof['success'] = True
    finally:
        proof['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (results / 'receipt.json').write_text(json.dumps(proof, indent=2))


if __name__ == '__main__':
    main()
