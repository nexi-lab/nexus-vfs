"""Publish the verified local Nexus node through the canonical role launcher."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import stat
import subprocess
import uuid


def windows_acl(path):
    command = r'''$s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$a=Get-Acl -LiteralPath $env:NEXUS_RECORD_ACL_TARGET
[pscustomobject]@{current=$s;owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;protected=$a.AreAccessRulesProtected;rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {[pscustomobject]@{sid=$_.IdentityReference.Value;type=$_.AccessControlType.ToString()}})} | ConvertTo-Json -Depth 4 -Compress'''
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                            env={**os.environ, 'NEXUS_RECORD_ACL_TARGET': str(path)},
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise OSError(f'Windows ACL query failed: {result.stderr.strip()}')
    return json.loads(result.stdout)


def private_windows_create(path, *, directory=False, payload=None):
    import msvcrt
    from ctypes import wintypes as w
    # Read the current identity from the already-existing parent, without changing it.
    sid = windows_acl(path.parent)['current']
    descriptor = ctypes.c_void_p()
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = w.BOOL
    inherit = 'OICI' if directory else ''
    if not convert(f'O:{sid}D:P(A;{inherit};FA;;;{sid})', 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    class Attributes(ctypes.Structure):
        _fields_ = [('length', w.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', w.BOOL)]
    attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
    try:
        if directory:
            create = kernel.CreateDirectoryW
            create.argtypes = [w.LPCWSTR, ctypes.POINTER(Attributes)]
            create.restype = w.BOOL
            if not create(str(path), ctypes.byref(attributes)):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            create = kernel.CreateFileW
            create.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(Attributes), w.DWORD, w.DWORD, w.HANDLE]
            create.restype = w.HANDLE
            handle = create(str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(descriptor)


def assert_private(path):
    if path.is_symlink():
        raise ValueError(f'node record path is a symlink: {path}')
    if os.name == 'nt':
        acl = windows_acl(path)
        if not (acl['owner'] == acl['current'] and acl['protected'] and acl['rules']
                and all(rule['sid'] == acl['current'] and rule['type'] == 'Allow' for rule in acl['rules'])):
            raise ValueError(f'node record path is not private to the owner: {path}')
    else:
        info = path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(f'node record path is not private to the owner: {path}')


def publish(record, target):
    if not target.parent.exists():
        if os.name == 'nt':
            private_windows_create(target.parent, directory=True)
        else:
            target.parent.mkdir(mode=0o700)
    assert_private(target.parent)
    if target.exists():
        assert_private(target)
        if json.loads(target.read_text(encoding='utf-8')) != record:
            raise ValueError('another node record already exists; refusing to retarget it')
        return 'already-published'
    temporary = target.with_name('.node.json.' + uuid.uuid4().hex + '.tmp')
    payload = (json.dumps(record, indent=2) + '\n').encode('utf-8')
    try:
        if os.name == 'nt':
            private_windows_create(temporary, payload=payload)
        else:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        assert_private(temporary)
        # Atomic, no-clobber first publication. A competing owner cannot be replaced.
        os.link(temporary, target)
        assert_private(target)
    finally:
        temporary.unlink(missing_ok=True)
    return 'published'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['founder', 'joiner'], required=True)
    parser.add_argument('--agents-dir', type=Path, required=True)
    parser.add_argument('--endpoint', default='127.0.0.1:2126')
    parser.add_argument('--zone', required=True)
    parser.add_argument('--agent', required=True)
    client = parser.add_mutually_exclusive_group(required=True)
    client.add_argument('--client', type=Path, help='existing mailbox_cli with zone-capable stat output')
    client.add_argument('--grpcurl', type=Path, help='verified standard grpcurl binary; avoids rebuilding an old helper')
    parser.add_argument('--proto', type=Path, help='the running Nexus revision public vfs.proto, for grpcurl')
    parser.add_argument('--node-id-sha256', required=True)
    parser.add_argument('--publish', action='store_true', help='activate only after old peer mailboxes are drained')
    args = parser.parse_args()
    if not args.agents_dir.is_absolute() or not (args.client or args.grpcurl).is_absolute():
        parser.error('agents-dir and client must be absolute paths')
    if args.grpcurl and (not args.proto or not args.proto.is_absolute()):
        parser.error('grpcurl requires an absolute --proto path')
    if '://' in args.endpoint or args.endpoint != '127.0.0.1:2126':
        parser.error('this shared-machine record uses the verified loopback mTLS endpoint 127.0.0.1:2126')
    node_id = args.agents_dir.parent / '.node_id'
    if hashlib.sha256(node_id.read_bytes()).hexdigest().lower() != args.node_id_sha256.lower():
        parser.error('node identity does not match the verified owner receipt')
    bundle = args.agents_dir / args.agent
    credential = json.loads((bundle / 'credential.json').read_text(encoding='utf-8'))
    if credential['agent'] != args.agent:
        parser.error('credential identity differs from the requested agent')
    probes = []
    for path in ['/agents', '/conversations', '/sessions']:
        for operation in ['stat', 'readdir']:
            if args.grpcurl:
                # A standard mTLS client and the daemon's exact public schema;
                # no private protocol implementation or authentication bypass.
                command = [str(args.grpcurl), '-max-time', '12',
                           '-authority', credential['server_name'],
                           '-cacert', str(bundle / credential['ca']),
                           '-cert', str(bundle / credential['cert']),
                           '-key', str(bundle / credential['key']),
                           '-import-path', str(args.proto.parent), '-proto', args.proto.name,
                           '-d', json.dumps({'path': path}), args.endpoint,
                           'nexus.grpc.vfs.NexusVFSService/' + operation.capitalize()]
            else:
                command = [str(args.client), args.endpoint, str(bundle), operation, path]
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError(f'{operation} {path} failed: {result.stderr.strip()}')
            if args.grpcurl:
                output = json.loads(result.stdout)
                if output.get('isError'):
                    raise RuntimeError(f'{operation} {path} returned an application error: {output}')
                if operation == 'stat' and not (output.get('found') and output.get('zoneId') == args.zone):
                    raise RuntimeError(f'{path} is not on the expected mounted zone')
            else:
                output = result.stdout.strip()
                if operation == 'stat' and not (
                        f'zone={args.zone}' in output.split() and 'found=true' in output.split()):
                    raise RuntimeError(f'{path} is not on the expected mounted zone')
            probes.append({'operation': operation, 'path': path, 'output': output})
    record = dict(version=1, endpoint=args.endpoint, agents_dir=str(args.agents_dir), role=args.role, zone=args.zone)
    target = Path.home() / '.nexus/run/node.json'
    status = publish(record, target) if args.publish else 'validated-not-published'
    print(json.dumps({'status': status, 'target': str(target), 'record': record, 'authenticatedProbes': probes}, indent=2))


if __name__ == '__main__':
    main()
